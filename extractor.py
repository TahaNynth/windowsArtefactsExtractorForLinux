#!/usr/bin/env python3
# extractor.py
# Linux/WSL-friendly E01 extractor for Windows artifacts
# - auto-detects Windows partition inside E01
# - extracts registry hives, per-user NTUSER/UsrClass, Prefetch, $MFT, $LogFile, $J
# - extracts browser data for Chrome & Edge per user
# - writes a structured output tree next to the E01 image

from pathlib import Path
import pathlib
import os
import time
import sys

# Try EWF binding names (robust)
_libewf = None
_last_ewf_err = None
for mod in ("libewf_python", "pyewf", "libewf"):
    try:
        _libewf = __import__(mod)
        break
    except Exception as e:
        _last_ewf_err = e

if _libewf is None:
    raise ImportError(
        "No EWF binding found (tried libewf_python, pyewf, libewf). "
        "Install libewf-python in the active venv (pip install libewf-python) "
        f"or ensure system package is installed. Last error: {_last_ewf_err}"
    )

libewf = _libewf

# pytsk3 (required)
try:
    import pytsk3
except Exception as e:
    raise ImportError("pytsk3 is required. Install with: pip install pytsk3") from e


# -----------------------
# Helpers
# -----------------------
def _ensure_dir(p: Path):
    p.mkdir(parents=True, exist_ok=True)


def _decode_name(name_obj):
    try:
        return name_obj.name.decode("utf-8", errors="ignore")
    except Exception:
        return str(name_obj)


def resolve_case_insensitive_path(fs, path):
    """
    Resolve a path case-insensitively; returns the real path in the image (preserving case).
    Raises FileNotFoundError if component missing.
    """
    if not path or path == "/":
        return "/"
    parts = [p for p in Path(path).parts if p not in ("/", "")]
    cur = "/"
    for part in parts:
        try:
            d = fs.open_dir(cur)
        except Exception as e:
            raise FileNotFoundError(f"Cannot open directory {cur}: {e}")
        found = None
        for entry in d:
            if not getattr(entry, "info", None) or not entry.info.name:
                continue
            name = _decode_name(entry.info.name)
            if name.lower() == part.lower():
                found = name
                break
        if found is None:
            raise FileNotFoundError(f"Component '{part}' not found under {cur}")
        cur = f"{cur.rstrip('/')}/{found}"
    return cur


def copy_file_or_dir(fs, src_path, dst_path: Path, log_cb=print):
    """
    Copy a file or directory from the image (fs) to local dst_path.
    Resolves path case-insensitively and copies recursively.
    Returns True if something was saved.
    """
    try:
        real_src = resolve_case_insensitive_path(fs, src_path)
    except FileNotFoundError as e:
        log_cb(f"[MISSING] {src_path}: {e}")
        return False

    # try directory first
    try:
        d = fs.open_dir(real_src)
        _ensure_dir(dst_path)
        saved_any = False
        for entry in d:
            if not getattr(entry, "info", None) or not entry.info.name:
                continue
            name = _decode_name(entry.info.name)
            if name in (".", ".."):
                continue
            img_entry_path = f"{real_src}/{name}"
            local_target = dst_path / name
            if copy_file_or_dir(fs, img_entry_path, local_target, log_cb=log_cb):
                saved_any = True
        return saved_any
    except Exception:
        # not a directory, treat as a file
        try:
            f = fs.open(real_src)
        except Exception as e:
            log_cb(f"[ERR] cannot open file {real_src}: {e}")
            return False
        _ensure_dir(dst_path.parent)
        with open(dst_path, "wb") as out:
            offset = 0
            size = None
            try:
                if f.info and f.info.meta:
                    size = int(getattr(f.info.meta, "size", None) or 0)
            except Exception:
                size = None
            if not size:
                # read until EOF
                while True:
                    chunk = f.read_random(offset, 8192)
                    if not chunk:
                        break
                    out.write(chunk)
                    offset += len(chunk)
            else:
                CHUNK = 4 * 1024 * 1024
                while offset < size:
                    to_read = min(CHUNK, size - offset)
                    data = f.read_random(offset, to_read)
                    if not data:
                        break
                    out.write(data)
                    offset += len(data)
        log_cb(f"[SAVED] {real_src} -> {dst_path}")
        return True


# -----------------------
# EWF open & partition detection
# -----------------------
def open_ewf_image_and_find_fs(image_path):
    """
    Opens an EWF image and returns: (img, fs, offset_bytes, partition_description)
    - auto-detects the partition containing Windows or Users (preferred)
    - falls back to the first usable filesystem if Windows/Users not found
    """
    import pathlib as _pl

    # Normalize image_path to native string
    if isinstance(image_path, _pl.Path):
        pattern = os.fspath(image_path)
    elif isinstance(image_path, str):
        pattern = image_path
    else:
        raise TypeError(f"Unsupported image_path type: {type(image_path)}")

    # pyewf (libewf) glob accepts a string pattern (it will return a list of segments)
    try:
        filenames = libewf.glob(pattern)
    except Exception as e:
        # Some libewf bindings expect list - try that fallback
        try:
            filenames = libewf.glob([pattern])
        except Exception as e2:
            raise RuntimeError(f"pyewf.glob failed for pattern {pattern!r}: {e} | fallback error: {e2}")

    if not filenames:
        raise RuntimeError(f"No EWF segments found matching pattern: {pattern}")

    # open handle
    try:
        ewf_handle = libewf.handle()
        ewf_handle.open(filenames)
    except Exception as e:
        raise RuntimeError(f"Failed to open EWF segments: {e}")

    # Adapter for pytsk3: implement read/get_size
    class EWFImgInfo(pytsk3.Img_Info):
        def __init__(self, ewf):
            self._ewf = ewf
            super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

        def read(self, offset, size):
            # pyewf handle uses seek/read
            self._ewf.seek(offset)
            return self._ewf.read(size)

        def get_size(self):
            return self._ewf.get_media_size()

    img = EWFImgInfo(ewf_handle)

    # Try FS at offset 0
    try:
        fs_test = pytsk3.FS_Info(img)
        # if no error, return it
        return img, fs_test, 0, "offset 0"
    except Exception:
        pass

    # Attempt to enumerate partitions
    try:
        volume = pytsk3.Volume_Info(img)
    except Exception as e:
        raise RuntimeError(f"Could not identify a partition table: {e}")

    sector_size = getattr(volume.info, "block_size", 512)

    # Preference: partition containing both 'Windows' and 'Users'
    best_candidate = None
    for part in volume:
        try:
            start = int(part.start)
            if start <= 0:
                continue
            offset_bytes = start * sector_size
            try:
                fs = pytsk3.FS_Info(img, offset=offset_bytes)
            except Exception:
                continue
            # list root entries
            try:
                root = fs.open_dir("/")
                names = [_decode_name(e.info.name) for e in root if getattr(e, "info", None) and e.info.name]
            except Exception:
                names = []
            has_windows = any(n.lower() == "windows" for n in names)
            has_users = any(n.lower() == "users" or n.lower() == "documents and settings" for n in names)
            desc = bytes(part.desc).strip(b"\x00").decode(errors="ignore").strip()
            if has_windows or has_users:
                return img, fs, offset_bytes, desc or f"start={start}"
            # keep first valid fs as fallback
            if best_candidate is None:
                best_candidate = (img, fs, offset_bytes, desc or f"start={start}")
        except Exception:
            continue

    if best_candidate:
        return best_candidate

    raise RuntimeError("No usable filesystem found in the E01 image.")


# -----------------------
# Main extraction routine
# -----------------------
def extract_artifacts(image_path, output_root, progress_callback=None, log_callback=None):
    """
    image_path: path to .E01 image (Path or str)
    output_root: folder where the output tree will be created
    progress_callback(msg) - optional
    log_callback(msg) - optional
    """
    def log(msg):
        if log_callback:
            log_callback(msg)
        else:
            print(msg)

    # Normalize inputs
    image_path = Path(image_path)
    output_root = Path(output_root)
    _ensure_dir(output_root)
    logs_dir = output_root / "logs"
    _ensure_dir(logs_dir)

    log(f"Opened image: {image_path}")
    # open image & detect fs
    img, fs, offset_bytes, part_desc = open_ewf_image_and_find_fs(image_path)
    log(f"Filesystem opened at offset {offset_bytes} ({part_desc})")

    # Directories to create (user requested layout)
    prefetch_out = output_root / "prefetch"
    filesystem_out = output_root / "filesystem"
    registry_root = output_root / "registry"
    registry_system = registry_root / "System"
    registry_peruser = registry_root / "PerUser"
    browsers_root = output_root / "browser"
    chrome_root = browsers_root / "Chrome"
    edge_root = browsers_root / "Edge"

    for p in (prefetch_out, filesystem_out, registry_root, registry_system, registry_peruser, chrome_root, edge_root):
        _ensure_dir(p)

    # -------------------------
    # SYSTEM Registry hives
    # -------------------------
    log("Extracting system registry hives (SYSTEM, SOFTWARE, SAM, SECURITY, DEFAULT)...")
    system_targets = {
        "SYSTEM": "/Windows/System32/config/SYSTEM",
        "SOFTWARE": "/Windows/System32/config/SOFTWARE",
        "SAM": "/Windows/System32/config/SAM",
        "SECURITY": "/Windows/System32/config/SECURITY",
        "DEFAULT": "/Windows/System32/config/DEFAULT",
    }
    for name, path in system_targets.items():
        try:
            copy_file_or_dir(fs, path, registry_system / name, log_cb=log)
            # try LOG1/LOG2 variants
            for suf in (".LOG1", ".LOG2"):
                copy_file_or_dir(fs, path + suf, registry_system / f"{name}{suf}", log_cb=log)
        except Exception as e:
            log(f"[REG-SYS] {name} -> {e}")

    # -------------------------
    # Filesystem artifacts: $MFT, $LogFile, $J
    # -------------------------
    log("Extracting filesystem metadata artifacts ($MFT, $LogFile, $J)...")
    try:
        copy_file_or_dir(fs, "/$MFT", filesystem_out / "$MFT", log_cb=log)
    except Exception:
        log("[FS] $MFT not found or could not be saved")
    try:
        copy_file_or_dir(fs, "/$LogFile", filesystem_out / "$LogFile", log_cb=log)
    except Exception:
        log("[FS] $LogFile not found or could not be saved")
    # $J (USN Journal) tries
    usn_candidates = ["/$Extend/$UsnJrnl/$J", "/$UsnJrnl/$J", "/$Extend/$UsnJrnl/$J:$J"]
    saved_usn = False
    for candidate in usn_candidates:
        try:
            if copy_file_or_dir(fs, candidate, filesystem_out / "$J", log_cb=log):
                saved_usn = True
                break
        except Exception as e:
            log(f"[USN] candidate {candidate} -> {e}")
    if not saved_usn:
        # try searching inside $Extend
        try:
            ext = resolve_case_insensitive_path(fs, "/$Extend")
            d = fs.open_dir(ext)
            for e in d:
                nm = _decode_name(e.info.name)
                if nm.lower().startswith("usnjrnl"):
                    cand = f"{ext}/{nm}/$J"
                    if copy_file_or_dir(fs, cand, filesystem_out / "$J", log_cb=log):
                        saved_usn = True
                        break
        except Exception:
            pass
    if not saved_usn:
        log("[USN] $J not found")

    # -------------------------
    # Prefetch
    # -------------------------
    log("Extracting Prefetch...")
    prefetch_saved = False
    for p in ("/Windows/Prefetch", "/windows/Prefetch"):
        try:
            if copy_file_or_dir(fs, p, prefetch_out, log_cb=log):
                prefetch_saved = True
        except Exception as e:
            log(f"[PREFETCH] {p} -> {e}")
    if not prefetch_saved:
        # try searching for 'Prefetch' under Windows or root
        try:
            try:
                win_root = resolve_case_insensitive_path(fs, "/Windows")
            except Exception:
                win_root = None
            candidates = []
            if win_root:
                candidates.append(f"{win_root}/Prefetch")
            # top-level search
            root_entries = fs.open_dir("/")
            for e in root_entries:
                nm = _decode_name(e.info.name)
                if nm.lower() == "prefetch":
                    candidates.append(f"/{nm}")
            for cand in candidates:
                try:
                    if copy_file_or_dir(fs, cand, prefetch_out, log_cb=log):
                        prefetch_saved = True
                        break
                except Exception:
                    pass
        except Exception:
            pass
    if not prefetch_saved:
        log("[PREFETCH] not found")

    # -------------------------
    # Browser artifacts per user (Chrome & Edge)
    # -------------------------
    log("Extracting browser artifacts (Chrome & Edge) per user...")
    users_path = None
    try:
        users_path = resolve_case_insensitive_path(fs, "/Users")
    except Exception:
        try:
            users_path = resolve_case_insensitive_path(fs, "/Documents and Settings")
        except Exception:
            users_path = None

    if users_path:
        try:
            udir = fs.open_dir(users_path)
            for entry in udir:
                if not getattr(entry, "info", None) or not entry.info.name:
                    continue
                uname = _decode_name(entry.info.name)
                if uname in (".", "..", "Public", "All Users", "Default", "Default User"):
                    continue
                # Chrome
                chrome_candidates = [
                    f"{users_path}/{uname}/AppData/Local/Google/Chrome/User Data",
                    f"{users_path}/{uname}/AppData/Local/Google/Chrome",
                ]
                for cp in chrome_candidates:
                    dest = chrome_root / uname
                    copy_file_or_dir(fs, cp, dest, log_cb=log)
                # Edge
                edge_candidates = [
                    f"{users_path}/{uname}/AppData/Local/Microsoft/Edge/User Data",
                    f"{users_path}/{uname}/AppData/Local/Microsoft/Edge",
                ]
                for ep in edge_candidates:
                    dest = edge_root / uname
                    copy_file_or_dir(fs, ep, dest, log_cb=log)
        except Exception as e:
            log(f"[BROWSERS] enumerate users failed: {e}")
    else:
        log("[BROWSERS] No Users folder found")

    # -------------------------
    # Per-user registry hives (NTUSER.DAT + UsrClass.dat)
    # -------------------------
    log("Extracting per-user registry hives (NTUSER.DAT & UsrClass.dat)...")
    if users_path:
        try:
            udir = fs.open_dir(users_path)
            for entry in udir:
                if not getattr(entry, "info", None) or not entry.info.name:
                    continue
                uname = _decode_name(entry.info.name)
                if uname in (".", "..", "Public", "All Users", "Default", "Default User"):
                    continue
                user_out = registry_peruser / uname
                _ensure_dir(user_out)
                # NTUSER.DAT and logs in user root
                nt_names = ["NTUSER.DAT", "NTUSER.DAT.LOG1", "NTUSER.DAT.LOG2",
                            "ntuser.dat", "ntuser.dat.log1", "ntuser.dat.log2"]
                for nm in nt_names:
                    src = f"{users_path}/{uname}/{nm}"
                    try:
                        copy_file_or_dir(fs, src, user_out / nm, log_cb=log)
                    except Exception as e:
                        log(f"[NTUSER] {src} -> {e}")
                # UsrClass.dat in AppData\Local\Microsoft\Windows\
                usrclass_dir_candidates = [
                    f"{users_path}/{uname}/AppData/Local/Microsoft/Windows",
                    f"{users_path}/{uname}/AppData/Local/Windows",
                ]
                found_uc = False
                for base in usrclass_dir_candidates:
                    try:
                        for candidate_name in ("UsrClass.dat", "UsrClass.dat.LOG1", "UsrClass.dat.LOG2",
                                               "usrclass.dat", "usrclass.dat.log1", "usrclass.dat.log2"):
                            src = f"{base}/{candidate_name}"
                            if copy_file_or_dir(fs, src, user_out / candidate_name, log_cb=log):
                                found_uc = True
                    except Exception:
                        pass
                if not found_uc:
                    # attempt to search AppData/Local recursively (slow), but left out for now
                    pass
        except Exception as e:
            log(f"[REG-USER] enumerate users failed: {e}")
    else:
        log("[REG-USER] No Users folder found to extract per-user registry hives")

    log("Extraction finished.")
    return True