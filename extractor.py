# extractor.py
import pathlib
from pathlib import Path
import time
import pytsk3
import sys
from subprocess import Popen, PIPE
import pyewf
import os

# Try multiple possible libewf module names for maximum compatibility.
# Many systems expose the bindings under different names depending on the package:
#   - libewf (some builds)
#   - libewf_python (many modern PyPI wheels)
#   - pyewf (older projects/packaging)
libewf = None
_last_import_error = None
for modname in ("libewf", "libewf_python", "pyewf"):
    try:
        __import__(modname)
        libewf = __import__(modname)
        break
    except Exception as e:
        _last_import_error = e

if libewf is None:
    # Give a friendly error explaining how to fix it
    raise ImportError(
        "No EWF Python binding found. Tried importing 'libewf', 'libewf_python', and 'pyewf' but none succeeded. "
        "Install the bindings in your active venv (recommended):\n\n"
        "  python -m pip install libewf-python\n\n"
        "If you already installed the package, verify you're using the same Python interpreter (venv) where it was installed:\n\n"
        "  which python\n"
        "  python -m pip show libewf-python\n\n"
        f"Last import error was: {_last_import_error}"
    )


def _ensure_dir(p: Path):
    p.mkdir(parents=True, exist_ok=True)


class EwfImgInfo(pytsk3.Img_Info):
    def __init__(self, ewf_handle):
        self._ewf_handle = ewf_handle
        super(EwfImgInfo, self).__init__(
            url="",
            type=pytsk3.TSK_IMG_TYPE_EXTERNAL
        )

    def read(self, offset, size):
        self._ewf_handle.seek(offset)
        return self._ewf_handle.read(size)

    def get_size(self):
        return self._ewf_handle.get_media_size()


def open_ewf_image_and_find_fs(image_path):
    """
    Opens an EWF (E01) image using pyewf + pytsk3, detects partitions,
    and returns (img, fs, offset_bytes, partition_description).

    img = pytsk3.Img_Info adapter over pyewf
    fs  = pytsk3.FS_Info object for the chosen partition
    offset_bytes = byte offset of the chosen partition
    partition_description = string description from GPT/MFT/etc.
    """
    
    # Normalize the image_path → string pattern
    if isinstance(image_path, pathlib.Path):
        pattern = str(image_path)
    elif isinstance(image_path, str):
        pattern = image_path
    else:
        raise TypeError(f"Unsupported image_path type: {type(image_path)}")

    # --- EWF FILE DISCOVERY (correct way for pyewf) ---
    filenames = pyewf.glob(pattern)
    if not filenames:
        raise RuntimeError(f"No EWF segments found matching pattern: {pattern}")

    # --- Open EWF using pyewf.handle ---
    ewf_handle = pyewf.handle()
    ewf_handle.open(filenames)

    # --- Adapter: allow pytsk3 to read pyewf handle ---
    class EWFImgInfo(pytsk3.Img_Info):
        def __init__(self, ewf):
            self._ewf = ewf
            super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

        def read(self, offset, size):
            self._ewf.seek(offset)
            return self._ewf.read(size)

        def get_size(self):
            return self._ewf.get_media_size()

    img = EWFImgInfo(ewf_handle)

    # --- Detect partitions using pytsk3.Volume_Info ---
    try:
        volume = pytsk3.Volume_Info(img)
    except Exception as e:
        raise RuntimeError(f"Could not identify any partition table: {e}")

    candidate = None
    chosen_offset = None
    chosen_desc = None

    # List partitions and choose the one with Windows + Users
    for part in volume:
        if part.len <= 0:
            continue

        start = part.start
        length = part.len
        desc = bytes(part.desc).strip(b"\x00").decode(errors="ignore").strip()

        offset_bytes = start * volume.info.block_size
        try:
            fs = pytsk3.FS_Info(img, offset=offset_bytes)
        except Exception:
            continue  # Not a valid filesystem

        # List root entries
        try:
            root_dir = fs.open_dir("/")
            names = [x.info.name.name.decode(errors="ignore") for x in root_dir]
        except Exception:
            continue

        has_windows = "Windows" in names
        has_users = "Users" in names

        if has_windows or has_users:
            candidate = fs
            chosen_offset = offset_bytes
            chosen_desc = desc
            break

    # If no Windows/Users found, fallback: pick the first valid filesystem
    if candidate is None:
        for part in volume:
            if part.len <= 0:
                continue
            offset_bytes = part.start * volume.info.block_size
            try:
                fs = pytsk3.FS_Info(img, offset=offset_bytes)
                candidate = fs
                chosen_offset = offset_bytes
                chosen_desc = bytes(part.desc).strip(b"\x00").decode(errors="ignore").strip()
                break
            except Exception:
                continue

    if candidate is None:
        raise RuntimeError("No usable filesystem found in the image.")

    return img, candidate, chosen_offset, chosen_desc

def _save_file(fs, src_path, dest_path: Path):
    """Reads a file from the image and writes it locally."""
    try:
        f = fs.open(src_path)
    except Exception:
        return False

    _ensure_dir(dest_path.parent)

    with open(dest_path, "wb") as out:
        size = None
        try:
            if f.info and f.info.meta:
                size = f.info.meta.size
        except Exception:
            size = None

        offset = 0
        CHUNK = 1024 * 1024

        if size is None:
            while True:
                chunk = f.read_random(offset, 4096)
                if not chunk:
                    break
                out.write(chunk)
                offset += len(chunk)
        else:
            while offset < size:
                to_read = min(CHUNK, size - offset)
                data = f.read_random(offset, to_read)
                if not data:
                    break
                out.write(data)
                offset += len(data)

    return True


def extract_artifacts(image_path, output_root, progress_callback=None, log_callback=None):
    def log(msg):
        if log_callback:
            log_callback(msg)
        else:
            print(msg)

    image_path = Path(image_path)
    output_root = Path(output_root)

    if image_path.suffix.lower() not in (".e01", ".ewf"):
        raise RuntimeError("Direct extraction requires an .E01 or .EWF image.")

    _ensure_dir(output_root)

    # Open image + filesystem (auto-detect partition)
    img, fs, offset_bytes, part_desc = open_ewf_image_and_find_fs(image_path)
    log(f"Opened E01 image: {image_path}")
    log(f"Filesystem opened at byte offset: {offset_bytes} ({part_desc})")
    log("Extracting registry hives...")
    registry_targets = {
        "DEFAULT": "/Windows/System32/config/DEFAULT",
        "SAM": "/Windows/System32/config/SAM",
        "SECURITY": "/Windows/System32/config/SECURITY",
        "SOFTWARE": "/Windows/System32/config/SOFTWARE",
        "SYSTEM": "/Windows/System32/config/SYSTEM",
    }

    reg_out = output_root / "Registry"
    _ensure_dir(reg_out)

    for name, src in registry_targets.items():
        dst = reg_out / name
        if _save_file(fs, src, dst):
            log(f"Saved registry hive: {name}")

        for suffix in (".LOG1", ".LOG2"):
            _save_file(fs, src + suffix, reg_out / (name + suffix))

    # Extract filesystem artifacts
    fs_out = output_root / "FilesystemArtifacts"
    _ensure_dir(fs_out)

    special_files = {
        "$MFT": "/$MFT",
        "$LogFile": "/$LogFile",
        "$UsnJrnl_J": "/$Extend/$UsnJrnl/$J",
    }

    for name, path in special_files.items():
        if _save_file(fs, path, fs_out / name):
            log(f"Saved {name}")

    # Event logs
    log("Extracting Windows Event Logs...")
    evt_src = "/Windows/System32/winevt/Logs"
    evt_out = output_root / "EventLogs"
    _ensure_dir(evt_out)

    try:
        d = fs.open(evt_src)
        for entry in d:
            name = entry.info.name.name.decode()
            if name in (".", ".."):
                continue
            _save_file(fs, f"{evt_src}/{name}", evt_out / name)
    except Exception:
        log("Event logs folder not found.")

    # Prefetch
    log("Extracting Prefetch...")
    prefetch_src = "/Windows/Prefetch"
    prefetch_out = output_root / "Prefetch"
    _ensure_dir(prefetch_out)

    try:
        d = fs.open(prefetch_src)
        for entry in d:
            name = entry.info.name.name.decode()
            if name in (".", ".."):
                continue
            _save_file(fs, f"{prefetch_src}/{name}", prefetch_out / name)
    except Exception:
        log("Prefetch folder not found.")

    log("Extraction complete.")
    return True
