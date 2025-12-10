# Windows Forensic Artifact Extractor  
Automated extraction of key forensic artifacts from Windows disk images (EWF `.E01` or raw images) using `pyewf` and `pytsk3`.  
This tool extracts filesystem artifacts, registry hives, browser data, prefetch files, and more.

---

## 📁 Output Structure  
After running the tool, the output folder will look like:

```
output/
 ├── filesystem/
 │    ├── $MFT
 │    ├── $LogFile
 │    ├── $J  (USN Journal)
 │    └── raw_extracted_files...
 ├── prefetch/
 ├── registry/
 │    ├── SYSTEM
 │    ├── SOFTWARE
 │    ├── SAM
 │    ├── SECURITY
 │    ├── ntuser/
 │    │    ├── <user>/NTUSER.DAT
 │    │    ├── <user>/NTUSER.DAT.LOG1
 │    │    ├── <user>/NTUSER.DAT.LOG2
 │    └── usrclass/
 │         ├── <user>/UsrClass.dat
 │         ├── <user>/UsrClass.dat.LOG1
 │         ├── <user>/UsrClass.dat.LOG2
 ├── browser/
 │    ├── <username>/
 │    │    ├── Chrome/
 │    │    └── Edge/
```

---

## ✅ Requirements  
Ubuntu 22.04+ is recommended.

The project relies on:  
- Python 3.10+  
- pyewf  
- pytsk3  
- libewf-dev  
- libtsk-dev  
- other supporting libraries in `requirements.txt`

---

## 📦 1. Create Virtual Environment  

```bash
python3 -m venv venv
source venv/bin/activate
```

---

## 📥 2. Install Dependencies  

Try normal installation first:

```bash
pip install -r requirements.txt
```

If **anything fails**, run:

```bash
bash setup.sh
```

---

## 🚀 3. Running the Extractor  

```bash
python3 main.py --image /path/to/disk.E01 --out ./output
```

If you run without arguments, `main.py` will interactively ask for the image path.

---

# 🛠 setup.sh (Automatic Fix-Everything Script)

This script:  
✔ Installs system libraries  
✔ Fixes common pyewf/pytsk build errors  
✔ Reinstalls dependencies safely  
✔ Rebuilds missing wheels  
✔ Ensures Python dev headers exist  

Place this file as **setup.sh**, then run:

```bash
chmod +x setup.sh
./setup.sh
```

**setup.sh**

```bash
#!/bin/bash
set -e

echo "[+] Updating system..."
sudo apt update -y
sudo apt upgrade -y

echo "[+] Installing required dev libraries for pyewf + pytsk..."
sudo apt install -y build-essential python3-dev python3-pip python3-venv \
    libewf-dev libtsk-dev libfuse-dev libssl-dev libbz2-dev zlib1g-dev \
    libffi-dev liblzma-dev libxml2-dev libxslt1-dev

echo "[+] Ensuring wheel + setuptools are up to date..."
pip install --upgrade pip setuptools wheel

echo "[+] Reinstalling problematic packages one-by-one..."
pip install --force-reinstall pyewf-python || pip install --no-binary :all: pyewf-python
pip install --force-reinstall pytsk3 || pip install --no-binary :all: pytsk3

echo "[+] Installing remaining Python dependencies..."
pip install -r requirements.txt || true

echo "[+] Setup complete. You can now run:"
echo "    source venv/bin/activate"
echo "    python3 main.py"
```

---

# 🧩 Troubleshooting Guide

### ❗ Error: `pyewf_glob: unsupported string object type`
Cause: pyewf expects **list of bytes**, not strings.  
Solution: Already fixed in our extractor — no action needed.

---

### ❗ Error: "pyewf-python build failed"
Run:

```bash
sudo apt install libewf-dev
pip install --no-binary :all: pyewf-python
```

Or simply:

```
./setup.sh
```

---

### ❗ Error: "pytsk3 build failed"
Install TSK system libs:

```bash
sudo apt install libtsk-dev
pip install --no-binary :all: pytsk3
```

---

### ❗ Error: "module not found: pyewf / pytsk3"
Run:

```bash
pip install --force-reinstall pyewf-python pytsk3
```

---

### ❗ Error: missing Python headers (`Python.h`)
Install:

```bash
sudo apt install python3-dev
```

---

### ❗ FTK Imager shows partitions but script finds none
Cause: some EWF files have nested GPT/MBR inside.  
Solution: our tool now auto-detects offsets.

---

### ❗ Extracted files are empty / random failures
Enable verbose logging:

```bash
python3 main.py --debug
```

---

# 📘 Project Description

This project automates Windows forensic artifact extraction so analysts don’t waste time manually carving files in FTK Imager or Autopsy.

It extracts:  
✔ MFT  
✔ LogFile  
✔ USN Journal  
✔ Prefetch  
✔ User Registry Hives  
✔ System Registry Hives  
✔ Chrome & Edge browser data (per-user)  
✔ Any file or directory directly from NTFS  

The design goal: **zero manual clicking, fully automated, robust against weird E01 edge cases.**

---

# 🧑‍💻 Development Notes  

- Code is written with clean separation between imaging, filesystem walking, and artifact extraction.  
- Works with both EWF and RAW datasets.  
- NTFS is required (for now).  
- Runs on Ubuntu with no proprietary dependencies.

---

# 🙌 Credits  
Developed with ❤️ for Digital Forensics students needing a fast, reliable extraction tool.

---
