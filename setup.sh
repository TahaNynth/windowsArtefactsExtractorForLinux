#!/usr/bin/env bash
set -euo pipefail

# setup.sh - Ubuntu / WSL setup for the extractor project
# Usage:
#   sudo ./setup.sh
# or as non-root (script will call sudo where needed)

echo "==> Installing system dependencies (apt)..."
sudo apt update
sudo apt install -y build-essential software-properties-common curl pkg-config \
  libssl-dev libbz2-dev libreadline-dev libsqlite3-dev zlib1g-dev \
  libewf-dev sleuthkit libtsk-dev qtbase5-dev libxcb-xinerama0 libxkbcommon-x11-0 \
  python3-venv python3-pip python3-dev

# Prefer python3.10; if not present, install from deadsnakes PPA
if ! command -v python3.10 >/dev/null 2>&1; then
  echo "python3.10 not found. Adding deadsnakes PPA and installing python3.10..."
  sudo add-apt-repository ppa:deadsnakes/ppa -y
  sudo apt update
  sudo apt install -y python3.10 python3.10-venv python3.10-dev
fi

echo "==> Creating virtual environment (venv)..."
python3.10 -m venv venv
source venv/bin/activate

echo "==> Upgrading pip and installing wheel..."
python -m pip install --upgrade pip wheel

echo "==> Installing Python dependencies (may build pytsk3/libewf from source)..."
# Recommended package names: libewf-python, pytsk3, PyQt5
python -m pip install --upgrade pip
python -m pip install libewf-python pytsk3 PyQt5

echo "==> Setup complete."
echo ""
echo "Activate the venv with:"
echo "  source venv/bin/activate"
echo "Then run the GUI with:"
echo "  python main.py"
