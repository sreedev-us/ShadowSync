#!/usr/bin/env bash
set -e

echo "======================================"
echo " ShadowSync Linux PyInstaller Builder "
echo "======================================"

# Install dependencies if requested
if [ "$1" == "--install-tools" ]; then
    echo "[+] Installing build dependencies..."
    python3 -m pip install -r requirements.txt
    python3 -m pip install pyinstaller
fi

# Clean previous build artifacts
echo "[+] Cleaning previous build artifacts..."
rm -rf build/ dist/ShadowSync

# Build the Linux standalone binary
echo "[+] Running PyInstaller..."
python3 -m PyInstaller \
    --onefile \
    --windowed \
    --name ShadowSync \
    --clean \
    shadowsync.py

echo ""
echo "======================================"
echo "[+] Linux standalone binary built at: dist/ShadowSync"
echo ""
echo "You can now rename or package this executable."
echo "For the dual-release ZIP, you can copy 'dist/ShadowSync' into the release archive."
echo "======================================"
