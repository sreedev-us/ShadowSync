param(
    [switch]$InstallTools
)

$ErrorActionPreference = "Stop"

if ($InstallTools) {
    python -m pip install -r requirements.txt
    python -m pip install pyinstaller
}

python -m PyInstaller `
    --onefile `
    --windowed `
    --name ShadowSync `
    --clean `
    shadowsync.py

Write-Host ""
Write-Host "Windows app built at: dist\ShadowSync.exe"
