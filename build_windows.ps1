param(
    [switch]$InstallTools
)

$ErrorActionPreference = "Stop"

if ($InstallTools) {
    python -m pip install -r requirements.txt
    python -m pip install pyinstaller
}

Write-Host "Cleaning previous build artifacts..."
if (Test-Path "build") { Remove-Item -Recurse -Force build -ErrorAction SilentlyContinue }
if (Test-Path "dist\ShadowSync.exe") { Remove-Item -Force "dist\ShadowSync.exe" -ErrorAction SilentlyContinue }


python -m PyInstaller `
    --onefile `
    --windowed `
    --name ShadowSync `
    --clean `
    shadowsync.py

Write-Host ""
Write-Host "Windows app built at: dist\ShadowSync.exe"

# Create the Release Archive
$Version = "1.0"
$StagingDir = Join-Path "dist" "release_staging"
$ZipPath = Join-Path "dist" "ShadowSync-v$Version.zip"

Write-Host "Preparing Release Archive..."

# Clean old staging or zip files
if (Test-Path $StagingDir) {
    Remove-Item -Recurse -Force $StagingDir
}
if (Test-Path $ZipPath) {
    Remove-Item -Force $ZipPath
}

# Create staging directories
New-Item -ItemType Directory -Path $StagingDir -Force | Out-Null
$StagingAssets = Join-Path $StagingDir "assets"
New-Item -ItemType Directory -Path $StagingAssets -Force | Out-Null

# Copy build artifacts and source script
Copy-Item -Path "dist\ShadowSync.exe" -Destination $StagingDir -Force
Copy-Item -Path "shadowsync.py" -Destination $StagingDir -Force

# Copy assets folder contents if they exist
if (Test-Path "assets") {
    Copy-Item -Path "assets\*" -Destination $StagingAssets -Recurse -Force
}

# Create README.md in the root of the staging folder
$ReadmeContent = @"
# ShadowSync v$Version Distribution Archive

To get a seamless, portable installation:
1. Extract the contents of this ZIP archive directly onto the root of your Ventoy USB drive.
2. The folder structure should look like this on your USB drive:
   ├── ShadowSync.exe (For when you plug the USB into Windows)
   ├── shadowsync.py (For when you boot into Tails/Linux)
   └── assets/
       ├── gocryptfs (The Linux binary for FUSE mode)
       └── README.md (Asset configuration guide)

## Quick Start
- **Windows**: Run \`ShadowSync.exe\` directly from your USB drive.
- **Tails / Linux**: Open a terminal on your USB drive and run \`python3 shadowsync.py\`.
"@

$ReadmePath = Join-Path $StagingDir "README.md"
Set-Content -Path $ReadmePath -Value $ReadmeContent -Encoding utf8

# Create the ZIP archive
Compress-Archive -Path "$StagingDir\*" -DestinationPath $ZipPath -Force

# Clean up staging directory
Remove-Item -Recurse -Force $StagingDir

Write-Host "Release Archive created at: $ZipPath"

