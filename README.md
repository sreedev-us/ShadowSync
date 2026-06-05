# ShadowSync

ShadowSync is a cross-platform encrypted persistence bridge for amnesic operating-system sessions. It was designed for workflows where the main OS should forget everything after shutdown, while selected app profiles and user files remain encrypted on removable storage.

The project is especially useful when using Tails or another live Linux environment from a Ventoy USB drive.

## Why This Exists

Some laptop setups, including certain Lenovo LOQ configurations, can make ordinary live-OS persistence awkward or undesirable. Depending on firmware, storage layout, boot policy, or hardware support, relying on internal disk persistence may be unreliable, noisy, or simply not part of the threat model.

The Ventoy workaround is simple:

1. Boot Tails or another live OS from a Ventoy USB drive.
2. Keep ShadowSync and your encrypted storage folder on that same removable drive.
3. Let the live OS remain amnesic.
4. Let ShadowSync restore only the specific app data or files you choose.
5. When you close the app, ShadowSync encrypts the updated state back to the USB drive.

This gives you app-level persistence without depending on the live OS persistence feature.

## Storage Layout

ShadowSync uses one storage folder:

```text
ShadowSyncStore/
  apps/
    Session/
      profiles/
        Default/
          profile.ssvault
          gocryptfs/
        Work/
          profile.ssvault
          gocryptfs/
  files/
    manual-files.ssvault
  user_registry.enc
```

This supports multiple apps, multiple identities per app, and a separate manual files vault for videos, audio, documents, archives, and other files.

## Modes

### DIY Sync-on-Close

This is the portable mode.

ShadowSync decrypts `profile.ssvault` into the selected app profile folder, launches the chosen executable or AppImage, waits for it to close, then compresses and encrypts the updated profile back into `profile.ssvault`.

DIY mode works across Windows, Tails, and other Linux systems.

Encryption:

- Archive: ZIP
- Key derivation: PBKDF2-HMAC-SHA256
- Encryption: AES-256-GCM
- File: `profile.ssvault`

DIY mode also runs a heartbeat save every 15 minutes when changes are detected.

### On-the-Fly FUSE

This is the real-time Linux/Tails mode.

ShadowSync uses `gocryptfs` to mount an encrypted folder directly at the selected profile path. The app writes to what looks like a normal folder, while `gocryptfs` encrypts the data immediately into the USB storage folder.

FUSE mode is Linux/Tails-specific. For Windows portability, use DIY mode.

ShadowSync looks for a bundled static Linux binary first:

```text
assets/gocryptfs
```

If that file is missing, it falls back to the host system `gocryptfs`.

If FUSE/gocryptfs is unavailable during FUSE-to-DIY migration, ShadowSync logs a warning and continues instead of locking you out.

## TOFU App Verification

ShadowSync uses TOFU: Trust On First Use.

When you select an executable, ShadowSync calculates its SHA-256 fingerprint and checks the encrypted registry:

```text
ShadowSyncStore/user_registry.enc
```

Verdicts:

- **First-Time Execution Warning**: ShadowSync has never seen the app before. If you trust the source, choose **Trust & Lock**.
- **Trusted Signature Match**: the app matches the fingerprint previously locked for it.
- **Corrupted or Tampered**: the app fingerprint changed. ShadowSync blocks execution.

On Linux/Tails, first-run trusted apps launch inside a Bubblewrap sandbox when `bwrap` is available. The sandbox allows the app to write to its selected profile folder and exposes the GUI/session sockets needed for Wayland/X11, D-Bus, PulseAudio, and PipeWire.

## Manual Files Vault

The manual files vault is not tied to any app.

Use the GUI buttons:

- **Add Files**
- **Add Folder**
- **Export Files**

Manual files are stored here:

```text
ShadowSyncStore/files/manual-files.ssvault
```

The vault is portable across Windows and Linux.

## App Detection

On startup, ShadowSync scans shallow app-friendly folders for `.AppImage` and `.appimage` files:

- the ShadowSync working folder
- `Apps/`
- `AppImages/`
- `Downloads/`
- the user's home `Downloads/`

The scan is depth-limited to avoid heavy I/O on large Ventoy drives.

## Requirements

Python 3.10+ is recommended.

Install Python dependencies:

```bash
python -m pip install -r requirements.txt
```

For FUSE mode on Linux/Tails:

- bundle `assets/gocryptfs`, or
- install `gocryptfs` on the host

For first-run sandboxing on Linux/Tails:

- install or provide `bwrap` / Bubblewrap

If Bubblewrap is unavailable, ShadowSync logs a warning and launches normally.

## Run

Windows:

```powershell
python .\shadowsync.py
```

Linux or Tails:

```bash
python3 shadowsync.py
```

## Build Windows EXE

```powershell
.\build_windows.ps1 -InstallTools
```

Output:

```text
dist\ShadowSync.exe
```

Build separately for each OS. The executable is OS-specific, but the `.ssvault` data is portable.

## Important Notes

- Use a strong master password.
- DIY mode is best for cross-platform portability.
- FUSE mode is best for real-time encrypted writes on Linux/Tails.
- Cleanup uses fast logical deletion. It does not pretend to securely erase flash media, because SSD/USB wear leveling can preserve old physical sectors.
- On Tails/tmpfs, RAM-backed data disappears when power is removed.

## License

ShadowSync is licensed under the GNU General Public License v3.0. See [LICENSE](LICENSE).
