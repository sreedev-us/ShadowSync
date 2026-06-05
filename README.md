# ShadowSync

ShadowSync is a GUI app for encrypted persistence in amnesic or temporary environments. It is designed for messenger profiles and similar app data that must survive across boots without leaving plain data behind.

The app now uses one storage folder. Inside that folder, each app gets its own namespace:

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
    SimpleX/
      profiles/
        Default/
          profile.ssvault
          gocryptfs/
  files/
    manual-files.ssvault
  user_registry.enc
```

This lets one USB folder hold multiple apps, multiple identities per app, and a separate manual files vault for videos, audio, documents, and any other files.

## Windows App

ShadowSync runs on Windows with Python, and it can also be built as a normal `.exe`.

Run from source:

```powershell
python -m pip install -r requirements.txt
python .\shadowsync.py
```

Build a Windows app:

```powershell
.\build_windows.ps1 -InstallTools
```

After the build completes, use:

```text
dist\ShadowSync.exe
```

That Windows app can unlock and export the portable `.ssvault` data created on Linux or Tails. FUSE/gocryptfs folders remain Linux/Tails-specific, but DIY app vaults and the manual files vault are cross-platform.

## Two Modes

### Mode 1: DIY Sync-on-Close

This is the portable mode.

ShadowSync decrypts `profile.ssvault` into the selected profile folder, launches the app, waits for that exact child process to close, then compresses and encrypts the updated profile back into `profile.ssvault`.

Use this when you want the same encrypted data to open on Windows, Tails, and other Linux systems.

DIY mode also runs an auto-save heartbeat every 15 minutes. If the profile folder changed, ShadowSync updates the encrypted vault in the background to reduce data loss from crashes or battery failure.

Encryption:

- Archive: ZIP
- Key derivation: PBKDF2-HMAC-SHA256
- Encryption: AES-256-GCM
- File: `profile.ssvault`

### Mode 2: On-the-Fly FUSE

This is the real-time Linux/Tails mode.

ShadowSync uses `gocryptfs` to mount an encrypted folder directly at the selected profile folder. The messenger app writes to what looks like a normal folder, while `gocryptfs` encrypts the data immediately into the USB storage folder.

Use this when you want instant encrypted writes and are running Linux/Tails with `gocryptfs` available.

FUSE mode is not Windows-portable by itself because Windows cannot normally mount `gocryptfs` folders. For Windows portability, use DIY mode.

ShadowSync looks for a bundled static Linux `gocryptfs` binary first:

```text
assets/gocryptfs
```

If that file is missing, it falls back to the host system's `gocryptfs`. Keeping a known-good static binary in `assets/` makes FUSE mode usable offline from the USB drive.

## Any Application

ShadowSync can work with any application as long as you provide:

- the application executable, `.exe`, binary, or AppImage
- the profile/data folder where that application stores local state

Built-in presets and AppImage detection make common apps easier, but uncommon apps may require selecting the profile folder manually.

## Manual Files Vault

ShadowSync also includes a cross-platform file vault that is not tied to any app.

Use:

- **Add Files** to import videos, audio, documents, archives, or any selected files.
- **Add Folder** to import a whole folder.
- **Export Files** to decrypt the manual file vault into a folder on Windows, Tails, or Linux.

Manual files are stored here:

```text
ShadowSyncStore/files/manual-files.ssvault
```

This vault uses the same portable AES-256-GCM encryption as DIY mode. Exporting files does not wipe the destination folder and avoids overwriting existing files by adding a numeric suffix when needed.

## Switching Modes

Changing modes does not erase data.

- Switching from DIY to FUSE: ShadowSync reads `profile.ssvault`, creates the app's `gocryptfs/` folder, copies the decrypted data into the mounted FUSE filesystem, and keeps `profile.ssvault` as a backup.
- Switching from FUSE to DIY: on Linux/Tails, ShadowSync mounts the app's `gocryptfs/` folder, creates `profile.ssvault`, and keeps the FUSE folder as a backup.

If FUSE/gocryptfs is unavailable during FUSE-to-DIY migration, ShadowSync logs a warning and continues instead of blocking launch. This prevents old FUSE data from locking you out on a machine that cannot mount it.

The two formats are both stored under the same app folder. They are separate encrypted formats because a normal AES vault file cannot also behave like a live FUSE filesystem without a custom filesystem driver.

## TOFU App Verification

ShadowSync uses TOFU: Trust On First Use. This is similar to SSH host key trust.

The first time you select an executable, ShadowSync calculates its SHA-256 fingerprint and checks the encrypted user registry:

```text
ShadowSyncStore/user_registry.enc
```

That registry is encrypted with your master password.

Verdicts:

- **First-Time Execution Warning**: ShadowSync has never seen this app before. If you trust the download source, choose **Trust & Lock**. ShadowSync records the fingerprint and immediately re-encrypts the registry.
- **Trusted Signature Match**: the executable matches the fingerprint previously locked for this app.
- **Corrupted or Tampered**: ShadowSync has seen this app before, but the executable fingerprint changed. ShadowSync blocks the executable.

For Linux/Tails, first-run trusted apps are launched inside a Bubblewrap sandbox when `bwrap` is available. The sandbox gives the app write access to its selected profile folder, creates the needed nested profile path inside the isolated home tmpfs, and exposes only the session sockets needed for normal GUI operation such as Wayland/X11, D-Bus, PulseAudio, and PipeWire.

## New App Detection

When ShadowSync starts, it scans for `.AppImage` and `.appimage` files. To avoid heavy I/O on large Ventoy drives, the scan is depth-limited and only checks shallow locations:

- the ShadowSync working folder
- `Apps/`
- `AppImages/`
- `Downloads/`
- the user's home `Downloads/`

If it finds an AppImage that does not already have a matching folder under `ShadowSyncStore/apps/`, it asks whether to configure it automatically.

If accepted, ShadowSync fills:

- App name
- Application path
- Profile name: `Default`
- A guessed Linux profile path such as `~/.config/Element`

The guessed profile path is highlighted so you can review it before launching.

## Panic Control

ShadowSync includes a prominent **Panic** button and an in-app `Ctrl+Shift+P` hotkey.

When triggered, ShadowSync:

- Kills the launched child process immediately.
- Wipes the selected RAM-side profile folder.
- Attempts to unmount the FUSE bridge if FUSE mode is active.
- Closes the ShadowSync window.

The hotkey is bound inside the ShadowSync window. A true OS-global hotkey would require extra platform-specific packages.

## Progress Feedback

During expensive encryption, decryption, and migration work, ShadowSync shows an indeterminate progress bar and updates the status indicator so the GUI does not look frozen while PBKDF2 and AES operations are running.

DIY heartbeat checks also pulse a small indicator next to the status area so the user can see that background protection is alive.

## Requirements

Python 3.10+ is recommended.

Install the Python dependency:

```bash
python -m pip install -r requirements.txt
```

For FUSE mode on Linux/Tails, bundle `assets/gocryptfs` or make sure `gocryptfs` is installed on the host.

For first-run sandboxing on Linux/Tails, install or provide `bwrap`/Bubblewrap. If Bubblewrap is unavailable, ShadowSync logs a warning and launches normally.

## Run

Windows:

```powershell
python .\shadowsync.py
```

Linux or Tails:

```bash
python3 shadowsync.py
```

## GUI Setup

The setup screen asks for:

- Mode: DIY sync-on-close or on-the-fly FUSE.
- Storage folder: the single folder on your USB drive.
- App name: used to separate app data inside the storage folder.
- Profile name: lets you keep separate identities such as `Default`, `Personal`, or `Work`.
- Master password: used for the selected encrypted backend.
- Profile folder: where the app stores its local profile.
- Application: the executable or AppImage to launch.

Built-in profile presets include Session, SimpleX, Signal, Element, Brave, and KeePassXC.

The manual files vault only needs the storage folder and master password.

## Important Notes

- Use a strong master password.
- DIY mode is the best choice for cross-platform portability.
- FUSE mode is the best choice for real-time encrypted writes on Linux/Tails.
- ShadowSync keeps old encrypted mode data as a backup during migration.
- Cleanup uses fast logical deletion. It does not pretend to securely erase flash media, because SSD/USB wear leveling can preserve old physical sectors. On Tails/tmpfs, RAM-backed data disappears when power is removed.
