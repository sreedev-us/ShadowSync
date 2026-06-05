# ShadowSync

**Cross-platform encrypted persistence bridge for amnesic operating-system sessions.**

ShadowSync lets you carry your app profiles and personal files in encrypted vaults on a USB drive. It restores them into a live OS session at launch, and seals them back when you're done — so the live OS stays amnesic, but your chosen data doesn't disappear.

---

## Table of Contents

- [Why This Exists — The Lenovo LOQ Problem](#why-this-exists--the-lenovo-loq-problem)
- [The Ventoy Workaround](#the-ventoy-workaround)
- [How ShadowSync Fits In](#how-shadowsync-fits-in)
- [Features](#features)
- [Storage Layout](#storage-layout)
- [Sync Modes](#sync-modes)
  - [DIY Sync-on-Close](#diy-sync-on-close)
  - [On-the-Fly FUSE](#on-the-fly-fuse)
- [TOFU App Verification](#tofu-app-verification)
- [Manual Files Vault](#manual-files-vault)
- [App Detection](#app-detection)
- [Requirements](#requirements)
- [Installation](#installation)
- [Running ShadowSync](#running-shadowsync)
- [Building a Windows Executable](#building-a-windows-executable)
- [Security Notes](#security-notes)
- [License](#license)

---

## Why This Exists — The Lenovo LOQ Problem

The **Lenovo LOQ** laptop series (and similar consumer gaming/budget laptops) ships with firmware and storage configurations that create friction when trying to run a live privacy OS like [Tails](https://tails.boum.org/):

| Issue | Detail |
|---|---|
| **Secure Boot complexity** | Lenovo LOQ models enforce Secure Boot by default. Enrolling a custom key or disabling it entirely varies by BIOS version and can break Windows' TPM-backed BitLocker seal. |
| **NVMe-only internal storage** | The internal drive is NVMe only. Many live OS images do not mount or touch it, but the BIOS boot order on Lenovo LOQ models often deprioritises USB devices, requiring manual intervention every boot. |
| **Ventoy USB boot quirks** | When booting a multi-ISO Ventoy stick, Lenovo LOQ firmware may hand off to Ventoy's GRUB in a way that causes the persistence partition (if configured on the Ventoy stick itself) to not be recognized by the live OS, or to require extra GRUB parameters. |
| **Tails Persistent Storage incompatibility** | Tails Persistent Storage is designed to live on a dedicated Tails-formatted USB stick. Because Ventoy uses a different partition layout (exFAT data + ISO images), Tails cannot create or use its built-in Persistent Storage on a Ventoy drive. You either use a dedicated Tails stick (losing multi-ISO flexibility) or you give up on persistence entirely. |

**The net result:** on a Lenovo LOQ, running Tails (or another amnesic live OS) from a Ventoy drive means you get no native persistence. Every session starts fresh. Passwords, browser profiles, and files are gone at shutdown.

ShadowSync is the targeted fix for this exact situation.

---

## The Ventoy Workaround

[Ventoy](https://www.ventoy.net/) is a USB tool that lets you place multiple `.iso` files on a single drive and boot any of them from a menu. This is useful because:

- You can carry Tails, a Linux distro, and a Windows recovery ISO on one stick.
- You do not need to re-flash the USB every time you switch OS images.
- The Ventoy data partition (exFAT) is writable from any OS, including Windows and Tails.

**The trick:** because the Ventoy data partition is just a normal filesystem visible from inside Tails, you can store arbitrary files there — including ShadowSync itself and its encrypted vaults.

The workaround flow looks like this:

```
┌──────────────────────────────────────────────────────┐
│                  Ventoy USB Drive                    │
│                                                      │
│  ┌──────────────────┐   ┌──────────────────────────┐ │
│  │  Ventoy EFI/MBR  │   │  Data Partition (exFAT)  │ │
│  │  boot loader     │   │                          │ │
│  │                  │   │  tails-*.iso             │ │
│  │                  │   │  ubuntu-*.iso            │ │
│  │                  │   │  shadowsync.py           │ │
│  │                  │   │  ShadowSyncStore/        │ │
│  └──────────────────┘   └──────────────────────────┘ │
└──────────────────────────────────────────────────────┘
         │
         │  Boot Tails from Ventoy menu
         ▼
┌──────────────────────────────────────────────────────┐
│  Tails (amnesic, no Persistent Storage)              │
│                                                      │
│  Ventoy data partition auto-mounted at /media/...    │
│                                                      │
│  Run ShadowSync → decrypts vaults from USB           │
│               → restores app profiles                │
│               → you work normally                    │
│               → ShadowSync re-encrypts on exit       │
└──────────────────────────────────────────────────────┘
```

Because ShadowSync only needs a working Python 3 interpreter (already in Tails), it runs directly from the USB drive without installation.

---

## How ShadowSync Fits In

ShadowSync sits between the amnesic live OS and your apps:

1. **Before your session** — ShadowSync decrypts your vault and restores your app profile to the location the app expects (e.g. `~/.mozilla/firefox/...` for Firefox).
2. **During your session** — the app runs normally, writing to what looks like a standard profile folder. In FUSE mode, every write is encrypted in real time back to the USB.
3. **After your session** — ShadowSync compresses and re-encrypts the updated profile back into the vault on the USB drive. Tails shuts down. The internal disk is untouched.

This gives you **app-level persistence** without modifying the live OS, the Ventoy partition layout, or the BIOS.

---

## Features

- 🔐 **AES-256-GCM encryption** with PBKDF2-HMAC-SHA256 key derivation
- 🗂️ **Multiple apps, multiple identities** — each app can have multiple named profiles
- 💾 **DIY mode** — works on Windows, Tails, and any Linux
- ⚡ **FUSE mode** — real-time encryption via `gocryptfs` (Linux/Tails only)
- 🛡️ **TOFU app verification** — SHA-256 fingerprinting blocks tampered executables
- 📦 **Manual files vault** — portable encrypted storage for documents, videos, and archives
- 🫧 **Bubblewrap sandbox** — first-run trusted apps on Linux/Tails are sandboxed with `bwrap`
- 💓 **Heartbeat saves** — DIY mode saves changes every 15 minutes automatically
- 🔍 **AppImage scanner** — auto-detects `.AppImage` files on the USB drive

---

## Storage Layout

All encrypted data lives in a single folder you can place anywhere — on the USB drive, a network share, or a local disk:

```
ShadowSyncStore/
  apps/
    Session/
      profiles/
        Default/
          profile.ssvault        ← encrypted ZIP of the app profile
          gocryptfs/             ← gocryptfs cipher directory (FUSE mode)
        Work/
          profile.ssvault
          gocryptfs/
  files/
    manual-files.ssvault         ← encrypted vault for manual files
  user_registry.enc              ← encrypted TOFU fingerprint registry
```

Each `.ssvault` file is a self-contained encrypted archive. The format is:

- **Archive:** ZIP
- **Key derivation:** PBKDF2-HMAC-SHA256 (600,000 iterations)
- **Cipher:** AES-256-GCM
- **Salt and nonce:** prepended to the vault file

The `gocryptfs/` subdirectory is only populated when you use FUSE mode. DIY mode only uses the `.ssvault` file.

---

## Sync Modes

### DIY Sync-on-Close

**Best for:** Windows, cross-platform portability, or situations where FUSE is unavailable.

**How it works:**

1. ShadowSync decrypts `profile.ssvault` into the app's profile folder.
2. It launches the chosen executable (or AppImage).
3. It waits for the process to exit.
4. It compresses the updated profile folder back into `profile.ssvault`, re-encrypting it.

While the app is running, ShadowSync also runs a **heartbeat save every 15 minutes** when it detects changes, so you don't lose work if something crashes.

```
USB vault ──decrypt──▶ profile folder ──launch──▶ app runs
                                                      │
                          ◀──compress+encrypt──────────┘
                                on close (or every 15 min)
```

### On-the-Fly FUSE

**Best for:** Linux and Tails where you want changes to be encrypted in real time.

**How it works:**

1. ShadowSync initialises a `gocryptfs` encrypted directory in `ShadowSyncStore/apps/<App>/profiles/<Name>/gocryptfs/`.
2. It mounts that directory at the app's expected profile path using `gocryptfs`.
3. The app writes normally. FUSE transparently encrypts every write to the USB.
4. ShadowSync unmounts when the app exits.

ShadowSync looks for a bundled static binary first:

```
assets/gocryptfs
```

If that is missing, it falls back to the system `gocryptfs`. If neither is available, it falls back to DIY mode and logs a warning.

---

## TOFU App Verification

ShadowSync uses **Trust On First Use (TOFU)** to protect you from running tampered executables.

**First time you select an executable:**

- ShadowSync calculates its SHA-256 fingerprint.
- It prompts: *"ShadowSync has never seen this app before. Trust & Lock it?"*
- If you confirm, the fingerprint is written to `ShadowSyncStore/user_registry.enc`.

**On every subsequent launch:**

| Verdict | Meaning | Action |
|---|---|---|
| ✅ Trusted Signature Match | Fingerprint matches the stored value | Launch normally |
| ⚠️ First-Time Execution Warning | App not yet in registry | Prompt to Trust & Lock |
| 🚫 Corrupted or Tampered | Fingerprint changed since last trust | Block launch |

On Linux/Tails, **trusted apps are sandboxed with Bubblewrap (`bwrap`)** on first run. The sandbox:
- Allows write access to the selected profile folder
- Exposes Wayland/X11, D-Bus, PulseAudio, and PipeWire sockets so the app renders normally

If `bwrap` is not available, ShadowSync logs a warning and launches without sandboxing.

---

## Manual Files Vault

The manual files vault is independent of any app. Use it to carry documents, videos, archives, or any other files you want to keep encrypted on the USB.

**GUI buttons:**

| Button | Action |
|---|---|
| **Add Files** | Encrypt individual files into the vault |
| **Add Folder** | Encrypt an entire folder recursively |
| **Export Files** | Decrypt and write selected vault contents to a destination |

Files are stored in:

```
ShadowSyncStore/files/manual-files.ssvault
```

The vault is portable across Windows and Linux. The same `.ssvault` file can be opened on both platforms.

---

## App Detection

On startup, ShadowSync scans a set of shallow app-friendly folders for `.AppImage` and `.appimage` files:

- The ShadowSync working folder
- `Apps/`
- `AppImages/`
- `Downloads/`
- The user's home `~/Downloads/`

The scan is **depth-limited** to 2 levels to avoid heavy I/O on large Ventoy drives with many files.

Detected AppImages appear in the app selector dropdown automatically.

---

## Requirements

- **Python 3.10+**
- **`cryptography` ≥ 42** (the only pip dependency)

For **FUSE mode** on Linux/Tails:

- Bundle `assets/gocryptfs` (recommended for portability), **or**
- Install `gocryptfs` on the host system

For **first-run sandboxing** on Linux/Tails:

- Install `bwrap` / [Bubblewrap](https://github.com/containers/bubblewrap) (already included in Tails)

Both `gocryptfs` and `bwrap` are optional — ShadowSync degrades gracefully if either is missing.

---

## Installation

ShadowSync has no installer. Clone or copy it to your Ventoy USB drive (or any folder):

```bash
git clone https://github.com/sreedev-us/ShadowSync.git
```

Or download the Windows `.exe` from [Releases](https://github.com/sreedev-us/ShadowSync/releases) and place it wherever you want.

### Install Python dependencies

```bash
python -m pip install -r requirements.txt
```

On Tails, Python 3 is already included. Install the dependency into your user site:

```bash
python3 -m pip install --user cryptography
```

---

## Running ShadowSync

**Windows:**

```powershell
python .\shadowsync.py
```

**Linux / Tails:**

```bash
python3 shadowsync.py
```

### First-run walkthrough

1. **Set a master password.** This password derives the encryption keys for all your vaults. Use a strong, memorable passphrase. There is no recovery mechanism.
2. **Add an app.** Click *Add App*, browse to an executable or AppImage, and choose a profile name (e.g. `Default`).
3. **Trust the app.** ShadowSync will prompt you to verify the SHA-256 fingerprint. Click *Trust & Lock*.
4. **Launch.** Click *Launch*. ShadowSync decrypts the vault, starts the app, and waits.
5. **Close the app.** ShadowSync detects the exit, compresses the updated profile, and re-encrypts the vault.
6. **Done.** Safely eject the USB. Your data is sealed.

### Switching between DIY and FUSE mode

Open the profile settings and toggle the *Sync Mode* selector. ShadowSync will migrate the profile data between formats on the next launch.

---

## Building a Windows Executable

If you want a standalone `.exe` that does not require Python to be installed:

```powershell
.\build_windows.ps1 -InstallTools
```

The `-InstallTools` flag installs `cryptography` and `pyinstaller` via pip first. Omit it if you have already installed them.

**Output:**

```
dist\ShadowSync.exe
```

The `.exe` is Windows-specific, but all `.ssvault` data files are cross-platform and can be opened by the Python script on Linux/Tails.

Build a separate binary for each OS you need. Do not try to run the Windows `.exe` under Wine on Tails.

---

## Security Notes

- **Use a strong master password.** The vaults are only as secure as your passphrase. A short or guessable password makes the AES-256 irrelevant.
- **DIY mode and flash storage.** When ShadowSync rewrites a vault, the old ciphertext is logically deleted but may remain in physical NAND cells due to USB/SSD wear levelling. ShadowSync does not attempt secure erasure of flash media, because wear levelling makes it unreliable. Use full-disk encryption on the USB drive (e.g. VeraCrypt) if physical-access adversaries are in your threat model.
- **Tails/tmpfs.** In DIY mode, the decrypted profile lives in RAM (tmpfs) during the session. It disappears instantly when power is cut. In FUSE mode, the decrypted data never leaves the USB — the ciphertext is there, but the cleartext only exists in the kernel's page cache.
- **TOFU limitations.** TOFU prevents a changed binary from running silently, but it does not verify the source of the original binary. Verify checksums from the official app distributor before trusting an executable for the first time.
- **Bubblewrap sandbox.** The sandbox reduces the blast radius if an app is malicious or compromised, but it is not a full security boundary. A sophisticated exploit can escape Bubblewrap.

---

## License

ShadowSync is free software, licensed under the **GNU General Public License v3.0**.

You are free to use, study, modify, and distribute this software. Any modified version you distribute must also be released under GPLv3 — it cannot be made proprietary.

See [LICENSE](LICENSE) for the full terms.

```
ShadowSync — Encrypted persistence bridge for amnesic OS sessions
Copyright (C) 2026  sreedev-us

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
```
