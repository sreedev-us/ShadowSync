#!/usr/bin/env python3
"""
ShadowSync: encrypted cross-platform persistence for amnesic environments.

The vault format is portable across Windows, Tails, and other Linux systems:
profile data is zipped, encrypted with AES-GCM, and protected by a password
through PBKDF2-HMAC-SHA256.
"""

from __future__ import annotations

import atexit
import base64
import io
import hashlib
import json
import math
import os
import platform
import queue
import shutil
import signal
import stat
import subprocess
import tempfile
import threading
import sys
import time
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ImportError:  # pragma: no cover
    AESGCM = None  # type: ignore[assignment]

try:
    import win32api
    import win32con
    _HAS_WIN32 = True
except ImportError:
    _HAS_WIN32 = False

import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import customtkinter as ctk

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

MAGIC = b"SHADOWSYNC1\n"
KDF_ITERATIONS = 390_000
MODE_DIY = "diy"
MODE_FUSE = "fuse"
HEARTBEAT_SECONDS = 15 * 60
APPIMAGE_SCAN_DEPTH = 2
VERDICT_VERIFIED = "verified"
VERDICT_FIRST_RUN = "first_run"
VERDICT_MISMATCH = "mismatch"

# ---------------------------------------------------------------------------
# Hydrate feature constants
# ---------------------------------------------------------------------------
HYDRATE_VAULT_NAME = "hydrate_config.json.ssvault"
OS_SETTINGS_VAULT_NAME = "os_settings/os_state.ssvault"
FILES_VAULT_SUBPATH = "ShadowSyncFiles/manual-files.ssvault"
_IS_LINUX = platform.system().lower() == "linux"
_IS_WINDOWS = platform.system().lower() == "windows"


def default_profile_paths() -> Dict[str, str]:
    home = Path.home()
    system = platform.system().lower()
    if system == "windows":
        appdata = Path(os.environ.get("APPDATA", home / "AppData" / "Roaming"))
        local = Path(os.environ.get("LOCALAPPDATA", home / "AppData" / "Local"))
        return {
            "Custom": "",
            "Session": str(appdata / "Session"),
            "SimpleX": str(local / "simplex"),
            "Signal": str(appdata / "Signal"),
            "Element": str(appdata / "Element"),
            "Brave": str(local / "BraveSoftware"),
            "KeePassXC": str(appdata / "keepassxc"),
        }
    return {
        "Custom": "",
        "Session": str(home / ".config" / "Session"),
        "SimpleX": str(home / ".local" / "share" / "simplex"),
        "Signal": str(home / ".config" / "Signal"),
        "Element": str(home / ".config" / "Element"),
        "Brave": str(home / ".config" / "BraveSoftware"),
        "KeePassXC": str(home / ".config" / "keepassxc"),
    }


class ShadowSyncError(RuntimeError):
    pass


@dataclass
class SecurityVerdict:
    status: str
    app_name: str
    sha256: str
    registry_path: Path
    matched_registry_name: str = ""
    sandbox_recommended: bool = False

    @property
    def title(self) -> str:
        if self.status == VERDICT_VERIFIED:
            return "Trusted Signature Match"
        if self.status == VERDICT_MISMATCH:
            return "Corrupted or Tampered"
        return "First-Time Execution Warning"


# ---------------------------------------------------------------------------
# Drive discovery
# ---------------------------------------------------------------------------

def list_mounted_drives() -> List[str]:
    """Return all mountable drive roots on the current platform."""
    drives: List[str] = []
    if _IS_WINDOWS:
        import string
        for letter in string.ascii_uppercase:
            drive = f"{letter}:\\"
            if Path(drive).exists():
                drives.append(drive)
    else:
        # Standard Linux mount bases
        mount_bases = [Path("/media"), Path("/mnt"), Path("/run/media")]
        # Tails/Debian: /media/<user>/<label> — iterate one extra level
        for base in mount_bases:
            if not base.exists():
                continue
            try:
                for sub in base.iterdir():
                    if not sub.is_dir():
                        continue
                    # /run/media/<user>/<label> or /media/<user>/<label>
                    # Check if sub is itself a drive (has files) OR a user dir
                    has_mountable_children = False
                    try:
                        for child in sub.iterdir():
                            if child.is_dir():
                                # Could be a user dir (e.g. /media/amnesia)
                                drives.append(str(child))
                                has_mountable_children = True
                    except (OSError, PermissionError):
                        pass
                    if not has_mountable_children:
                        # sub itself is a drive mount (e.g. /media/usb0)
                        drives.append(str(sub))
            except (OSError, PermissionError):
                pass

        # Tails persistent storage (official install)
        for tails_persist in (
            Path("/live/persistence/TailsData_unlocked"),
            Path("/live/persistence"),
            Path("/live/mount/medium"),
        ):
            if tails_persist.exists() and tails_persist.is_dir():
                drives.append(str(tails_persist))

        # Ventoy data partition label is typically 'Ventoy'
        for ventoy_path in (
            Path("/media/amnesia/Ventoy"),
            Path("/media/user/Ventoy"),
            Path("/run/media/amnesia/Ventoy"),
            Path("/run/media/user/Ventoy"),
        ):
            if ventoy_path.exists() and str(ventoy_path) not in drives:
                drives.append(str(ventoy_path))

        # Always include home as fallback (RAM on Tails but writable)
        home_str = str(Path.home())
        if home_str not in drives:
            drives.append(home_str)

        # Deduplicate while preserving order
        seen: set = set()
        unique: List[str] = []
        for d in drives:
            try:
                resolved = str(Path(d).resolve())
            except OSError:
                resolved = d
            if resolved not in seen:
                seen.add(resolved)
                unique.append(d)
        drives = unique

    return drives


def files_vault_path_for_drive(drive: str) -> Path:
    """Return the file-vault path on an arbitrary drive/mount point."""
    return Path(drive) / FILES_VAULT_SUBPATH


# ---------------------------------------------------------------------------
# Vault helpers
# ---------------------------------------------------------------------------

class PortableVault:
    def __init__(self, path: Path) -> None:
        self.path = path.expanduser().resolve()

    def exists(self) -> bool:
        return self.path.exists()

    def restore_to(self, destination: Path, password: str) -> None:
        if not self.path.exists():
            return
        plaintext = self._decrypt(password)
        staging = Path(tempfile.mkdtemp(prefix="shadowsync-restore-"))
        try:
            with zipfile.ZipFile(io.BytesIO(plaintext), "r") as archive:
                self._safe_extract(archive, staging)
            wipe_directory(destination)
            destination.mkdir(parents=True, exist_ok=True)
            copy_tree_contents(staging, destination)
        finally:
            wipe_directory(staging)

    def extract_to(self, destination: Path, password: str) -> None:
        if not self.path.exists():
            return
        plaintext = self._decrypt(password)
        destination.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(io.BytesIO(plaintext), "r") as archive:
            self._safe_extract_no_overwrite(archive, destination)

    def save_from(self, source: Path, password: str) -> None:
        zip_bytes = io.BytesIO()
        with zipfile.ZipFile(zip_bytes, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            if source.exists():
                for path in sorted(source.rglob("*")):
                    if path.is_file():
                        archive.write(path, path.relative_to(source).as_posix())
        encrypted = self._encrypt(zip_bytes.getvalue(), password)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_bytes(encrypted)
        os.replace(tmp, self.path)

    def save_bytes(self, data: bytes, password: str) -> None:
        """Encrypt raw bytes (for non-folder payloads like JSON)."""
        encrypted = self._encrypt(data, password)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_bytes(encrypted)
        os.replace(tmp, self.path)

    def load_bytes(self, password: str) -> bytes:
        """Decrypt and return raw bytes."""
        return self._decrypt(password)

    def _encrypt(self, plaintext: bytes, password: str) -> bytes:
        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = derive_key(password, salt)
        header = {
            "kdf": "PBKDF2-HMAC-SHA256",
            "iterations": KDF_ITERATIONS,
            "salt": salt.hex(),
            "nonce": nonce.hex(),
            "cipher": "AES-256-GCM",
        }
        header_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, header_bytes)
        return MAGIC + len(header_bytes).to_bytes(4, "big") + header_bytes + ciphertext

    def _decrypt(self, password: str) -> bytes:
        raw = self.path.read_bytes()
        if not raw.startswith(MAGIC):
            raise ShadowSyncError("This is not a ShadowSync portable vault.")
        header_len_start = len(MAGIC)
        header_len = int.from_bytes(raw[header_len_start : header_len_start + 4], "big")
        header_start = header_len_start + 4
        header_bytes = raw[header_start : header_start + header_len]
        ciphertext = raw[header_start + header_len :]
        header = json.loads(header_bytes.decode("utf-8"))
        key = derive_key(password, bytes.fromhex(header["salt"]))
        nonce = bytes.fromhex(header["nonce"])
        try:
            return AESGCM(key).decrypt(nonce, ciphertext, header_bytes)
        except Exception as exc:
            raise ShadowSyncError("Wrong password or damaged vault.") from exc

    def _safe_extract(self, archive: zipfile.ZipFile, destination: Path) -> None:
        root = destination.resolve()
        for member in archive.infolist():
            target = (root / member.filename).resolve()
            if root not in target.parents and target != root:
                raise ShadowSyncError(f"Unsafe vault entry blocked: {member.filename}")
            archive.extract(member, root)

    def _safe_extract_no_overwrite(self, archive: zipfile.ZipFile, destination: Path) -> None:
        root = destination.resolve()
        for member in archive.infolist():
            target = (root / member.filename).resolve()
            if root not in target.parents and target != root:
                raise ShadowSyncError(f"Unsafe vault entry blocked: {member.filename}")
            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            final_target = unique_path(target)
            with archive.open(member, "r") as source, final_target.open("wb") as output:
                shutil.copyfileobj(source, output)


class TofuRegistry:
    def __init__(self, storage_root: Path) -> None:
        self.path = storage_root.expanduser().resolve() / "user_registry.enc"
        self.data = {"version": 1, "apps": {}}

    def load(self, password: str) -> None:
        if not self.path.exists():
            self.data = {"version": 1, "apps": {}}
            return
        plaintext = PortableVault(self.path)._decrypt(password)
        try:
            loaded = json.loads(plaintext.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise ShadowSyncError("TOFU registry is damaged or not valid JSON.") from exc
        if not isinstance(loaded, dict) or not isinstance(loaded.get("apps"), dict):
            raise ShadowSyncError("TOFU registry has an unsupported format.")
        self.data = loaded

    def save(self, password: str) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        plaintext = json.dumps(self.data, indent=2, sort_keys=True).encode("utf-8")
        encrypted = PortableVault(self.path)._encrypt(plaintext, password)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_bytes(encrypted)
        os.replace(tmp, self.path)

    def get_entry(self, app_name: str) -> Optional[Dict[str, object]]:
        apps = self.data.setdefault("apps", {})
        if not isinstance(apps, dict):
            self.data["apps"] = {}
            apps = self.data["apps"]
        return apps.get(sanitize_app_name(app_name))

    def trust(self, app_name: str, executable: Path, sha256: str) -> None:
        apps = self.data.setdefault("apps", {})
        if not isinstance(apps, dict):
            self.data["apps"] = {}
            apps = self.data["apps"]
        apps[sanitize_app_name(app_name)] = {
            "display_name": app_name,
            "sha256": sha256,
            "first_trusted_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "last_seen_path": str(executable),
        }


class GocryptfsBridge:
    def __init__(self, cipher_dir: Path, mount_dir: Path, password: str) -> None:
        self.cipher_dir = cipher_dir.expanduser().resolve()
        self.mount_dir = mount_dir.expanduser().resolve()
        self.password = password
        self.mounted = False

    def mount(self) -> None:
        if platform.system().lower() == "windows":
            raise ShadowSyncError("FUSE mode requires Linux/Tails with gocryptfs installed.")
        gocryptfs = resolve_gocryptfs_binary()
        self.cipher_dir.mkdir(parents=True, exist_ok=True)
        self._ensure_mountpoint_empty()
        with self._passfile() as passfile:
            if not (self.cipher_dir / "gocryptfs.conf").exists():
                self._run([gocryptfs, "-q", "-init", "-passfile", str(passfile), str(self.cipher_dir)])
            self._run([gocryptfs, "-q", "-passfile", str(passfile), str(self.cipher_dir), str(self.mount_dir)])
        self.mounted = True

    def unmount(self) -> None:
        if not self.mounted:
            return
        commands = [
            ["fusermount3", "-u", str(self.mount_dir)],
            ["fusermount", "-u", str(self.mount_dir)],
            ["umount", str(self.mount_dir)],
        ]
        for command in commands:
            if shutil.which(command[0]) is None:
                continue
            completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
            if completed.returncode == 0:
                self.mounted = False
                return
        raise ShadowSyncError("Could not unmount the gocryptfs profile folder.")

    def flush(self) -> None:
        subprocess.run(["sync"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)

    def _ensure_mountpoint_empty(self) -> None:
        self.mount_dir.mkdir(parents=True, exist_ok=True)
        try:
            next(self.mount_dir.iterdir())
        except StopIteration:
            return
        raise ShadowSyncError(
            "FUSE mode needs an empty profile folder as the mount point. "
            "Move existing data into a DIY vault first, or choose an empty folder."
        )

    def _passfile(self):
        class Passfile:
            def __init__(self, password: str) -> None:
                self.password = password
                self.path: Optional[Path] = None

            def __enter__(self) -> Path:
                handle = tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8")
                self.path = Path(handle.name)
                handle.write(self.password)
                handle.write("\n")
                handle.close()
                os.chmod(self.path, 0o600)
                return self.path

            def __exit__(self, *_exc: object) -> None:
                if self.path:
                    secure_unlink(self.path)

        return Passfile(self.password)

    def _run(self, command: list[str]) -> None:
        completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        if completed.returncode != 0:
            raise ShadowSyncError(completed.stderr.strip() or f"Command failed: {' '.join(command)}")


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------

def app_storage_paths(storage_root: Path, app_name: str, profile_name: str = "Default") -> Dict[str, Path]:
    safe_name = sanitize_app_name(app_name)
    safe_profile = sanitize_app_name(profile_name)
    app_root = storage_root.expanduser().resolve() / "apps" / safe_name
    profile_root = app_root / "profiles" / safe_profile
    return {
        "app_root": app_root,
        "profile_root": profile_root,
        "portable_vault": profile_root / "profile.ssvault",
        "fuse_cipher_dir": profile_root / "gocryptfs",
    }


def files_vault_path(storage_root: Path) -> Path:
    return storage_root.expanduser().resolve() / "files" / "manual-files.ssvault"


def hydrate_config_path(storage_root: Path) -> Path:
    return storage_root.expanduser().resolve() / HYDRATE_VAULT_NAME


def os_settings_vault_path(storage_root: Path) -> Path:
    return storage_root.expanduser().resolve() / OS_SETTINGS_VAULT_NAME


def user_registry_path(storage_root: Path) -> Path:
    return storage_root.expanduser().resolve() / "user_registry.enc"


def is_valid_shadowsync_store(path: Path) -> bool:
    """Check if a directory looks like a valid ShadowSync storage root."""
    if not path.is_dir():
        return False
    markers = [
        path / "apps",
        path / "files",
        path / "os_settings",
        path / "user_registry.enc",
        path / HYDRATE_VAULT_NAME,
    ]
    has_marker = any(m.exists() for m in markers)
    if has_marker:
        return True
    try:
        for item in path.iterdir():
            if item.is_file() and item.suffix == ".ssvault":
                return True
            if item.is_dir():
                try:
                    for sub in item.iterdir():
                        if sub.is_file() and sub.suffix == ".ssvault":
                            return True
                except (OSError, PermissionError):
                    continue
    except (OSError, PermissionError):
        pass
    return False


def find_shadowsync_stores(max_depth: int = 3) -> list[Path]:
    """Scan all drives (Windows) or mount points (Linux/Tails/Ventoy) for ShadowSyncStore directories."""
    found: list[Path] = []
    seen: set[Path] = set()
    system = platform.system().lower()
    scan_roots: list[Path] = []

    if system == "windows":
        import string
        for letter in string.ascii_uppercase:
            drive = Path(f"{letter}:\\")
            if drive.exists():
                scan_roots.append(drive)
    else:
        # Use the comprehensive list_mounted_drives() which already handles Tails+Ventoy
        for d in list_mounted_drives():
            p = Path(d)
            if p.exists():
                scan_roots.append(p)
        # Also scan home (RAM on Tails but may hold a store)
        if Path.home() not in scan_roots:
            scan_roots.append(Path.home())
        # Tails persistent directory — always check directly
        for tails_path in (
            Path("/live/persistence/TailsData_unlocked"),
            Path("/live/persistence"),
        ):
            if tails_path.exists() and tails_path not in scan_roots:
                scan_roots.append(tails_path)

    cwd = Path.cwd()
    prioritized = [cwd]
    for root in scan_roots:
        try:
            resolved = root.resolve()
        except OSError:
            continue
        if resolved not in seen and resolved != cwd.resolve():
            prioritized.append(resolved)
            seen.add(resolved)

    skipped = {
        ".git", "__pycache__", "node_modules", "System Volume Information",
        "$RECYCLE.BIN", "$Recycle.Bin", "lost+found", "Windows", "Program Files",
        "Program Files (x86)", "ProgramData", "Recovery", ".Trash",
        "AppData", ".local", ".cache", ".config",
        # Ventoy/live system directories to skip
        "syslinux", "EFI", "boot", "ventoy", "live",
    }

    def _scan_dir(directory: Path, depth: int) -> None:
        if depth > max_depth:
            return
        try:
            for entry in directory.iterdir():
                if not entry.is_dir():
                    continue
                if entry.name in skipped:
                    continue
                if entry.name == "ShadowSyncStore" or entry.name.lower() == "shadowsyncstore":
                    resolved = entry.resolve()
                    if resolved not in seen and is_valid_shadowsync_store(entry):
                        found.append(resolved)
                        seen.add(resolved)
                    continue
                if is_valid_shadowsync_store(entry):
                    resolved = entry.resolve()
                    if resolved not in seen:
                        found.append(resolved)
                        seen.add(resolved)
                    continue
                if depth < max_depth:
                    _scan_dir(entry, depth + 1)
        except (OSError, PermissionError):
            pass

    for root in prioritized:
        if root.name == "ShadowSyncStore" or root.name.lower() == "shadowsyncstore":
            resolved = root.resolve()
            if resolved not in seen and is_valid_shadowsync_store(root):
                found.append(resolved)
                seen.add(resolved)
            continue
        _scan_dir(root, 0)

    return found


# ---------------------------------------------------------------------------
# String / name helpers
# ---------------------------------------------------------------------------

def sanitize_app_name(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip()).strip("-._")
    return cleaned or "CustomApp"


def infer_app_name(executable: Path, preset: str) -> str:
    if preset and preset != "Custom":
        return preset
    stem = executable.expanduser().name
    for suffix in (".AppImage", ".appimage", ".exe"):
        if stem.endswith(suffix):
            stem = stem[: -len(suffix)]
    return sanitize_app_name(Path(stem).stem)


def display_app_name(raw_name: str) -> str:
    stem = raw_name
    for suffix in (".AppImage", ".appimage", ".exe"):
        if stem.endswith(suffix):
            stem = stem[: -len(suffix)]
    words = re.sub(r"[-_]+", " ", Path(stem).stem).strip()
    return " ".join(part.capitalize() for part in words.split()) or "Custom App"


def guess_profile_path(app_name: str) -> str:
    presets = default_profile_paths()
    normalized = sanitize_app_name(app_name).lower()
    known = {
        "session": "Session",
        "simplex": "SimpleX",
        "signal": "Signal",
        "signal-desktop": "Signal",
        "element": "Element",
        "element-desktop": "Element",
        "brave": "Brave",
        "brave-browser": "Brave",
        "keepassxc": "KeePassXC",
    }
    if normalized in known:
        return presets[known[normalized]]
    if platform.system().lower() == "windows":
        appdata = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
        return str(appdata / sanitize_app_name(app_name))
    return str(Path.home() / ".config" / sanitize_app_name(app_name))


# ---------------------------------------------------------------------------
# Crypto / hashing
# ---------------------------------------------------------------------------

def calculate_file_sha256(file_path: Path) -> str:
    sha256_hash = hashlib.sha256()
    with file_path.open("rb") as handle:
        for byte_block in iter(lambda: handle.read(65536), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def verify_executable_hash(file_path: Path, app_name: str, storage_root: Path, password: str) -> SecurityVerdict:
    file_hash = calculate_file_sha256(file_path)
    registry = TofuRegistry(storage_root)
    registry.load(password)
    entry = registry.get_entry(app_name)
    if not entry:
        return SecurityVerdict(
            status=VERDICT_FIRST_RUN,
            app_name=app_name,
            sha256=file_hash,
            registry_path=registry.path,
            sandbox_recommended=True,
        )
    trusted_hash = str(entry.get("sha256", "")).lower()
    if trusted_hash == file_hash:
        return SecurityVerdict(
            status=VERDICT_VERIFIED,
            app_name=app_name,
            sha256=file_hash,
            registry_path=registry.path,
            matched_registry_name=str(entry.get("display_name", app_name)),
        )
    return SecurityVerdict(
        status=VERDICT_MISMATCH,
        app_name=app_name,
        sha256=file_hash,
        registry_path=registry.path,
        matched_registry_name=str(entry.get("display_name", app_name)),
    )


def security_verdict_message(verdict: SecurityVerdict) -> str:
    short_hash = f"{verdict.sha256[:16]}...{verdict.sha256[-12:]}"
    if verdict.status == VERDICT_VERIFIED:
        detail = f"This executable matches the signature ShadowSync previously locked for {verdict.matched_registry_name}."
        action = "Do you want ShadowSync to use this executable?"
    elif verdict.status == VERDICT_MISMATCH:
        detail = (
            f"ShadowSync has seen {verdict.matched_registry_name} before, but this file's fingerprint changed. "
            "This could be an update, corruption, or tampering. Execution is blocked unless you intentionally re-trust it."
        )
        action = "ShadowSync will not use this executable."
    else:
        detail = (
            f"ShadowSync has never seen {verdict.app_name} before. If you just downloaded it from a source you trust, "
            "choose Trust & Lock to record this fingerprint and detect tampering later."
        )
        action = "Do you want to Trust & Lock this executable?"
    return (
        f"{verdict.title}\n\n"
        f"Application: {verdict.app_name}\n"
        f"SHA-256: {short_hash}\n"
        f"Registry: {verdict.registry_path}\n\n"
        f"{detail}\n\n"
        + action
    )


def resolve_gocryptfs_binary() -> str:
    system = platform.system().lower()
    local_candidates = []
    if system == "linux":
        local_candidates = [
            Path.cwd() / "assets" / "gocryptfs",
            Path(__file__).resolve().parent / "assets" / "gocryptfs",
        ]
    for candidate in local_candidates:
        if candidate.exists():
            mode = candidate.stat().st_mode
            candidate.chmod(mode | stat.S_IXUSR)
            return str(candidate)
    system_binary = shutil.which("gocryptfs")
    if system_binary:
        return system_binary
    raise ShadowSyncError(
        "FUSE mode requires gocryptfs. Put a static Linux binary at assets/gocryptfs, "
        "install gocryptfs on the host, or use DIY mode."
    )


def depth_limited_files(root: Path, max_depth: int):
    stack = [(root, 0)]
    skipped = {
        ".git", ".qodo", "__pycache__",
        "System Volume Information", "$RECYCLE.BIN", "lost+found",
        "ShadowSyncStore",
    }
    while stack:
        current, depth = stack.pop()
        try:
            for entry in current.iterdir():
                if entry.name in skipped:
                    continue
                if entry.is_file():
                    yield entry
                elif depth < max_depth and entry.is_dir() and not entry.is_symlink():
                    stack.append((entry, depth + 1))
        except OSError:
            continue


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def copy_tree_contents(source: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    for item in source.iterdir():
        target = destination / item.name
        if item.is_dir():
            shutil.copytree(item, target, symlinks=True)
        else:
            shutil.copy2(item, target, follow_symlinks=False)


def copy_into_unique(source: Path, destination_dir: Path) -> Path:
    destination_dir.mkdir(parents=True, exist_ok=True)
    target = unique_path(destination_dir / source.name)
    if source.is_dir():
        shutil.copytree(source, target, symlinks=True)
    else:
        shutil.copy2(source, target, follow_symlinks=False)
    return target


def unique_path(path: Path) -> Path:
    if not path.exists():
        return path
    stem = path.stem
    suffix = path.suffix
    parent = path.parent
    counter = 2
    while True:
        candidate = parent / f"{stem}-{counter}{suffix}"
        if not candidate.exists():
            return candidate
        counter += 1


def wipe_directory(directory: Path) -> None:
    if not directory.exists():
        return
    for path in sorted(directory.rglob("*"), reverse=True):
        try:
            if path.is_file() or path.is_symlink():
                secure_unlink(path)
            elif path.is_dir():
                path.rmdir()
        except OSError:
            pass
    try:
        directory.rmdir()
    except OSError:
        pass


def secure_unlink(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    except OSError:
        try:
            path.unlink()
        except OSError:
            pass


def fingerprint_tree(root: Path) -> str:
    digest = hashlib.sha256()
    if not root.exists():
        return ""
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        try:
            info = path.stat()
        except OSError:
            continue
        digest.update(path.relative_to(root).as_posix().encode("utf-8", "surrogateescape"))
        digest.update(str(info.st_mtime_ns).encode("ascii"))
        digest.update(str(info.st_size).encode("ascii"))
    return digest.hexdigest()


# ---------------------------------------------------------------------------
# OS Settings — data model
# ---------------------------------------------------------------------------

@dataclass
class WifiProfile:
    ssid: str
    auth_type: str = ""          # WPA2, WPA3, open, etc.
    blob: str = ""               # base64-encoded exported profile (XML on Windows, nmconnection on Linux)
    password_hint: str = ""      # optional plaintext fallback for nmcli connect

    def to_dict(self) -> dict:
        return {
            "ssid": self.ssid,
            "auth_type": self.auth_type,
            "blob": self.blob,
            "password_hint": self.password_hint,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "WifiProfile":
        return cls(
            ssid=str(d.get("ssid", "")),
            auth_type=str(d.get("auth_type", "")),
            blob=str(d.get("blob", "")),
            password_hint=str(d.get("password_hint", "")),
        )


@dataclass
class OSSettings:
    """All OS-level state captured for hibernation / restore."""
    wifi_profiles: List[WifiProfile] = field(default_factory=list)
    wallpaper_path: str = ""
    os_theme: str = "dark"
    hostname: str = ""
    env_vars: Dict[str, str] = field(default_factory=dict)
    shell_rc: str = ""           # ~/.bashrc / .zshrc on Linux
    shell_aliases: str = ""      # extracted alias lines
    git_config: str = ""         # ~/.gitconfig
    registry_exports: Dict[str, str] = field(default_factory=dict)  # {key: base64_reg}
    installed_apps: List[str] = field(default_factory=list)  # human-readable app list
    captured_at: str = ""

    def to_dict(self) -> dict:
        return {
            "wifi_profiles": [w.to_dict() for w in self.wifi_profiles],
            "wallpaper_path": self.wallpaper_path,
            "os_theme": self.os_theme,
            "hostname": self.hostname,
            "env_vars": self.env_vars,
            "shell_rc": self.shell_rc,
            "shell_aliases": self.shell_aliases,
            "git_config": self.git_config,
            "registry_exports": self.registry_exports,
            "installed_apps": self.installed_apps,
            "captured_at": self.captured_at,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "OSSettings":
        return cls(
            wifi_profiles=[WifiProfile.from_dict(w) for w in d.get("wifi_profiles", [])],
            wallpaper_path=str(d.get("wallpaper_path", "")),
            os_theme=str(d.get("os_theme", "dark")),
            hostname=str(d.get("hostname", "")),
            env_vars=dict(d.get("env_vars", {})),
            shell_rc=str(d.get("shell_rc", "")),
            shell_aliases=str(d.get("shell_aliases", "")),
            git_config=str(d.get("git_config", "")),
            registry_exports=dict(d.get("registry_exports", {})),
            installed_apps=list(d.get("installed_apps", [])),
            captured_at=str(d.get("captured_at", "")),
        )

    def save(self, storage_root: Path, password: str) -> None:
        vault_path = os_settings_vault_path(storage_root)
        data = json.dumps(self.to_dict(), indent=2).encode("utf-8")
        PortableVault(vault_path).save_bytes(data, password)

    @classmethod
    def load(cls, storage_root: Path, password: str) -> "OSSettings":
        vault_path = os_settings_vault_path(storage_root)
        if not vault_path.exists():
            return cls()
        raw = PortableVault(vault_path).load_bytes(password)
        data = json.loads(raw.decode("utf-8"))
        return cls.from_dict(data)


# ---------------------------------------------------------------------------
# OS Settings — worker (capture & restore)
# ---------------------------------------------------------------------------

class OSSettingsWorker:
    """Platform-aware capture and restore of OS-level state."""

    def __init__(self, log: queue.Queue) -> None:
        self.log = log

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def capture(self) -> OSSettings:
        settings = OSSettings()
        settings.captured_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        settings.hostname = platform.node()
        settings.os_theme = self._capture_theme()
        settings.wallpaper_path = self._capture_wallpaper()
        settings.wifi_profiles = self._capture_wifi()
        settings.env_vars = self._capture_env_vars()
        settings.git_config = self._capture_git_config()
        settings.installed_apps = self._capture_installed_apps()
        if _IS_LINUX:
            settings.shell_rc = self._capture_shell_rc()
            settings.shell_aliases = self._capture_shell_aliases()
        if _IS_WINDOWS:
            settings.registry_exports = self._capture_registry()
        self._log(
            f"OS state captured: {len(settings.wifi_profiles)} WiFi profiles, "
            f"{len(settings.installed_apps)} installed apps, "
            f"{len(settings.env_vars)} env vars, theme={settings.os_theme}"
        )
        return settings

    def restore(self, settings: OSSettings) -> None:
        self._restore_wifi(settings.wifi_profiles)
        if settings.wallpaper_path:
            self._restore_wallpaper(settings.wallpaper_path)
        if settings.os_theme:
            self._restore_theme(settings.os_theme)
        if settings.env_vars:
            self._restore_env_vars(settings.env_vars)
        if settings.git_config:
            self._restore_git_config(settings.git_config)
        if _IS_LINUX and settings.shell_rc:
            self._restore_shell_rc(settings.shell_rc)
        if _IS_WINDOWS and settings.registry_exports:
            self._restore_registry(settings.registry_exports)
        self._log("OS state restore complete.")

    # ------------------------------------------------------------------
    # WiFi — capture
    # ------------------------------------------------------------------

    def _capture_wifi(self) -> List[WifiProfile]:
        if _IS_WINDOWS:
            return self._capture_wifi_windows()
        if _IS_LINUX:
            return self._capture_wifi_linux()
        return []

    @staticmethod
    def _is_root() -> bool:
        """Return True if running as root/admin."""
        try:
            return os.getuid() == 0
        except AttributeError:
            return False  # Windows

    @staticmethod
    def _sudo_prefix() -> List[str]:
        """Return sudo prefix when not root, for subprocess calls.

        On Tails, the 'amnesia' user has passwordless sudo configured,
        so we use plain 'sudo' (without -n) to allow it to work.
        On other systems we still try pkexec first for GUI contexts.
        """
        if OSSettingsWorker._is_root():
            return []
        # On Tails the user is 'amnesia' and passwordless sudo is available
        # Detect Tails by checking /etc/os-release or specific Tails paths
        _is_tails = Path("/etc/amnesia").exists() or Path("/live/boot-dev").exists() or \
                    Path("/lib/live/mount/medium").exists() or \
                    os.environ.get("USER", "") == "amnesia" or \
                    Path.home().name == "amnesia"
        if shutil.which("sudo"):
            # On Tails: plain sudo (passwordless)
            # On other systems: sudo without -n is safer than -n which silently fails
            return ["sudo"]
        if shutil.which("pkexec"):
            return ["pkexec"]
        return []

    def _capture_wifi_windows(self) -> List[WifiProfile]:
        profiles: List[WifiProfile] = []
        # List profiles
        result = subprocess.run(
            ["netsh", "wlan", "show", "profiles"],
            capture_output=True, text=True, check=False,
        )
        if result.returncode != 0:
            self._log("WiFi capture: netsh not available or no profiles.")
            return profiles

        # Extract profile names
        names = re.findall(r"All User Profile\s*:\s*(.+)", result.stdout)
        if not names:
            names = re.findall(r"User Profile\s*:\s*(.+)", result.stdout)

        tmp_dir = Path(tempfile.mkdtemp(prefix="shadowsync-wifi-"))
        try:
            for name in names:
                name = name.strip()
                # Export with key=clear (requires admin; falls back to key=remove if not)
                for key_opt in ("key=clear", "key=remove"):
                    r = subprocess.run(
                        ["netsh", "wlan", "export", "profile",
                         f"name={name}", key_opt, f"folder={tmp_dir}"],
                        capture_output=True, text=True, check=False,
                    )
                    if r.returncode == 0:
                        break
                # Find generated XML file
                xml_files = list(tmp_dir.glob("*.xml"))
                if not xml_files:
                    continue
                xml_path = xml_files[-1]
                xml_data = xml_path.read_bytes()
                blob = base64.b64encode(xml_data).decode("ascii")
                xml_path.unlink(missing_ok=True)

                # Try to extract auth type from XML
                auth_match = re.search(r"<authentication>(.+?)</authentication>", xml_data.decode("utf-8", errors="ignore"))
                auth_type = auth_match.group(1) if auth_match else ""

                profiles.append(WifiProfile(ssid=name, auth_type=auth_type, blob=blob))
                self._log(f"WiFi captured: {name} ({auth_type})")
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)
        return profiles

    def _capture_wifi_linux(self) -> List[WifiProfile]:
        profiles: List[WifiProfile] = []
        # List connections via nmcli
        result = subprocess.run(
            ["nmcli", "-t", "-f", "NAME,TYPE", "connection", "show"],
            capture_output=True, text=True, check=False,
        )
        if result.returncode != 0:
            self._log("WiFi capture: nmcli not available — trying iw/iwconfig fallback.")
            return self._capture_wifi_linux_fallback()

        wifi_names = []
        for line in result.stdout.splitlines():
            parts = line.split(":")
            if len(parts) >= 2 and "wireless" in parts[1].lower():
                wifi_names.append(parts[0].strip())

        if not wifi_names:
            self._log("WiFi capture: no wireless connections found in nmcli.")
            return profiles

        # Search multiple NM connection directories (Tails may use /run/NetworkManager)
        nm_dirs = [
            Path("/etc/NetworkManager/system-connections"),
            Path("/run/NetworkManager/system-connections"),
            Path("/var/run/NetworkManager/system-connections"),
        ]

        for name in wifi_names:
            blob = ""
            auth_type = ""

            # 1) Try nmcli connection export (best: works even without root for some)
            export_result = subprocess.run(
                ["nmcli", "--show-secrets", "connection", "export", name],
                capture_output=True, check=False,
            )
            if export_result.returncode == 0 and export_result.stdout:
                blob = base64.b64encode(export_result.stdout).decode("ascii")
                self._log(f"WiFi captured via nmcli export: {name}")
            else:
                # 2) Try reading the .nmconnection file directly (may need root)
                for nm_dir in nm_dirs:
                    conn_file = nm_dir / f"{name}.nmconnection"
                    if not conn_file.exists():
                        # also try without spaces
                        conn_file = nm_dir / f"{name.replace(' ', '_')}.nmconnection"
                    if conn_file.exists():
                        try:
                            raw = conn_file.read_bytes()
                            blob = base64.b64encode(raw).decode("ascii")
                            self._log(f"WiFi captured from file: {conn_file}")
                            break
                        except (OSError, PermissionError):
                            # 3) Try with sudo
                            sudo = self._sudo_prefix()
                            if sudo:
                                r2 = subprocess.run(
                                    sudo + ["cat", str(conn_file)],
                                    capture_output=True, check=False,
                                )
                                if r2.returncode == 0 and r2.stdout:
                                    blob = base64.b64encode(r2.stdout).decode("ascii")
                                    self._log(f"WiFi captured via sudo: {name}")
                                    break
                            self._log(f"WiFi capture: cannot read {conn_file} (need root).")

            # Extract password hint from blob if it's a .nmconnection (ini format)
            password_hint = ""
            if blob:
                try:
                    raw_str = base64.b64decode(blob).decode("utf-8", errors="ignore")
                    # Look for psk= in [wifi-security] section
                    psk_match = re.search(r"^psk=(.+)$", raw_str, re.MULTILINE)
                    if psk_match:
                        password_hint = psk_match.group(1).strip()
                    # Extract auth type
                    key_mgmt_match = re.search(r"^key-mgmt=(.+)$", raw_str, re.MULTILINE)
                    if key_mgmt_match:
                        auth_type = key_mgmt_match.group(1).strip()
                except Exception:
                    pass

            profiles.append(WifiProfile(
                ssid=name,
                blob=blob,
                auth_type=auth_type,
                password_hint=password_hint,
            ))
            if not blob:
                self._log(f"WiFi captured (no blob/needs root for full export): {name}")
        return profiles

    def _capture_wifi_linux_fallback(self) -> List[WifiProfile]:
        """Fallback WiFi capture when nmcli is unavailable."""
        profiles: List[WifiProfile] = []
        # Try iwconfig to find current SSID
        for tool in ("iwgetid", "iw"):
            if not shutil.which(tool):
                continue
            if tool == "iwgetid":
                r = subprocess.run(["iwgetid", "-r"], capture_output=True, text=True, check=False)
                if r.returncode == 0 and r.stdout.strip():
                    ssid = r.stdout.strip()
                    profiles.append(WifiProfile(ssid=ssid))
                    self._log(f"WiFi fallback (iwgetid): found current SSID {ssid}")
            break
        return profiles

    # ------------------------------------------------------------------
    # WiFi — restore
    # ------------------------------------------------------------------

    def _restore_wifi(self, profiles: List[WifiProfile]) -> None:
        if _IS_WINDOWS:
            self._restore_wifi_windows(profiles)
        elif _IS_LINUX:
            self._restore_wifi_linux(profiles)

    def _restore_wifi_windows(self, profiles: List[WifiProfile]) -> None:
        tmp_dir = Path(tempfile.mkdtemp(prefix="shadowsync-wifi-restore-"))
        try:
            for profile in profiles:
                if not profile.blob:
                    # Fallback: use nmcli-style connect
                    if profile.password_hint:
                        subprocess.run(
                            ["netsh", "wlan", "connect", f"name={profile.ssid}"],
                            capture_output=True, check=False,
                        )
                    continue
                xml_data = base64.b64decode(profile.blob)
                xml_file = tmp_dir / f"{sanitize_app_name(profile.ssid)}.xml"
                xml_file.write_bytes(xml_data)
                r = subprocess.run(
                    ["netsh", "wlan", "add", "profile", f"filename={xml_file}"],
                    capture_output=True, text=True, check=False,
                )
                if r.returncode == 0:
                    self._log(f"WiFi restored: {profile.ssid}")
                else:
                    self._log(f"WiFi restore failed for {profile.ssid}: {r.stderr.strip()}")
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def _restore_wifi_linux(self, profiles: List[WifiProfile]) -> None:
        nm_dir = Path("/etc/NetworkManager/system-connections")
        sudo = self._sudo_prefix()
        needs_reload = False
        activated_ssids: List[str] = []

        for profile in profiles:
            if not profile.blob:
                # Fallback: nmcli connect with stored password
                if profile.password_hint and profile.ssid:
                    cmd = ["nmcli", "dev", "wifi", "connect", profile.ssid,
                           "password", profile.password_hint]
                    result = subprocess.run(
                        cmd, capture_output=True, text=True, check=False, timeout=20,
                    )
                    if result.returncode == 0:
                        self._log(f"WiFi connected: {profile.ssid}")
                    else:
                        self._log(f"WiFi connect failed for {profile.ssid}: {result.stderr.strip()}")
                continue

            raw = base64.b64decode(profile.blob)
            conn_file = nm_dir / f"{profile.ssid}.nmconnection"
            written = False

            # Try direct write first
            try:
                nm_dir.mkdir(parents=True, exist_ok=True)
                conn_file.write_bytes(raw)
                conn_file.chmod(0o600)
                written = True
                self._log(f"WiFi profile written: {profile.ssid}")
            except (OSError, PermissionError):
                # Try with sudo
                if sudo:
                    try:
                        import tempfile as _tmpmod
                        with _tmpmod.NamedTemporaryFile(delete=False, suffix=".nmconnection") as tf:
                            tf.write(raw)
                            tf_path = tf.name
                        r_cp = subprocess.run(
                            sudo + ["cp", tf_path, str(conn_file)],
                            capture_output=True, check=False,
                        )
                        subprocess.run(
                            sudo + ["chmod", "600", str(conn_file)],
                            capture_output=True, check=False,
                        )
                        os.unlink(tf_path)
                        if r_cp.returncode == 0:
                            written = True
                            self._log(f"WiFi profile written (sudo): {profile.ssid}")
                        else:
                            self._log(f"WiFi restore: sudo copy failed for {profile.ssid}")
                    except Exception as e:
                        self._log(f"WiFi restore: sudo fallback failed for {profile.ssid}: {e}")
                else:
                    self._log(f"WiFi restore: cannot write {conn_file} (need root)")

            if written:
                needs_reload = True
                activated_ssids.append(profile.ssid)

        # Reload NetworkManager after writing profiles
        if needs_reload:
            reload_cmd = sudo + ["nmcli", "connection", "reload"] if sudo else ["nmcli", "connection", "reload"]
            r = subprocess.run(
                reload_cmd, capture_output=True, text=True, check=False,
            )
            if r.returncode == 0:
                self._log("NetworkManager connections reloaded.")
            else:
                self._log(f"nmcli reload failed: {r.stderr.strip()}")

            # Activate each written connection
            for ssid in activated_ssids:
                up_result = subprocess.run(
                    ["nmcli", "connection", "up", ssid],
                    capture_output=True, text=True, check=False, timeout=20,
                )
                if up_result.returncode == 0:
                    self._log(f"WiFi activated: {ssid}")
                else:
                    self._log(f"WiFi activate failed for {ssid}: {up_result.stderr.strip()} — trying dev wifi connect")
                    # Last resort: nmcli dev wifi connect
                    for wp in profiles:
                        if wp.ssid == ssid and wp.password_hint:
                            subprocess.run(
                                ["nmcli", "dev", "wifi", "connect", ssid, "password", wp.password_hint],
                                capture_output=True, check=False, timeout=20,
                            )
                            break

    # ------------------------------------------------------------------
    # Wallpaper
    # ------------------------------------------------------------------

    def _capture_wallpaper(self) -> str:
        if _IS_WINDOWS:
            try:
                import winreg
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                    r"Control Panel\Desktop") as key:
                    value, _ = winreg.QueryValueEx(key, "Wallpaper")
                    return str(value)
            except Exception:
                return ""
        if _IS_LINUX:
            # Try gsettings with explicit DBUS address
            env = self._gnome_env()
            if env:
                r = subprocess.run(
                    ["gsettings", "get", "org.gnome.desktop.background", "picture-uri"],
                    capture_output=True, text=True, check=False, env=env,
                )
                if r.returncode == 0 and r.stdout.strip():
                    return r.stdout.strip().strip("'\"")
            # Try xfconf (XFCE)
            r2 = subprocess.run(
                ["xfconf-query", "-c", "xfce4-desktop", "-p", "/backdrop/screen0/monitor0/workspace0/last-image"],
                capture_output=True, text=True, check=False,
            )
            if r2.returncode == 0 and r2.stdout.strip():
                return r2.stdout.strip()
        return ""

    @staticmethod
    def _gnome_env() -> Optional[dict]:
        """Build env dict with correct DBUS_SESSION_BUS_ADDRESS for gsettings.

        Tails boots as user 'amnesia' (uid 1000). The D-Bus session socket is
        typically at /run/user/1000/bus.  We also check the current user's uid.
        """
        env = dict(os.environ)
        if "DBUS_SESSION_BUS_ADDRESS" in env and env["DBUS_SESSION_BUS_ADDRESS"]:
            return env  # already set — good
        # Try to find the session bus for the current / expected user
        try:
            import glob as _glob
            # Tails uid is 1000 (amnesia), standard Linux too
            try:
                current_uid = os.getuid()
            except AttributeError:
                current_uid = 1000
            # Try current uid first, then common uids
            for uid in (current_uid, 1000, 1001):
                bus_path = Path(f"/run/user/{uid}/bus")
                if bus_path.exists():
                    env["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={bus_path}"
                    return env
            # Wildcard fallback
            buses = _glob.glob("/run/user/*/bus")
            if buses:
                env["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={buses[0]}"
                return env
        except Exception:
            pass
        return None

    def _restore_wallpaper(self, path: str) -> None:
        if _IS_WINDOWS:
            try:
                import ctypes
                ctypes.windll.user32.SystemParametersInfoW(20, 0, path, 3)
                self._log(f"Wallpaper restored: {path}")
            except Exception as e:
                self._log(f"Wallpaper restore failed: {e}")
        elif _IS_LINUX:
            uri = path if path.startswith("file://") else f"file://{path}"
            env = self._gnome_env()
            for key in ("picture-uri", "picture-uri-dark"):
                subprocess.run(
                    ["gsettings", "set", "org.gnome.desktop.background", key, uri],
                    capture_output=True, check=False,
                    **(dict(env=env) if env else {}),
                )
            self._log(f"Wallpaper restored: {uri}")

    # ------------------------------------------------------------------
    # Theme
    # ------------------------------------------------------------------

    def _capture_theme(self) -> str:
        if _IS_LINUX:
            env = self._gnome_env()
            if env:
                r = subprocess.run(
                    ["gsettings", "get", "org.gnome.desktop.interface", "color-scheme"],
                    capture_output=True, text=True, check=False, env=env,
                )
                if r.returncode == 0 and "dark" in r.stdout.lower():
                    return "dark"
                if r.returncode == 0:
                    return "light"
            # Fallback: dconf
            r2 = subprocess.run(
                ["dconf", "read", "/org/gnome/desktop/interface/color-scheme"],
                capture_output=True, text=True, check=False,
            )
            if r2.returncode == 0 and "dark" in r2.stdout.lower():
                return "dark"
            return "dark"  # Tails default
        if _IS_WINDOWS:
            try:
                import winreg
                with winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
                ) as key:
                    val, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
                    return "light" if val == 1 else "dark"
            except Exception:
                return "dark"
        return "dark"

    def _restore_theme(self, theme: str) -> None:
        if _IS_LINUX:
            scheme = "prefer-dark" if theme == "dark" else "default"
            env = self._gnome_env()
            subprocess.run(
                ["gsettings", "set", "org.gnome.desktop.interface", "color-scheme", scheme],
                capture_output=True, check=False,
                **(dict(env=env) if env else {}),
            )
            self._log(f"Theme restored: {scheme}")
        elif _IS_WINDOWS:
            try:
                import winreg
                val = 0 if theme == "dark" else 1
                with winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
                    0, winreg.KEY_SET_VALUE,
                ) as key:
                    winreg.SetValueEx(key, "AppsUseLightTheme", 0, winreg.REG_DWORD, val)
                    winreg.SetValueEx(key, "SystemUsesLightTheme", 0, winreg.REG_DWORD, val)
                self._log(f"Windows theme restored: {theme}")
            except Exception as e:
                self._log(f"Theme restore failed: {e}")

    # ------------------------------------------------------------------
    # Env vars
    # ------------------------------------------------------------------

    _ENV_CAPTURE_KEYS = [
        "PATH", "EDITOR", "VISUAL", "PAGER", "LANG", "LC_ALL", "TZ",
        "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
        "JAVA_HOME", "ANDROID_HOME", "GOPATH", "GOROOT",
        "NVM_DIR", "PYENV_ROOT", "CARGO_HOME", "RUSTUP_HOME",
    ]

    def _capture_env_vars(self) -> Dict[str, str]:
        return {k: os.environ[k] for k in self._ENV_CAPTURE_KEYS if k in os.environ}

    def _restore_env_vars(self, env_vars: Dict[str, str]) -> None:
        if _IS_WINDOWS:
            try:
                import winreg
                with winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER, "Environment", 0, winreg.KEY_SET_VALUE
                ) as key:
                    for k, v in env_vars.items():
                        if k.upper() == "PATH":
                            continue  # skip PATH — too dangerous to overwrite blindly
                        winreg.SetValueEx(key, k, 0, winreg.REG_EXPAND_SZ, v)
                self._log(f"Env vars restored: {', '.join(env_vars.keys())}")
            except Exception as e:
                self._log(f"Env vars restore failed: {e}")
        else:
            self._log("Env vars note: set these manually or via shell_rc on Linux.")

    # ------------------------------------------------------------------
    # Shell RC / git config
    # ------------------------------------------------------------------

    def _capture_shell_rc(self) -> str:
        for name in (".bashrc", ".zshrc", ".profile"):
            path = Path.home() / name
            if path.exists():
                try:
                    return path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    pass
        return ""

    def _restore_shell_rc(self, content: str) -> None:
        for name in (".bashrc", ".zshrc"):
            path = Path.home() / name
            if path.exists():
                try:
                    path.write_text(content, encoding="utf-8")
                    self._log(f"Shell RC restored: ~/{name}")
                    return
                except OSError as e:
                    self._log(f"Shell RC restore failed: {e}")

    def _capture_git_config(self) -> str:
        path = Path.home() / ".gitconfig"
        if path.exists():
            try:
                return path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                pass
        return ""

    def _restore_git_config(self, content: str) -> None:
        path = Path.home() / ".gitconfig"
        try:
            path.write_text(content, encoding="utf-8")
            self._log("Git config restored: ~/.gitconfig")
        except OSError as e:
            self._log(f"Git config restore failed: {e}")

    # ------------------------------------------------------------------
    # Registry (Windows only)
    # ------------------------------------------------------------------

    _REGISTRY_KEYS = [
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
        r"HKCU\Console",
    ]

    def _capture_registry(self) -> Dict[str, str]:
        exports: Dict[str, str] = {}
        tmp_dir = Path(tempfile.mkdtemp(prefix="shadowsync-reg-"))
        try:
            for key_path in self._REGISTRY_KEYS:
                safe = re.sub(r"[^A-Za-z0-9]+", "_", key_path)
                out_file = tmp_dir / f"{safe}.reg"
                r = subprocess.run(
                    ["reg", "export", key_path, str(out_file), "/y"],
                    capture_output=True, check=False,
                )
                if r.returncode == 0 and out_file.exists():
                    raw = out_file.read_bytes()
                    exports[key_path] = base64.b64encode(raw).decode("ascii")
                    self._log(f"Registry captured: {key_path}")
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)
        return exports

    def _restore_registry(self, exports: Dict[str, str]) -> None:
        tmp_dir = Path(tempfile.mkdtemp(prefix="shadowsync-reg-restore-"))
        try:
            for key_path, b64 in exports.items():
                safe = re.sub(r"[^A-Za-z0-9]+", "_", key_path)
                reg_file = tmp_dir / f"{safe}.reg"
                reg_file.write_bytes(base64.b64decode(b64))
                r = subprocess.run(
                    ["reg", "import", str(reg_file)],
                    capture_output=True, text=True, check=False,
                )
                if r.returncode == 0:
                    self._log(f"Registry restored: {key_path}")
                else:
                    self._log(f"Registry restore failed for {key_path}: {r.stderr.strip()}")
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    # ------------------------------------------------------------------
    # Installed apps
    # ------------------------------------------------------------------

    def _capture_installed_apps(self) -> List[str]:
        apps: List[str] = []
        if _IS_LINUX:
            # dpkg --get-selections (standard Debian/Tails)
            apps.extend(self._run_lines(["dpkg", "--get-selections"], prefix="dpkg"))
            # apt list --installed (better on modern Debian/Tails)
            if not apps and shutil.which("apt"):
                try:
                    r = subprocess.run(
                        ["apt", "list", "--installed"],
                        capture_output=True, text=True, check=False, timeout=30,
                        env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"},
                    )
                    if r.returncode == 0:
                        for line in r.stdout.splitlines():
                            if line and not line.startswith("Listing") and "/" in line:
                                pkg_name = line.split("/")[0].strip()
                                if pkg_name:
                                    apps.append(f"apt:{pkg_name}")
                except (FileNotFoundError, subprocess.TimeoutExpired):
                    pass
            if shutil.which("flatpak"):
                apps.extend(self._run_lines(["flatpak", "list", "--app", "--columns=name"], prefix="flatpak"))
            if shutil.which("snap"):
                apps.extend(self._run_lines(["snap", "list"], prefix="snap", skip_header=True))
        elif _IS_WINDOWS:
            # winget (if available)
            r = subprocess.run(
                ["winget", "list", "--accept-source-agreements"],
                capture_output=True, text=True, check=False, timeout=30,
            )
            if r.returncode == 0:
                for line in r.stdout.splitlines()[2:]:  # skip header
                    parts = line.split()
                    if parts:
                        apps.append(f"winget:{parts[0]}")
            # PowerShell installed packages (fast)
            r2 = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-Package | Select-Object -ExpandProperty Name"],
                capture_output=True, text=True, check=False, timeout=30,
            )
            if r2.returncode == 0:
                for line in r2.stdout.splitlines():
                    name = line.strip()
                    if name:
                        apps.append(f"pkg:{name}")
        unique = list(dict.fromkeys(apps))  # deduplicate preserving order
        self._log(f"Installed apps captured: {len(unique)} entries.")
        return unique

    def _run_lines(self, cmd: List[str], prefix: str = "", skip_header: bool = False) -> List[str]:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=20)
            if r.returncode != 0:
                return []
            lines = r.stdout.splitlines()
            if skip_header and lines:
                lines = lines[1:]
            tag = f"{prefix}:" if prefix else ""
            return [f"{tag}{l.strip()}" for l in lines if l.strip()]
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return []

    # ------------------------------------------------------------------
    # Shell aliases
    # ------------------------------------------------------------------

    def _capture_shell_aliases(self) -> str:
        """Extract alias lines from common shell RC files."""
        aliases: List[str] = []
        for name in (".bashrc", ".zshrc", ".bash_aliases"):
            path = Path.home() / name
            if not path.exists():
                continue
            try:
                for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                    stripped = line.strip()
                    if stripped.startswith("alias "):
                        aliases.append(stripped)
            except OSError:
                pass
        result = "\n".join(dict.fromkeys(aliases))  # deduplicated
        self._log(f"Shell aliases captured: {len(aliases)} entries.")
        return result

    def _log(self, msg: str) -> None:
        self.log.put(msg)


# ---------------------------------------------------------------------------
# Hydrate — data model
# ---------------------------------------------------------------------------

@dataclass
class HydrateConfig:
    """All personalisation settings stored in the encrypted hydrate vault."""
    dark_mode: bool = True
    # Ventoy mounts at /media/amnesia/Ventoy; Tails installs at /live/mount/medium
    # Use a neutral empty default — user sets this in the UI
    wallpaper_path: str = ""
    wifi_profiles: list = None  # list of {ssid, password} — simple plaintext fallback
    git_remote: str = ""
    git_branch: str = "main"
    git_name: str = "Tails User"
    git_email: str = ""
    git_token: str = ""
    # New fields
    git_host: str = "github"   # "github" | "gitlab" | "custom"
    auto_push_on_close: bool = False
    push_includes_os_state: bool = True

    def __post_init__(self) -> None:
        if self.wifi_profiles is None:
            self.wifi_profiles = []

    def to_dict(self) -> dict:
        return {
            "dark_mode": self.dark_mode,
            "wallpaper_path": self.wallpaper_path,
            "wifi_profiles": self.wifi_profiles,
            "git_remote": self.git_remote,
            "git_branch": self.git_branch,
            "git_name": self.git_name,
            "git_email": self.git_email,
            "git_token": self.git_token,
            "git_host": self.git_host,
            "auto_push_on_close": self.auto_push_on_close,
            "push_includes_os_state": self.push_includes_os_state,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "HydrateConfig":
        return cls(
            dark_mode=bool(data.get("dark_mode", True)),
            wallpaper_path=str(data.get("wallpaper_path", "/live/mount/medium/wallpaper.jpg")),
            wifi_profiles=list(data.get("wifi_profiles", [])),
            git_remote=str(data.get("git_remote", "")),
            git_branch=str(data.get("git_branch", "main")),
            git_name=str(data.get("git_name", "Tails User")),
            git_email=str(data.get("git_email", "")),
            git_token=str(data.get("git_token", "")),
            git_host=str(data.get("git_host", "github")),
            auto_push_on_close=bool(data.get("auto_push_on_close", False)),
            push_includes_os_state=bool(data.get("push_includes_os_state", True)),
        )

    def save(self, storage_root: Path, password: str) -> None:
        vault_path = hydrate_config_path(storage_root)
        staging = Path(tempfile.mkdtemp(prefix="shadowsync-hydrate-"))
        try:
            cfg_file = staging / "hydrate_config.json"
            cfg_file.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")
            PortableVault(vault_path).save_from(staging, password)
        finally:
            wipe_directory(staging)

    @classmethod
    def load(cls, storage_root: Path, password: str) -> "HydrateConfig":
        vault_path = hydrate_config_path(storage_root)
        if not vault_path.exists():
            return cls()
        staging = Path(tempfile.mkdtemp(prefix="shadowsync-hydrate-"))
        try:
            PortableVault(vault_path).restore_to(staging, password)
            cfg_file = staging / "hydrate_config.json"
            if not cfg_file.exists():
                return cls()
            data = json.loads(cfg_file.read_text(encoding="utf-8"))
            return cls.from_dict(data)
        finally:
            wipe_directory(staging)


# ---------------------------------------------------------------------------
# Hydrate — worker threads
# ---------------------------------------------------------------------------

class HydrateWorker:
    """Applies GNOME personalisation settings concurrently in a background thread."""

    def __init__(self, config: HydrateConfig, log: queue.Queue) -> None:
        self.config = config
        self.log = log

    def run(self) -> None:
        threads = []
        if self.config.dark_mode:
            threads.append(threading.Thread(target=self._apply_dark_mode, daemon=True))
        if self.config.wallpaper_path.strip():
            threads.append(threading.Thread(target=self._apply_wallpaper, daemon=True))
        if self.config.wifi_profiles:
            threads.append(threading.Thread(target=self._apply_wifi, daemon=True))

        if not threads:
            self._log("Hydrate: nothing to do — all hooks are disabled or empty.")
            return

        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        self._log("Hydrate: all hooks completed.")

    def _apply_dark_mode(self) -> None:
        """Apply dark mode via gsettings, injecting the correct DBUS env for Tails."""
        env = None
        if _IS_LINUX:
            # Build env with correct DBUS_SESSION_BUS_ADDRESS for Tails/GNOME
            e = dict(os.environ)
            if not e.get("DBUS_SESSION_BUS_ADDRESS"):
                import glob as _glob
                try:
                    uid = os.getuid()
                except AttributeError:
                    uid = 1000
                for candidate_uid in (uid, 1000, 1001):
                    bp = Path(f"/run/user/{candidate_uid}/bus")
                    if bp.exists():
                        e["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={bp}"
                        break
                else:
                    buses = _glob.glob("/run/user/*/bus")
                    if buses:
                        e["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={buses[0]}"
            env = e
        try:
            subprocess.run(
                ["gsettings", "set", "org.gnome.desktop.interface",
                 "color-scheme", "prefer-dark"],
                check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                **(dict(env=env) if env else {}),
            )
            self._log("Hydrate: dark mode applied.")
        except FileNotFoundError:
            self._log("Hydrate: gsettings not found — skipping dark mode.")
        except subprocess.CalledProcessError as exc:
            self._log(f"Hydrate: dark mode failed: {exc.stderr.strip()}")

    def _apply_wallpaper(self) -> None:
        """Apply wallpaper via gsettings, injecting DBUS env for Tails."""
        uri = self.config.wallpaper_path.strip()
        if not uri:
            self._log("Hydrate: wallpaper path not set — skipping.")
            return
        if not uri.startswith(("file://", "http://", "https://")):
            uri = "file://" + uri
        # Check file actually exists (Ventoy path may differ from Tails install path)
        if uri.startswith("file://"):
            local_path = uri[7:]
            if not Path(local_path).exists():
                self._log(f"Hydrate: wallpaper file not found at {local_path} — skipping.")
                return
        env = None
        if _IS_LINUX:
            e = dict(os.environ)
            if not e.get("DBUS_SESSION_BUS_ADDRESS"):
                import glob as _glob
                try:
                    uid = os.getuid()
                except AttributeError:
                    uid = 1000
                for candidate_uid in (uid, 1000, 1001):
                    bp = Path(f"/run/user/{candidate_uid}/bus")
                    if bp.exists():
                        e["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={bp}"
                        break
                else:
                    buses = _glob.glob("/run/user/*/bus")
                    if buses:
                        e["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={buses[0]}"
            env = e
        try:
            for key in ("picture-uri", "picture-uri-dark"):
                subprocess.run(
                    ["gsettings", "set", "org.gnome.desktop.background", key, uri],
                    check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                    **(dict(env=env) if env else {}),
                )
            self._log(f"Hydrate: wallpaper set → {uri}")
        except FileNotFoundError:
            self._log("Hydrate: gsettings not found — skipping wallpaper.")
        except subprocess.CalledProcessError as exc:
            self._log(f"Hydrate: wallpaper failed: {exc.stderr.strip()}")

    def _apply_wifi(self) -> None:
        """
        Hydrate WiFi for Tails/Linux.

        Strategy:
        1. If a full nmconnection blob is stored in the profile dict ('blob' key),
           write it to /etc/NetworkManager/system-connections/, reload NM, and
           activate the connection — so Tails users never re-type WiFi passwords.
        2. Otherwise fall back to nmcli connect with the stored plaintext password.
        3. Uses sudo/pkexec automatically when not running as root.
        """
        if not _IS_LINUX:
            self._log("Hydrate: WiFi hydration is Linux/Tails only.")
            return

        nm_dir = Path("/etc/NetworkManager/system-connections")
        # Determine if we need sudo
        is_root = False
        try:
            is_root = os.getuid() == 0
        except AttributeError:
            pass
        sudo: List[str] = []
        if not is_root:
            if shutil.which("sudo"):
                sudo = ["sudo", "-n"]
            elif shutil.which("pkexec"):
                sudo = ["pkexec"]

        written_ssids: List[str] = []
        failed_ssids: List[tuple] = []  # (ssid, password)

        for idx, profile in enumerate(self.config.wifi_profiles, start=1):
            ssid = str(profile.get("ssid", "")).strip()
            pwd = str(profile.get("password", "")).strip()
            blob = str(profile.get("blob", "")).strip()
            if not ssid:
                continue
            self._log(f"Hydrate: applying Wi-Fi profile {idx} ({ssid})…")

            # ── Path A: write full nmconnection blob (preferred, works without password prompt) ──
            if blob:
                raw = base64.b64decode(blob)
                conn_file = nm_dir / f"{ssid}.nmconnection"
                blob_written = False

                # Try direct write first
                try:
                    nm_dir.mkdir(parents=True, exist_ok=True)
                    conn_file.write_bytes(raw)
                    conn_file.chmod(0o600)
                    blob_written = True
                    self._log(f"Hydrate: wrote nmconnection for {ssid}.")
                except (OSError, PermissionError):
                    # Try with sudo
                    if sudo:
                        import tempfile as _tmpmod
                        try:
                            with _tmpmod.NamedTemporaryFile(delete=False, suffix=".nmconnection") as tf:
                                tf.write(raw)
                                tf_path = tf.name
                            r_cp = subprocess.run(
                                sudo + ["cp", tf_path, str(conn_file)],
                                capture_output=True, check=False,
                            )
                            subprocess.run(
                                sudo + ["chmod", "600", str(conn_file)],
                                capture_output=True, check=False,
                            )
                            subprocess.run(
                                sudo + ["chown", "root:root", str(conn_file)],
                                capture_output=True, check=False,
                            )
                            os.unlink(tf_path)
                            if r_cp.returncode == 0:
                                blob_written = True
                                self._log(f"Hydrate: wrote nmconnection (sudo) for {ssid}.")
                            else:
                                self._log(f"Hydrate: sudo cp failed for {ssid} — will try nmcli connect.")
                        except Exception as e:
                            self._log(f"Hydrate: sudo blob write error for {ssid}: {e}")
                    else:
                        self._log(f"Hydrate: cannot write nmconnection for {ssid} (not root, no sudo). Falling back to nmcli connect.")

                if blob_written:
                    written_ssids.append(ssid)
                    continue  # Will be activated after reload
                # If blob write failed, fall through to nmcli connect
                failed_ssids.append((ssid, pwd))
            else:
                failed_ssids.append((ssid, pwd))

        # ── Reload NM after writing blobs ──
        if written_ssids:
            reload_cmd = (sudo + ["nmcli", "connection", "reload"]) if sudo else ["nmcli", "connection", "reload"]
            r = subprocess.run(reload_cmd, capture_output=True, text=True, check=False)
            if r.returncode == 0:
                self._log("Hydrate: NetworkManager reloaded with new profiles.")
            else:
                self._log(f"Hydrate: nmcli reload: {r.stderr.strip()}")

            # Activate each written profile
            for ssid in written_ssids:
                up_result = subprocess.run(
                    ["nmcli", "connection", "up", ssid],
                    capture_output=True, text=True, check=False, timeout=25,
                )
                if up_result.returncode == 0:
                    self._log(f"Hydrate: Wi-Fi activated → {ssid}")
                else:
                    self._log(f"Hydrate: activation failed for {ssid}: {up_result.stderr.strip()}")
                    # Try connecting to the AP directly as last resort
                    # Find stored password for this ssid
                    for p in self.config.wifi_profiles:
                        if str(p.get("ssid", "")).strip() == ssid and str(p.get("password", "")).strip():
                            failed_ssids.append((ssid, str(p.get("password", "")).strip()))
                            break

        # ── Path B: nmcli connect for profiles without a blob ──
        for ssid, pwd in failed_ssids:
            try:
                cmd = ["nmcli", "dev", "wifi", "connect", ssid]
                if pwd:
                    cmd += ["password", pwd]
                result = subprocess.run(
                    cmd, check=False,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                    timeout=25,
                )
                if result.returncode == 0:
                    self._log(f"Hydrate: Wi-Fi connected to {ssid}.")
                else:
                    self._log(f"Hydrate: connect failed for {ssid}: {result.stderr.strip()}")
            except FileNotFoundError:
                self._log("Hydrate: nmcli not found — cannot connect to Wi-Fi.")
                break
            except subprocess.TimeoutExpired:
                self._log(f"Hydrate: Wi-Fi connect timed out for {ssid}.")

    def _log(self, message: str) -> None:
        self.log.put(message)


# ---------------------------------------------------------------------------
# Git Push worker
# ---------------------------------------------------------------------------

class GitPushWorker:
    """
    Commits the entire ShadowSync storage folder to a remote Git repo.

    Security guarantees:
    - The PAT is injected into the remote URL at runtime only.
    - It is never written to .git/config or any file.
    - push is to a timestamped branch, never --force, so historical backups survive.
    """

    def __init__(
        self,
        storage_root: Path,
        config: HydrateConfig,
        log: queue.Queue,
        summary: str = "",
    ) -> None:
        self.storage_root = storage_root.expanduser().resolve()
        self.config = config
        self.log = log
        self.summary = summary

    def run(self) -> None:
        cfg = self.config
        if not cfg.git_remote.strip():
            self._log("Git Push: no remote URL configured — skipped.")
            return

        branch = f"backup-{time.strftime('%Y%m%d-%H%M%S')}"
        self._log(f"Git Push: starting → branch '{branch}'")

        try:
            self._write_gitignore()
            self._git("init")
            self._git("config", "user.name", cfg.git_name or "ShadowSync")
            self._git("config", "user.email", cfg.git_email or "shadowsync@local")
            self._set_remote(cfg.git_remote, cfg.git_token)
            self._git("checkout", "-B", branch)
            self._git("add", "-A")
            commit_msg = (
                f"ShadowSync auto-push — {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}"
                + (f" | {self.summary}" if self.summary else "")
            )
            self._git("commit", "--allow-empty", "-m", commit_msg)
            self._git_push(branch)
            self._log(f"Git Push: vault pushed successfully to branch '{branch}'.")
        except ShadowSyncError as exc:
            self._log(f"Git Push error: {exc}")

    def _write_gitignore(self) -> None:
        gitignore = self.storage_root / ".gitignore"
        content = "*.tmp\n__pycache__/\n*.pyc\n.DS_Store\n"
        try:
            gitignore.write_text(content, encoding="utf-8")
        except OSError:
            pass

    def _set_remote(self, remote_url: str, token: str) -> None:
        if token:
            if remote_url.startswith("https://"):
                authed_url = "https://" + token + "@" + remote_url[len("https://"):]
            else:
                authed_url = remote_url
        else:
            authed_url = remote_url

        result = subprocess.run(
            ["git", "-C", str(self.storage_root), "remote", "get-url", "origin"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
        )
        if result.returncode == 0:
            subprocess.run(
                ["git", "-C", str(self.storage_root), "remote", "set-url", "origin", authed_url],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
            )
        else:
            subprocess.run(
                ["git", "-C", str(self.storage_root), "remote", "add", "origin", authed_url],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
            )

    def _git(self, *args: str) -> None:
        cmd = ["git", "-C", str(self.storage_root)] + list(args)
        result = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
        )
        if result.returncode != 0:
            raise ShadowSyncError(
                f"git {' '.join(args)} failed: {(result.stderr or result.stdout).strip()}"
            )

    def _git_push(self, branch: str) -> None:
        cmd = ["git", "-C", str(self.storage_root), "push", "origin", branch]
        result = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
        )
        if result.returncode != 0:
            raise ShadowSyncError(
                f"git push failed: {(result.stderr or result.stdout).strip()}"
            )

    def _log(self, message: str) -> None:
        self.log.put(message)


# ---------------------------------------------------------------------------
# Git History — query commit log and restore individual vaults
# ---------------------------------------------------------------------------

@dataclass
class GitCommitInfo:
    branch: str
    commit_hash: str
    subject: str
    author_date: str
    has_apps: bool = False
    has_os: bool = False
    app_names: List[str] = field(default_factory=list)


class GitHistoryWorker:
    """
    Reads the local git history of the ShadowSync storage root.
    Each auto-push creates a timestamped branch, so we list branches
    sorted by date to produce a backup timeline.
    """

    def __init__(self, storage_root: Path, log: queue.Queue) -> None:
        self.storage_root = storage_root.expanduser().resolve()
        self.log = log

    def fetch_commits(self, max_entries: int = 50) -> List[GitCommitInfo]:
        """Return recent backup commits ordered newest-first."""
        commits: List[GitCommitInfo] = []
        if not (self.storage_root / ".git").exists():
            return commits

        # List remote-tracking branches that look like our backup branches
        r = subprocess.run(
            ["git", "-C", str(self.storage_root),
             "branch", "-a", "--sort=-committerdate",
             "--format=%(refname:short)|||%(objectname:short)|||%(subject)|||%(committerdate:iso)"],
            capture_output=True, text=True, check=False,
        )
        if r.returncode != 0:
            self._log(f"Git history: {r.stderr.strip() or 'git branch failed'}")
            return commits

        for line in r.stdout.splitlines():
            parts = line.split("|||", 3)
            if len(parts) < 4:
                continue
            branch, commit_hash, subject, date = parts
            branch = branch.strip()
            # Only show backup branches and main/master
            if not ("backup-" in branch or branch in ("main", "master", "origin/main", "origin/master")):
                continue
            # Inspect tree at that commit for apps and os_settings
            tree_r = subprocess.run(
                ["git", "-C", str(self.storage_root),
                 "ls-tree", "--name-only", commit_hash],
                capture_output=True, text=True, check=False,
            )
            top_level = set(tree_r.stdout.splitlines())
            has_os = "os_settings" in top_level
            # List apps
            app_names: List[str] = []
            if "apps" in top_level:
                apps_r = subprocess.run(
                    ["git", "-C", str(self.storage_root),
                     "ls-tree", "--name-only", f"{commit_hash}:apps"],
                    capture_output=True, text=True, check=False,
                )
                app_names = [n.strip() for n in apps_r.stdout.splitlines() if n.strip()]

            commits.append(GitCommitInfo(
                branch=branch,
                commit_hash=commit_hash.strip(),
                subject=subject.strip(),
                author_date=date.strip(),
                has_apps=bool(app_names),
                has_os=has_os,
                app_names=app_names,
            ))
            if len(commits) >= max_entries:
                break

        return commits

    def _log(self, msg: str) -> None:
        self.log.put(msg)


class GitRestoreWorker:
    """
    Restores a specific app vault or the OS state vault from a historical
    Git commit.  The ssvault file is checked out from the commit into a
    temp location, then the caller decrypts it normally.
    """

    def __init__(self, storage_root: Path, log: queue.Queue) -> None:
        self.storage_root = storage_root.expanduser().resolve()
        self.log = log

    def restore_app_vault(
        self,
        commit_hash: str,
        app_name: str,
        profile_name: str,
        destination: Path,
        password: str,
    ) -> bool:
        """Checkout profile.ssvault from commit and decrypt it to destination."""
        git_path = f"apps/{sanitize_app_name(app_name)}/profiles/{sanitize_app_name(profile_name)}/profile.ssvault"
        return self._restore_ssvault(commit_hash, git_path, destination, password)

    def restore_os_vault(
        self,
        commit_hash: str,
        storage_root: Path,
        password: str,
    ) -> Optional[OSSettings]:
        """Checkout os_state.ssvault from commit, decrypt and return OSSettings."""
        git_path = "os_settings/os_state.ssvault"
        tmp_dir = Path(tempfile.mkdtemp(prefix="shadowsync-os-restore-"))
        tmp_vault = tmp_dir / "os_state.ssvault"
        try:
            if not self._checkout_file(commit_hash, git_path, tmp_vault):
                return None
            raw = PortableVault(tmp_vault).load_bytes(password)
            data = json.loads(raw.decode("utf-8"))
            self._log(f"OS settings restored from commit {commit_hash[:8]}.")
            return OSSettings.from_dict(data)
        except Exception as exc:
            self._log(f"OS restore error: {exc}")
            return None
        finally:
            wipe_directory(tmp_dir)

    def _restore_ssvault(self, commit_hash: str, git_path: str, destination: Path, password: str) -> bool:
        tmp_dir = Path(tempfile.mkdtemp(prefix="shadowsync-git-restore-"))
        tmp_vault = tmp_dir / "profile.ssvault"
        try:
            if not self._checkout_file(commit_hash, git_path, tmp_vault):
                return False
            PortableVault(tmp_vault).restore_to(destination, password)
            self._log(f"Vault from commit {commit_hash[:8]} restored to: {destination}")
            return True
        except ShadowSyncError as exc:
            self._log(f"Restore failed: {exc}")
            return False
        finally:
            wipe_directory(tmp_dir)

    def _checkout_file(self, commit_hash: str, git_path: str, out_file: Path) -> bool:
        """Run git show to extract a single file from a commit."""
        out_file.parent.mkdir(parents=True, exist_ok=True)
        r = subprocess.run(
            ["git", "-C", str(self.storage_root),
             "show", f"{commit_hash}:{git_path}"],
            capture_output=True, check=False,
        )
        if r.returncode != 0:
            self._log(f"git show {commit_hash[:8]}:{git_path} failed: {r.stderr.decode(errors='replace').strip()}")
            return False
        out_file.write_bytes(r.stdout)
        return True

    def _log(self, msg: str) -> None:
        self.log.put(msg)


# ---------------------------------------------------------------------------
# Shutdown hook — auto-push on close / shutdown
# ---------------------------------------------------------------------------

class ShutdownHook:
    """
    Registers atexit + platform signals so that when the process exits
    (app close, Ctrl+C, SIGTERM, Windows logoff), a Git push is attempted.
    """

    def __init__(self) -> None:
        self._callback = None
        self._registered = False

    def register(self, callback) -> None:
        """Set the callback that will be called on shutdown. Call once."""
        self._callback = callback
        if self._registered:
            return
        self._registered = True
        atexit.register(self._fire)
        # POSIX signals
        for sig in (signal.SIGTERM,):
            try:
                signal.signal(sig, self._signal_handler)
            except (OSError, ValueError):
                pass
        # Windows console handler
        if _HAS_WIN32:
            try:
                win32api.SetConsoleCtrlHandler(self._win32_handler, True)
            except Exception:
                pass

    def unregister(self) -> None:
        """Clear the callback (e.g., user turned off auto-push)."""
        self._callback = None

    def _fire(self) -> None:
        if self._callback:
            try:
                self._callback()
            except Exception:
                pass

    def _signal_handler(self, signum, frame) -> None:
        self._fire()
        sys.exit(0)

    def _win32_handler(self, event_type) -> bool:
        # CTRL_CLOSE_EVENT=2, CTRL_LOGOFF_EVENT=5, CTRL_SHUTDOWN_EVENT=6
        if event_type in (2, 5, 6):
            self._fire()
        return False


_SHUTDOWN_HOOK = ShutdownHook()


# ---------------------------------------------------------------------------
# RunOptions / ShadowSyncWorker
# ---------------------------------------------------------------------------

@dataclass
class RunOptions:
    storage_root: Path
    app_name: str
    profile_name: str
    profile_dir: Path
    executable: Path
    password: str
    mode: str
    wipe_after: bool
    sandbox_app: bool


def build_bwrap_command(executable: Path, profile_dir: Path) -> Optional[list[str]]:
    if platform.system().lower() != "linux":
        return None
    bwrap = shutil.which("bwrap")
    if not bwrap:
        return None
    executable = executable.expanduser().resolve()
    profile_dir = profile_dir.expanduser().resolve()
    profile_dir.mkdir(parents=True, exist_ok=True)
    home = Path.home().resolve()
    profile_dirs = sandbox_parent_dirs(profile_dir, home)
    command = [
        bwrap,
        "--die-with-parent", "--unshare-all", "--share-net",
        "--proc", "/proc", "--dev", "/dev",
        "--tmpfs", "/tmp",
        "--ro-bind-try", "/tmp/.X11-unix", "/tmp/.X11-unix",
        "--ro-bind-try", "/tmp/.ICE-unix", "/tmp/.ICE-unix",
        "--tmpfs", str(Path.home()),
        "--ro-bind", "/usr", "/usr",
        "--ro-bind", "/etc", "/etc",
        "--ro-bind", "/lib", "/lib",
        "--ro-bind", "/lib64", "/lib64",
        "--ro-bind", "/bin", "/bin",
        "--ro-bind", str(executable.parent), "/app",
        "--chdir", "/app",
    ]
    for directory in profile_dirs:
        command.extend(["--dir", str(directory)])
    command.extend(["--bind", str(profile_dir), str(profile_dir)])
    command.extend(session_socket_binds())
    command.extend(xauthority_bind())
    command.extend(sandbox_env_args())
    command.append(f"/app/{executable.name}")
    return command


def sandbox_parent_dirs(target: Path, stop_at: Path) -> list[Path]:
    target = target.resolve()
    stop_at = stop_at.resolve()
    directories = []
    current = target.parent
    while current != stop_at and stop_at in current.parents:
        directories.append(current)
        current = current.parent
    directories.reverse()
    return directories


def session_socket_binds() -> list[str]:
    args: list[str] = []
    runtime_dir = os.environ.get("XDG_RUNTIME_DIR")
    if runtime_dir:
        runtime_path = Path(runtime_dir)
        args.extend(["--dir", "/run", "--dir", "/run/user", "--dir", str(runtime_path)])
        for name in ("bus", "pulse", "pipewire-0", "wayland-0", "wayland-1"):
            path = runtime_path / name
            if path.exists():
                args.extend(["--bind", str(path), str(path)])
    return args


def xauthority_bind() -> list[str]:
    xauthority = os.environ.get("XAUTHORITY")
    if not xauthority:
        return []
    path = Path(xauthority).expanduser()
    if not path.exists():
        return []
    return ["--ro-bind", str(path), str(path)]


def sandbox_env_args() -> list[str]:
    args: list[str] = []
    for name in ("DISPLAY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS",
                 "PULSE_SERVER", "PIPEWIRE_REMOTE", "XAUTHORITY"):
        value = os.environ.get(name)
        if value:
            args.extend(["--setenv", name, value])
    return args


class ShadowSyncWorker:
    def __init__(self, options: RunOptions, log: queue.Queue[object]) -> None:
        self.options = options
        self.log = log
        self.stop_event = threading.Event()
        self.panic_event = threading.Event()
        self.save_lock = threading.Lock()
        self.process: Optional[subprocess.Popen] = None
        self.last_fingerprint = ""

    def run(self) -> None:
        if self.options.mode == MODE_FUSE:
            self._run_fuse()
        else:
            self._run_diy()

    def _run_diy(self) -> None:
        paths = app_storage_paths(self.options.storage_root, self.options.app_name, self.options.profile_name)
        vault = PortableVault(paths["portable_vault"])
        profile = self.options.profile_dir.expanduser().resolve()
        executable = self.options.executable.expanduser().resolve()
        if not executable.exists():
            raise ShadowSyncError(f"Application file not found: {executable}")

        self._migrate_fuse_to_diy_if_needed(paths)
        self._log("Unlocking vault...")
        if vault.exists():
            self._busy(True, "Decrypting portable vault...")
            try:
                vault.restore_to(profile, self.options.password)
            finally:
                self._busy(False)
            self._log("Vault restored into the profile folder.")
        else:
            profile.mkdir(parents=True, exist_ok=True)
            self._log("No vault found. A new vault will be created when you save.")

        self.last_fingerprint = fingerprint_tree(profile)
        heartbeat = threading.Thread(target=self._heartbeat_loop, daemon=True)
        heartbeat.start()
        self._log("DIY heartbeat enabled. Changes are saved every 15 minutes when detected.")
        self.process = self._launch(executable)
        self._log("Application launched. Close it when you are done.")
        self.process.wait()
        self.stop_event.set()
        heartbeat.join(timeout=2)
        if self.panic_event.is_set():
            self._log("Panic cleanup completed. Final vault save skipped.")
            return
        self.save_now()
        if self.options.wipe_after:
            wipe_directory(profile)
            self._log("RAM-side profile folder wiped.")
        self._log("Done. Your encrypted vault is up to date.")

    def save_now(self) -> None:
        if self.options.mode == MODE_FUSE:
            self._flush_fuse()
            return
        if self.panic_event.is_set():
            return
        with self.save_lock:
            paths = app_storage_paths(self.options.storage_root, self.options.app_name, self.options.profile_name)
            vault = PortableVault(paths["portable_vault"])
            self._busy(True, "Encrypting portable vault...")
            try:
                vault.save_from(self.options.profile_dir.expanduser().resolve(), self.options.password)
                self.last_fingerprint = fingerprint_tree(self.options.profile_dir.expanduser().resolve())
            finally:
                self._busy(False)
            self._log(f"Encrypted vault saved: {vault.path}")

    def stop(self) -> None:
        self.stop_event.set()
        if self.process and self.process.poll() is None:
            self._log("Closing launched application...")
            self.process.terminate()
            try:
                self.process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                self.process.kill()

    def panic(self) -> None:
        self._log("PANIC triggered. Killing app and wiping active profile.")
        self.panic_event.set()
        self.stop_event.set()
        if self.process and self.process.poll() is None:
            self.process.kill()
        bridge = getattr(self, "_fuse_bridge", None)
        if bridge:
            try:
                bridge.unmount()
            except ShadowSyncError as exc:
                self._log(f"Panic unmount warning: {exc}")
        wipe_directory(self.options.profile_dir.expanduser().resolve())

    def _run_fuse(self) -> None:
        paths = app_storage_paths(self.options.storage_root, self.options.app_name, self.options.profile_name)
        profile = self.options.profile_dir.expanduser().resolve()
        executable = self.options.executable.expanduser().resolve()
        if not executable.exists():
            raise ShadowSyncError(f"Application file not found: {executable}")

        bridge = GocryptfsBridge(paths["fuse_cipher_dir"], profile, self.options.password)
        self._fuse_bridge = bridge
        try:
            self._migrate_diy_to_fuse_if_needed(paths, profile)
            self._log("Mounting encrypted FUSE bridge...")
            bridge.mount()
            self._log("FUSE bridge mounted. App writes are encrypted on the fly.")
            self.process = self._launch(executable)
            self._log("Application launched. Close it when you are done.")
            self.process.wait()
            if self.panic_event.is_set():
                self._log("Panic cleanup completed.")
                return
            bridge.flush()
            self._log("Encrypted FUSE data flushed to storage.")
        finally:
            self.stop_event.set()
            if self.process and self.process.poll() is None:
                self.stop()
            try:
                bridge.unmount()
                self._log("FUSE bridge unmounted.")
            except ShadowSyncError as exc:
                if not self.panic_event.is_set():
                    raise
                self._log(f"FUSE unmount warning: {exc}")
            if self.options.wipe_after:
                wipe_directory(profile)
                self._log("Empty mount folder cleaned up.")
            self._log("Done. On-the-fly encrypted storage is closed.")

    def _flush_fuse(self) -> None:
        bridge = getattr(self, "_fuse_bridge", None)
        if bridge:
            bridge.flush()
            self._log("FUSE writes flushed to encrypted storage.")

    def _heartbeat_loop(self) -> None:
        while not self.stop_event.wait(HEARTBEAT_SECONDS):
            if self.panic_event.is_set():
                return
            profile = self.options.profile_dir.expanduser().resolve()
            current = fingerprint_tree(profile)
            if current != self.last_fingerprint:
                self._log("Heartbeat detected changes. Saving portable vault...")
                self.save_now()
            else:
                self._log("Heartbeat checked profile. No changes found.")
            self.log.put(("heartbeat", time.time()))

    def _migrate_diy_to_fuse_if_needed(self, paths: Dict[str, Path], profile: Path) -> None:
        portable_vault = paths["portable_vault"]
        fuse_conf = paths["fuse_cipher_dir"] / "gocryptfs.conf"
        if fuse_conf.exists() or not portable_vault.exists():
            return
        self._log("Portable vault found. Migrating app data into FUSE storage...")
        restored = Path(tempfile.mkdtemp(prefix="shadowsync-restore-"))
        mountpoint = Path(tempfile.mkdtemp(prefix="shadowsync-mount-"))
        bridge = GocryptfsBridge(paths["fuse_cipher_dir"], mountpoint, self.options.password)
        try:
            self._busy(True, "Decrypting portable vault for FUSE migration...")
            try:
                PortableVault(portable_vault).restore_to(restored, self.options.password)
            finally:
                self._busy(False)
            bridge.mount()
            copy_tree_contents(restored, mountpoint)
            bridge.flush()
            self._log("Migration complete. DIY vault kept as a backup.")
        finally:
            try:
                bridge.unmount()
            except ShadowSyncError:
                pass
            wipe_directory(restored)
            wipe_directory(mountpoint)
            wipe_directory(profile)

    def _migrate_fuse_to_diy_if_needed(self, paths: Dict[str, Path]) -> None:
        portable_vault = paths["portable_vault"]
        fuse_conf = paths["fuse_cipher_dir"] / "gocryptfs.conf"
        if portable_vault.exists() or not fuse_conf.exists():
            return
        if platform.system().lower() == "windows":
            self._log("FUSE storage exists, but Windows cannot read gocryptfs. Using portable vault if present.")
            return
        self._log("FUSE storage found. Migrating app data into the portable vault...")
        staging = Path(tempfile.mkdtemp(prefix="shadowsync-migrate-"))
        bridge = GocryptfsBridge(paths["fuse_cipher_dir"], staging, self.options.password)
        try:
            try:
                bridge.mount()
            except ShadowSyncError as exc:
                self._log(f"FUSE-to-DIY migration skipped: {exc}")
                return
            self._busy(True, "Encrypting portable vault from FUSE storage...")
            try:
                try:
                    PortableVault(portable_vault).save_from(staging, self.options.password)
                finally:
                    self._busy(False)
            except ShadowSyncError as exc:
                self._log(f"FUSE-to-DIY migration failed: {exc}")
                return
            self._log("Migration complete. FUSE storage kept as a backup.")
        finally:
            try:
                bridge.unmount()
            except ShadowSyncError:
                pass
            wipe_directory(staging)

    def _launch(self, executable: Path) -> subprocess.Popen:
        """
        Launch the executable.

        Ventoy/FAT/exFAT filesystems are typically mounted `noexec`, which means
        chmod +x works locally but the kernel still refuses to execute the file.
        If the file lives on a noexec filesystem, we copy it to /tmp first and
        run from there.  This is safe because we've already verified its SHA-256.
        """
        if platform.system().lower() != "windows":
            try:
                mode = executable.stat().st_mode
                executable.chmod(mode | stat.S_IXUSR)
            except (OSError, PermissionError):
                pass  # noexec fs — handled below

            # Check if the file is on a noexec filesystem by trying os.access
            if not os.access(str(executable), os.X_OK):
                self._log(f"Executable is on a noexec filesystem (Ventoy/FAT). Copying to /tmp…")
                import tempfile as _tmp
                tmp_dir = Path(_tmp.mkdtemp(prefix="shadowsync-exec-"))
                tmp_exe = tmp_dir / executable.name
                shutil.copy2(str(executable), str(tmp_exe))
                try:
                    tmp_exe.chmod(0o755)
                except OSError:
                    pass
                # Register cleanup
                import atexit as _atexit
                _atexit.register(shutil.rmtree, str(tmp_dir), True)
                executable = tmp_exe
                self._log(f"Running from /tmp copy: {executable}")

        if self.options.sandbox_app:
            command = build_bwrap_command(executable, self.options.profile_dir.expanduser().resolve())
            if command:
                self._log("Launching application inside Bubblewrap sandbox.")
                return subprocess.Popen(command)
            self._log("Bubblewrap not available. Launching without sandbox.")
        return subprocess.Popen([str(executable)])

    def _log(self, message: str) -> None:
        self.log.put(message)

    def _busy(self, active: bool, message: str = "") -> None:
        self.log.put(("busy", active, message))


# ---------------------------------------------------------------------------
# Main GUI
# ---------------------------------------------------------------------------

class ShadowSyncApp(ctk.CTk):
    # ── Palette ──────────────────────────────────────────────────────────────
    C = {
        "bg":        "#0f111a",
        "sidebar":   "#141824",
        "panel":     "#0f111a",
        "card":      "#1a2035",
        "accent":    "#00c8ff",
        "accent2":   "#0097c4",
        "purple":    "#7c3aed",
        "purple2":   "#6d28d9",
        "green":     "#22c55e",
        "green2":    "#16a34a",
        "danger":    "#e03131",
        "danger2":   "#c92a2a",
        "ghost":     "#212942",
        "ghost2":    "#2a3454",
        "text":      "#e2eaf4",
        "muted":     "#7a8ea3",
        "label":     "#8aabcc",
        "run_green": "#22c55e",
        "lock_blue": "#3b82f6",
        "input_bg":  "#141824",
        "log_bg":    "#060c18",
        "log_ts":    "#3a5270",
        "log_ok":    "#22c55e",
        "log_err":   "#f87171",
        "log_warn":  "#fbbf24",
        "log_info":  "#93c5fd",
    }

    def __init__(self) -> None:
        super().__init__()
        self.title("ShadowSync v2.0")
        self.geometry("1200x880")
        self.minsize(960, 760)
        self.configure(fg_color=self.C["bg"])

        self.presets = default_profile_paths()
        self.log_queue: queue.Queue[object] = queue.Queue()
        self.worker: Optional[ShadowSyncWorker] = None
        self.worker_thread: Optional[threading.Thread] = None
        self.approved_executable_path = ""
        self.approved_storage_root = ""
        self.sandbox_next_launch = False
        self._hydrate_config: Optional[HydrateConfig] = None
        self._os_settings: Optional[OSSettings] = None
        self._pw_visible = False
        self._files_view_mode = "list"
        self._files_manifest: list[dict] = []
        self._files_view_frame: Optional[ctk.CTkFrame] = None
        self._files_status_label: Optional[ctk.CTkLabel] = None
        self._files_empty_label: Optional[ctk.CTkLabel] = None
        self._stored_apps_frame: Optional[ctk.CTkFrame] = None
        self._os_tab_summary_frame: Optional[ctk.CTkFrame] = None
        self._os_captured_label: Optional[ctk.CTkLabel] = None
        # WiFi profile rows for OS tab (dynamic)
        self._os_wifi_rows: List[dict] = []
        self._os_wifi_container: Optional[ctk.CTkScrollableFrame] = None

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._build_sidebar()
        self._build_main_panel()

        self.after(150, self._drain_log)
        self.after(500, self._start_storage_scan)
        self.after(900, self._start_appimage_scan)
        self.bind_all("<Control-Shift-P>", lambda _event: self._panic())
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ─────────────────────────────────────────────────────────────────────────
    # Sidebar
    # ─────────────────────────────────────────────────────────────────────────

    def _build_sidebar(self) -> None:
        C = self.C
        sidebar = ctk.CTkFrame(self, fg_color=C["sidebar"], width=280, corner_radius=0)
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.grid_columnconfigure(0, weight=1)

        logo_f = ctk.CTkFrame(sidebar, fg_color="transparent")
        logo_f.grid(row=0, column=0, pady=(32, 20), padx=20, sticky="ew")
        ctk.CTkLabel(logo_f, text="🔐", font=("Segoe UI", 28), text_color=C["accent"]).pack(side="left", padx=(0, 10))
        text_f = ctk.CTkFrame(logo_f, fg_color="transparent")
        text_f.pack(side="left", fill="x")
        ctk.CTkLabel(text_f, text="ShadowSync", font=("Segoe UI", 18, "bold"), text_color=C["accent"], anchor="w").pack(fill="x")
        ctk.CTkLabel(text_f, text="Zero-Trust Persistence v2", font=("Segoe UI", 10), text_color=C["muted"], anchor="w").pack(fill="x")

        ctk.CTkFrame(sidebar, fg_color=C["ghost"], height=2).grid(row=1, column=0, sticky="ew", padx=20, pady=10)

        self.status_frame = ctk.CTkFrame(sidebar, fg_color=C["ghost"], corner_radius=8)
        self.status_frame.grid(row=3, column=0, sticky="ew", padx=20, pady=10)
        self._status_dot = ctk.CTkLabel(self.status_frame, text="●", font=("Segoe UI", 16), text_color=C["lock_blue"])
        self._status_dot.pack(side="left", padx=(15, 10), pady=12)
        self.state_label = ctk.CTkLabel(self.status_frame, text="Locked", font=("Segoe UI", 13, "bold"), text_color=C["lock_blue"])
        self.state_label.pack(side="left", pady=12)

        self.heartbeat_dot = ctk.CTkLabel(sidebar, text="● Heartbeat idle", font=("Segoe UI", 11), text_color=C["muted"], anchor="w")
        self.heartbeat_dot.grid(row=4, column=0, sticky="ew", padx=28, pady=(0, 10))

        # Drive info
        self._drive_label = ctk.CTkLabel(sidebar, text="💾 Drive: —", font=("Segoe UI", 11), text_color=C["muted"], anchor="w")
        self._drive_label.grid(row=5, column=0, sticky="ew", padx=28, pady=(0, 10))

        panic_btn = ctk.CTkButton(sidebar, text="⚠️ PANIC WIPE", fg_color=C["danger"], hover_color=C["danger2"],
                                  font=("Segoe UI", 12, "bold"), corner_radius=6, command=self._panic)
        panic_btn.grid(row=6, column=0, sticky="ew", padx=20, pady=(10, 0))

    # ─────────────────────────────────────────────────────────────────────────
    # Main panel / tabs
    # ─────────────────────────────────────────────────────────────────────────

    def _build_main_panel(self) -> None:
        C = self.C
        self.tabview = ctk.CTkTabview(
            self, fg_color=C["panel"],
            segmented_button_fg_color=C["sidebar"],
            segmented_button_selected_color=C["accent"],
            segmented_button_selected_hover_color=C["accent2"],
            text_color=C["text"], corner_radius=10,
        )
        self.tabview.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)

        self.tabview.add("🔒 Vault")
        self.tabview.add("📁 Files")
        self.tabview.add("🖥 OS State")
        self.tabview.add("⚡ Hydrate")
        self.tabview.add("📜 History")

        self._build_vault_tab(self.tabview.tab("🔒 Vault"))
        self._build_files_tab(self.tabview.tab("📁 Files"))
        self._build_os_tab(self.tabview.tab("🖥 OS State"))
        self._build_hydrate_tab(self.tabview.tab("⚡ Hydrate"))
        self._build_history_tab(self.tabview.tab("📜 History"))

    # ─────────────────────────────────────────────────────────────────────────
    # Vault Tab
    # ─────────────────────────────────────────────────────────────────────────

    def _build_vault_tab(self, parent) -> None:
        C = self.C
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(2, weight=1)

        card = ctk.CTkFrame(parent, fg_color=C["card"], corner_radius=12)
        card.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 0))
        card.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(card, text="MODE", font=("Segoe UI", 11, "bold"), text_color=C["label"]).grid(row=0, column=0, sticky="w", padx=(20, 10), pady=(20, 10))
        self.mode_var = ctk.StringVar(value=MODE_DIY)
        mode_f = ctk.CTkFrame(card, fg_color="transparent")
        mode_f.grid(row=0, column=1, sticky="w", pady=(20, 10))
        ctk.CTkRadioButton(mode_f, text="DIY sync-on-close", variable=self.mode_var, value=MODE_DIY, command=self._mode_changed, text_color=C["text"]).pack(side="left", padx=(0, 20))
        ctk.CTkRadioButton(mode_f, text="On-the-fly FUSE", variable=self.mode_var, value=MODE_FUSE, command=self._mode_changed, text_color=C["text"]).pack(side="left")

        self.storage_var = ctk.StringVar(value=str(Path.cwd() / "ShadowSyncStore"))
        self.app_name_var = ctk.StringVar(value="Session")
        self.profile_name_var = ctk.StringVar(value="Default")
        self.profile_kind_var = ctk.StringVar(value="Session")
        self.profile_var = ctk.StringVar(value=self.presets.get("Session", ""))
        self.exec_var = ctk.StringVar()
        self.wipe_var = ctk.BooleanVar(value=True)
        self.password_var = ctk.StringVar()
        self.password_var.trace_add("write", lambda *_args: self._clear_executable_approval())

        self._vault_field(card, 1, "STORAGE FOLDER", self.storage_var, self._browse_storage)
        self._vault_field(card, 2, "APP NAME", self.app_name_var, None)
        self._vault_field(card, 3, "PROFILE FOLDER", self.profile_var, self._browse_profile, is_profile=True)
        self._vault_field(card, 4, "APPLICATION", self.exec_var, self._browse_executable)

        ctk.CTkLabel(card, text="PROFILE NAME", font=("Segoe UI", 11, "bold"), text_color=C["label"]).grid(row=5, column=0, sticky="w", padx=(20, 10), pady=10)
        pname_f = ctk.CTkFrame(card, fg_color="transparent")
        pname_f.grid(row=5, column=1, sticky="ew", pady=10, padx=(0, 20))
        pname_f.grid_columnconfigure(0, weight=1)
        self.profile_combo = ctk.CTkComboBox(pname_f, variable=self.profile_name_var, values=["Default"], fg_color=C["input_bg"], border_color=C["ghost"], button_color=C["ghost"])
        self.profile_combo.grid(row=0, column=0, sticky="ew")
        ctk.CTkButton(pname_f, text="Refresh", width=80, fg_color=C["ghost"], hover_color=C["ghost2"], command=self._refresh_profile_names).grid(row=0, column=1, padx=(10, 0))

        ctk.CTkLabel(card, text="PRESET", font=("Segoe UI", 11, "bold"), text_color=C["label"]).grid(row=6, column=0, sticky="w", padx=(20, 10), pady=10)
        preset = ctk.CTkComboBox(card, variable=self.profile_kind_var, values=list(self.presets), fg_color=C["input_bg"], border_color=C["ghost"], button_color=C["ghost"], command=self._preset_changed)
        preset.grid(row=6, column=1, sticky="ew", pady=10, padx=(0, 20))

        ctk.CTkLabel(card, text="MASTER PASSWORD", font=("Segoe UI", 11, "bold"), text_color=C["label"]).grid(row=7, column=0, sticky="w", padx=(20, 10), pady=10)
        pw_f = ctk.CTkFrame(card, fg_color="transparent")
        pw_f.grid(row=7, column=1, sticky="ew", pady=10, padx=(0, 20))
        pw_f.grid_columnconfigure(0, weight=1)
        self._pw_entry = ctk.CTkEntry(pw_f, textvariable=self.password_var, show="●", fg_color=C["input_bg"], border_color=C["ghost"])
        self._pw_entry.grid(row=0, column=0, sticky="ew")
        self._pw_eye_btn = ctk.CTkButton(pw_f, text="👁", width=40, fg_color=C["ghost"], hover_color=C["ghost2"], command=self._toggle_password_visibility)
        self._pw_eye_btn.grid(row=0, column=1, padx=(10, 0))

        ctk.CTkCheckBox(card, text="Wipe profile after close", variable=self.wipe_var, text_color=C["text"], fg_color=C["accent"]).grid(row=8, column=1, sticky="w", pady=(10, 20))

        actions_f = ctk.CTkFrame(card, fg_color="transparent")
        actions_f.grid(row=9, column=0, columnspan=3, sticky="ew", padx=20, pady=(0, 20))
        ctk.CTkButton(actions_f, text="▶ Open & Launch", font=("Segoe UI", 13, "bold"), fg_color=C["accent"], text_color="#000", hover_color=C["accent2"], command=self._start).pack(side="left")
        ctk.CTkButton(actions_f, text="💾 Save Vault", fg_color=C["ghost"], hover_color=C["ghost2"], command=self._save_now).pack(side="left", padx=(10, 0))
        ctk.CTkButton(actions_f, text="⬛ Stop", fg_color=C["ghost"], hover_color=C["ghost2"], command=self._stop_worker).pack(side="left", padx=(10, 0))

        self.progress = ctk.CTkProgressBar(card, mode="indeterminate", progress_color=C["accent"], fg_color=C["input_bg"])
        self.progress.grid(row=10, column=0, columnspan=3, sticky="ew", padx=20, pady=(0, 20))
        self.progress.set(0)
        self.progress.grid_remove()

        # Stored Apps Panel
        apps_card = ctk.CTkFrame(parent, fg_color=C["card"], corner_radius=12)
        apps_card.grid(row=1, column=0, sticky="ew", padx=10, pady=(10, 0))
        apps_card.grid_columnconfigure(0, weight=1)
        apps_header = ctk.CTkFrame(apps_card, fg_color="transparent")
        apps_header.grid(row=0, column=0, sticky="ew", padx=20, pady=(15, 5))
        apps_header.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(apps_header, text="📦 Stored App Vaults", font=("Segoe UI", 14, "bold"), text_color=C["accent"]).grid(row=0, column=0, sticky="w")
        ctk.CTkButton(apps_header, text="🔄 Refresh", width=90, font=("Segoe UI", 11), fg_color=C["ghost"], hover_color=C["ghost2"], command=self._refresh_stored_apps).grid(row=0, column=1, sticky="e")
        self._stored_apps_frame = ctk.CTkFrame(apps_card, fg_color="transparent")
        self._stored_apps_frame.grid(row=1, column=0, sticky="ew", padx=15, pady=(5, 15))
        self._stored_apps_frame.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(self._stored_apps_frame, text="No stored app vaults found. Launch an app with ShadowSync to create one.", text_color=C["muted"], font=("Segoe UI", 11)).grid(row=0, column=0, sticky="w", padx=5, pady=5)

        # Log Terminal
        log_card = ctk.CTkFrame(parent, fg_color=C["log_bg"], corner_radius=8)
        log_card.grid(row=2, column=0, sticky="nsew", padx=10, pady=(10, 10))
        log_card.grid_columnconfigure(0, weight=1)
        log_card.grid_rowconfigure(0, weight=1)
        self.log_text = ctk.CTkTextbox(log_card, fg_color="transparent", text_color=C["text"], font=("Consolas", 12), wrap="word")
        self.log_text.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.log_text.tag_config("ts", foreground=C["log_ts"])
        self.log_text.tag_config("ok", foreground=C["log_ok"])
        self.log_text.tag_config("err", foreground=C["log_err"])
        self.log_text.tag_config("warn", foreground=C["log_warn"])
        self.log_text.tag_config("info", foreground=C["log_info"])
        self.log_text.tag_config("body", foreground=C["text"])
        self._log("Ready — enter the master password, then choose an app.")

    def _vault_field(self, parent, row, label, var, browse_cmd, is_profile=False) -> None:
        C = self.C
        ctk.CTkLabel(parent, text=label, font=("Segoe UI", 11, "bold"), text_color=C["label"]).grid(row=row, column=0, sticky="w", padx=(20, 10), pady=10)
        entry = ctk.CTkEntry(parent, textvariable=var, fg_color=C["input_bg"], border_color=C["ghost"])
        entry.grid(row=row, column=1, sticky="ew", pady=10, padx=(0, 20 if not browse_cmd else 0))
        if is_profile:
            self.profile_entry = entry
        if browse_cmd:
            ctk.CTkButton(parent, text="Browse", width=80, fg_color=C["ghost"], hover_color=C["ghost2"], command=browse_cmd).grid(row=row, column=2, padx=(10, 20))

    # ─────────────────────────────────────────────────────────────────────────
    # Files Tab — with drive picker
    # ─────────────────────────────────────────────────────────────────────────

    def _build_files_tab(self, parent) -> None:
        C = self.C
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(1, weight=1)

        # Header card
        header_card = ctk.CTkFrame(parent, fg_color=C["card"], corner_radius=12)
        header_card.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 0))
        header_card.grid_columnconfigure(0, weight=1)

        title_row = ctk.CTkFrame(header_card, fg_color="transparent")
        title_row.grid(row=0, column=0, sticky="ew", padx=20, pady=(15, 5))
        title_row.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(title_row, text="📁 Files Vault — Drive Manager", font=("Segoe UI", 18, "bold"), text_color=C["text"]).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(header_card, text="Encrypt and carry files on any drive. Pick a target drive — the vault lives there independently.",
                     text_color=C["muted"], font=("Segoe UI", 11)).grid(row=1, column=0, sticky="w", padx=20, pady=(0, 5))

        # Drive picker row
        drive_row = ctk.CTkFrame(header_card, fg_color="transparent")
        drive_row.grid(row=2, column=0, sticky="ew", padx=20, pady=(0, 8))
        ctk.CTkLabel(drive_row, text="TARGET DRIVE", font=("Segoe UI", 11, "bold"), text_color=C["label"]).pack(side="left", padx=(0, 10))
        self._files_drive_var = ctk.StringVar()
        drives = list_mounted_drives()
        default_drive = drives[0] if drives else str(Path.cwd().anchor)
        self._files_drive_var.set(default_drive)
        self._files_drive_combo = ctk.CTkComboBox(
            drive_row, variable=self._files_drive_var,
            values=drives, width=200,
            fg_color=C["input_bg"], border_color=C["ghost"], button_color=C["ghost"],
            command=self._on_files_drive_changed,
        )
        self._files_drive_combo.pack(side="left", padx=(0, 8))
        ctk.CTkButton(drive_row, text="🔄 Scan Drives", width=110, fg_color=C["ghost"], hover_color=C["ghost2"],
                      command=self._refresh_drive_list).pack(side="left", padx=(0, 8))
        self._files_drive_path_label = ctk.CTkLabel(drive_row, text="", font=("Segoe UI", 10), text_color=C["muted"])
        self._files_drive_path_label.pack(side="left", padx=(10, 0))
        self._update_drive_path_label()

        # Toolbar
        toolbar = ctk.CTkFrame(header_card, fg_color="transparent")
        toolbar.grid(row=3, column=0, sticky="ew", padx=20, pady=(0, 15))
        ctk.CTkButton(toolbar, text="➕ Add Files", width=110, font=("Segoe UI", 11), fg_color=C["accent"], text_color="#000", hover_color=C["accent2"], command=self._add_files_to_vault).pack(side="left", padx=(0, 8))
        ctk.CTkButton(toolbar, text="📂 Add Folder", width=110, font=("Segoe UI", 11), fg_color=C["ghost"], hover_color=C["ghost2"], command=self._add_folder_to_vault).pack(side="left", padx=(0, 8))
        ctk.CTkButton(toolbar, text="📤 Export", width=90, font=("Segoe UI", 11), fg_color=C["ghost"], hover_color=C["ghost2"], command=self._export_files_vault).pack(side="left", padx=(0, 8))
        ctk.CTkButton(toolbar, text="📥 Restore from Drive", width=140, font=("Segoe UI", 11), fg_color=C["purple"], hover_color=C["purple2"], command=self._restore_files_from_drive).pack(side="left", padx=(0, 8))
        ctk.CTkButton(toolbar, text="🔄 Refresh", width=90, font=("Segoe UI", 11), fg_color=C["ghost"], hover_color=C["ghost2"], command=self._refresh_files_view).pack(side="left", padx=(0, 8))
        self._view_toggle_btn = ctk.CTkButton(toolbar, text="☰ List", width=80, font=("Segoe UI", 11), fg_color=C["ghost"], hover_color=C["ghost2"], command=self._toggle_files_view_mode)
        self._view_toggle_btn.pack(side="right")

        # Scrollable content area
        content_card = ctk.CTkFrame(parent, fg_color=C["card"], corner_radius=12)
        content_card.grid(row=1, column=0, sticky="nsew", padx=10, pady=(8, 0))
        content_card.grid_columnconfigure(0, weight=1)
        content_card.grid_rowconfigure(0, weight=1)
        self._files_scroll = ctk.CTkScrollableFrame(content_card, fg_color="transparent", scrollbar_button_color=C["ghost"], scrollbar_button_hover_color=C["ghost2"])
        self._files_scroll.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        self._files_scroll.grid_columnconfigure(0, weight=1)
        self._files_empty_label = ctk.CTkLabel(self._files_scroll, text="\n\n📭  Vault is empty\n\nAdd files or folders with the buttons above.\nThey will be encrypted and stored securely.", font=("Segoe UI", 13), text_color=C["muted"], justify="center")
        self._files_empty_label.grid(row=0, column=0, sticky="nsew", pady=40)

        # Status bar
        status_bar = ctk.CTkFrame(parent, fg_color=C["card"], corner_radius=8, height=32)
        status_bar.grid(row=2, column=0, sticky="ew", padx=10, pady=(4, 10))
        status_bar.grid_columnconfigure(0, weight=1)
        self._files_status_label = ctk.CTkLabel(status_bar, text="0 items  •  Vault not loaded", font=("Segoe UI", 11), text_color=C["muted"], anchor="w")
        self._files_status_label.grid(row=0, column=0, sticky="w", padx=15, pady=6)

    def _get_active_files_vault_path(self) -> Path:
        """Return the vault path on the currently selected drive."""
        drive = self._files_drive_var.get().strip() if hasattr(self, "_files_drive_var") else ""
        if drive:
            return files_vault_path_for_drive(drive)
        # Fallback to storage root
        return files_vault_path(Path(self.storage_var.get()))

    def _update_drive_path_label(self) -> None:
        if hasattr(self, "_files_drive_path_label") and hasattr(self, "_files_drive_var"):
            vpath = self._get_active_files_vault_path()
            exists = "✓ vault exists" if vpath.exists() else "no vault yet"
            self._files_drive_path_label.configure(text=f"→ {vpath.parent}  [{exists}]")

    def _on_files_drive_changed(self, _val=None) -> None:
        self._update_drive_path_label()
        self._log(f"Files drive set to: {self._files_drive_var.get()}")

    def _refresh_drive_list(self) -> None:
        drives = list_mounted_drives()
        self._files_drive_combo.configure(values=drives)
        if drives and self._files_drive_var.get() not in drives:
            self._files_drive_var.set(drives[0])
        self._update_drive_path_label()
        self._log(f"Drives refreshed: {', '.join(drives)}")

    def _restore_files_from_drive(self) -> None:
        """Decrypt the files vault on the selected drive to a user-chosen folder."""
        try:
            password = self._file_vault_password()
        except ShadowSyncError as exc:
            messagebox.showerror("ShadowSync", str(exc))
            return
        vault_path = self._get_active_files_vault_path()
        if not vault_path.exists():
            messagebox.showinfo("ShadowSync", f"No files vault found at:\n{vault_path}\n\nInsert the drive and try again.")
            return
        destination = filedialog.askdirectory(title="Restore files to folder")
        if not destination:
            return
        self._set_busy(True, "Restoring files from drive vault...")

        def task() -> None:
            try:
                PortableVault(vault_path).extract_to(Path(destination), password)
                self.log_queue.put(f"Files restored from drive to: {destination}")
            except ShadowSyncError as exc:
                msg = str(exc)
                self.after(0, lambda m=msg: messagebox.showerror("ShadowSync", m))
            finally:
                self.log_queue.put(("busy", False, ""))

        threading.Thread(target=task, daemon=True).start()

    # ─────────────────────────────────────────────────────────────────────────
    # OS State Tab
    # ─────────────────────────────────────────────────────────────────────────

    def _build_os_tab(self, parent) -> None:
        C = self.C
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(1, weight=1)

        # Header card
        header_card = ctk.CTkFrame(parent, fg_color=C["card"], corner_radius=12)
        header_card.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 0))
        header_card.grid_columnconfigure(0, weight=1)

        title_row = ctk.CTkFrame(header_card, fg_color="transparent")
        title_row.grid(row=0, column=0, sticky="ew", padx=20, pady=(15, 5))
        title_row.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(title_row, text="🖥 OS State Hibernation", font=("Segoe UI", 18, "bold"), text_color=C["green"]).grid(row=0, column=0, sticky="w")

        self._os_captured_label = ctk.CTkLabel(
            header_card,
            text="Last captured: —",
            font=("Segoe UI", 11), text_color=C["muted"],
        )
        self._os_captured_label.grid(row=1, column=0, sticky="w", padx=20, pady=(0, 10))

        # Action buttons
        actions_f = ctk.CTkFrame(header_card, fg_color="transparent")
        actions_f.grid(row=2, column=0, sticky="ew", padx=20, pady=(0, 15))
        ctk.CTkButton(actions_f, text="📸 Capture Now", font=("Segoe UI", 13, "bold"), fg_color=C["green"], text_color="#000", hover_color=C["green2"], command=self._capture_os_settings).pack(side="left", padx=(0, 10))
        ctk.CTkButton(actions_f, text="♻️ Restore from Vault", font=("Segoe UI", 12), fg_color=C["ghost"], hover_color=C["ghost2"], command=self._restore_os_settings).pack(side="left", padx=(0, 10))
        ctk.CTkButton(actions_f, text="💾 Save to Vault", font=("Segoe UI", 12), fg_color=C["ghost"], hover_color=C["ghost2"], command=self._save_os_settings).pack(side="left", padx=(0, 10))
        ctk.CTkButton(actions_f, text="📂 Load from Vault", font=("Segoe UI", 12), fg_color=C["ghost"], hover_color=C["ghost2"], command=self._load_os_settings).pack(side="left")

        # Scrollable detail area
        detail_scroll = ctk.CTkScrollableFrame(parent, fg_color=C["card"], corner_radius=12, scrollbar_button_color=C["ghost"], scrollbar_button_hover_color=C["ghost2"])
        detail_scroll.grid(row=1, column=0, sticky="nsew", padx=10, pady=(8, 10))
        detail_scroll.grid_columnconfigure(0, weight=1)

        # ── WiFi section ──
        wifi_header = ctk.CTkFrame(detail_scroll, fg_color="transparent")
        wifi_header.grid(row=0, column=0, sticky="ew", padx=15, pady=(15, 5))
        wifi_header.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(wifi_header, text="📶 WiFi Profiles", font=("Segoe UI", 14, "bold"), text_color=C["accent"]).grid(row=0, column=0, sticky="w")
        ctk.CTkButton(wifi_header, text="+ Add Manual", width=110, font=("Segoe UI", 11), fg_color=C["ghost"], hover_color=C["ghost2"], command=self._add_wifi_row).grid(row=0, column=1, sticky="e")
        ctk.CTkButton(wifi_header, text="🔍 Scan System", width=110, font=("Segoe UI", 11), fg_color=C["accent"], text_color="#000", hover_color=C["accent2"], command=self._scan_system_wifi).grid(row=0, column=2, padx=(8, 0), sticky="e")

        self._os_wifi_container = ctk.CTkScrollableFrame(detail_scroll, fg_color=C["sidebar"], corner_radius=8, height=160, scrollbar_button_color=C["ghost"])
        self._os_wifi_container.grid(row=1, column=0, sticky="ew", padx=15, pady=(0, 10))
        self._os_wifi_container.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(self._os_wifi_container, text="No WiFi profiles. Click 'Scan System' to import from OS.", font=("Segoe UI", 11), text_color=C["muted"]).grid(row=0, column=0, padx=10, pady=10)

        # ── OS details section ──
        details_card = ctk.CTkFrame(detail_scroll, fg_color=C["sidebar"], corner_radius=8)
        details_card.grid(row=2, column=0, sticky="ew", padx=15, pady=(0, 10))
        details_card.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(details_card, text="⚙️ OS Details", font=("Segoe UI", 14, "bold"), text_color=C["accent"]).grid(row=0, column=0, columnspan=2, sticky="w", padx=15, pady=(15, 10))

        fields = [
            ("THEME", "_os_theme_var", "dark"),
            ("WALLPAPER PATH", "_os_wallpaper_var", ""),
            ("HOSTNAME", "_os_hostname_var", platform.node()),
        ]
        for i, (lbl, attr, default) in enumerate(fields):
            r = i + 1
            ctk.CTkLabel(details_card, text=lbl, font=("Segoe UI", 11, "bold"), text_color=C["label"]).grid(row=r, column=0, sticky="w", padx=(15, 10), pady=6)
            var = ctk.StringVar(value=default)
            setattr(self, attr, var)
            ctk.CTkEntry(details_card, textvariable=var, fg_color=C["input_bg"], border_color=C["ghost"]).grid(row=r, column=1, sticky="ew", padx=(0, 15), pady=6)

        # Env vars
        ctk.CTkLabel(details_card, text="ENV VARS", font=("Segoe UI", 11, "bold"), text_color=C["label"]).grid(row=4, column=0, sticky="nw", padx=(15, 10), pady=6)
        self._os_env_text = ctk.CTkTextbox(details_card, fg_color=C["input_bg"], text_color=C["text"], font=("Consolas", 11), height=80)
        self._os_env_text.grid(row=4, column=1, sticky="ew", padx=(0, 15), pady=6)
        self._os_env_text.insert("end", "# KEY=VALUE (one per line, auto-captured)\n")

        # Registry / Shell RC
        reg_lbl = "REGISTRY KEYS (Windows)" if _IS_WINDOWS else "SHELL RC (~/.bashrc)"
        ctk.CTkLabel(details_card, text=reg_lbl, font=("Segoe UI", 11, "bold"), text_color=C["label"]).grid(row=5, column=0, sticky="nw", padx=(15, 10), pady=(6, 15))
        self._os_extra_text = ctk.CTkTextbox(details_card, fg_color=C["input_bg"], text_color=C["text"], font=("Consolas", 11), height=80)
        self._os_extra_text.grid(row=5, column=1, sticky="ew", padx=(0, 15), pady=(6, 15))
        self._os_extra_text.insert("end", "# Captured automatically when you click 'Capture Now'\n")

    def _add_wifi_row(self, ssid: str = "", password: str = "", blob: str = "", auth: str = "") -> None:
        """Add a WiFi profile row to the OS WiFi container."""
        C = self.C
        container = self._os_wifi_container
        if container is None:
            return

        # Clear placeholder label if first row
        if not self._os_wifi_rows:
            for w in container.winfo_children():
                w.destroy()

        idx = len(self._os_wifi_rows)
        row_frame = ctk.CTkFrame(container, fg_color=C["card"], corner_radius=6)
        row_frame.grid(row=idx, column=0, sticky="ew", padx=5, pady=3)
        row_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(row_frame, text="📶", font=("Segoe UI", 14), text_color=C["accent"]).grid(row=0, column=0, padx=(10, 5), pady=8)
        ssid_var = ctk.StringVar(value=ssid)
        ctk.CTkEntry(row_frame, textvariable=ssid_var, placeholder_text="SSID", fg_color=C["input_bg"], border_color=C["ghost"], width=180).grid(row=0, column=1, sticky="ew", padx=5, pady=8)
        pwd_var = ctk.StringVar(value=password)
        ctk.CTkEntry(row_frame, textvariable=pwd_var, placeholder_text="Password (optional)", show="●", fg_color=C["input_bg"], border_color=C["ghost"], width=180).grid(row=0, column=2, padx=5, pady=8)

        # Auth type badge
        auth_lbl = ctk.CTkLabel(row_frame, text=auth or "—", font=("Segoe UI", 10), text_color=C["muted"], width=60)
        auth_lbl.grid(row=0, column=3, padx=5, pady=8)

        # Blob indicator
        has_blob = bool(blob)
        blob_lbl = ctk.CTkLabel(row_frame, text="🔑 Profile" if has_blob else "⚠ No profile", font=("Segoe UI", 10), text_color=C["green"] if has_blob else C["muted"], width=80)
        blob_lbl.grid(row=0, column=4, padx=5, pady=8)

        def remove_row() -> None:
            row_data = {"ssid": ssid_var, "password": pwd_var, "blob": blob, "auth": auth, "frame": row_frame}
            if row_data in self._os_wifi_rows:
                self._os_wifi_rows.remove(row_data)
            row_frame.destroy()

        ctk.CTkButton(row_frame, text="✕", width=30, fg_color=C["danger"], hover_color=C["danger2"], command=remove_row, font=("Segoe UI", 12)).grid(row=0, column=5, padx=(5, 10), pady=8)

        self._os_wifi_rows.append({"ssid": ssid_var, "password": pwd_var, "blob": blob, "auth": auth, "frame": row_frame})

    def _scan_system_wifi(self) -> None:
        """Scan the OS for saved WiFi profiles and populate the list."""
        password = self.password_var.get()
        self._set_busy(True, "Scanning system WiFi profiles…")
        self._log("Scanning system WiFi profiles…")

        def task() -> None:
            worker = OSSettingsWorker(self.log_queue)
            try:
                profiles = worker._capture_wifi()
                self.after(0, lambda p=profiles: self._populate_wifi_rows(p))
                self.log_queue.put(f"WiFi scan: found {len(profiles)} profile(s).")
            except Exception as exc:
                self.log_queue.put(f"WiFi scan error: {exc}")
            finally:
                self.log_queue.put(("busy", False, ""))

        threading.Thread(target=task, daemon=True).start()

    def _populate_wifi_rows(self, profiles: List[WifiProfile]) -> None:
        """Clear existing WiFi rows and populate from scanned profiles."""
        # Clear
        if self._os_wifi_container:
            for w in self._os_wifi_container.winfo_children():
                w.destroy()
        self._os_wifi_rows.clear()
        for p in profiles:
            self._add_wifi_row(ssid=p.ssid, password=p.password_hint, blob=p.blob, auth=p.auth_type)
        if not profiles:
            ctk.CTkLabel(self._os_wifi_container, text="No WiFi profiles found.", font=("Segoe UI", 11), text_color=self.C["muted"]).grid(row=0, column=0, padx=10, pady=10)

    def _get_os_wifi_profiles(self) -> List[WifiProfile]:
        profiles = []
        for row in self._os_wifi_rows:
            ssid = row["ssid"].get().strip()
            if ssid:
                profiles.append(WifiProfile(
                    ssid=ssid,
                    password_hint=row["password"].get(),
                    blob=row.get("blob", ""),
                    auth_type=row.get("auth", ""),
                ))
        return profiles

    def _capture_os_settings(self) -> None:
        self._set_busy(True, "Capturing OS state…")
        self._log("Capturing OS state (WiFi, theme, wallpaper, registry…)")

        def task() -> None:
            try:
                worker = OSSettingsWorker(self.log_queue)
                settings = worker.capture()
                self._os_settings = settings
                self.after(0, lambda s=settings: self._populate_os_fields(s))
                self.log_queue.put(f"OS state captured at {settings.captured_at}")
            except Exception as exc:
                self.log_queue.put(f"OS capture error: {exc}")
            finally:
                self.log_queue.put(("busy", False, ""))

        threading.Thread(target=task, daemon=True).start()

    def _populate_os_fields(self, settings: OSSettings) -> None:
        """Fill OS tab fields from a captured OSSettings object."""
        self._os_theme_var.set(settings.os_theme)
        self._os_wallpaper_var.set(settings.wallpaper_path)
        self._os_hostname_var.set(settings.hostname)
        # Env vars
        self._os_env_text.delete("1.0", "end")
        for k, v in settings.env_vars.items():
            self._os_env_text.insert("end", f"{k}={v}\n")
        # Extra (registry / shell rc / aliases / installed apps)
        self._os_extra_text.delete("1.0", "end")
        extra_parts: List[str] = []
        if settings.shell_aliases:
            extra_parts.append("── Shell Aliases ──")
            extra_parts.append(settings.shell_aliases[:1500])
        if _IS_LINUX and settings.shell_rc:
            extra_parts.append("── Shell RC (excerpt) ──")
            extra_parts.append(settings.shell_rc[:800])
        if _IS_WINDOWS and settings.registry_exports:
            extra_parts.append("── Registry exports ──")
            for k in settings.registry_exports:
                extra_parts.append(f"[REG] {k}")
        if settings.installed_apps:
            extra_parts.append(f"── Installed Apps ({len(settings.installed_apps)}) ──")
            extra_parts.extend(settings.installed_apps[:80])
            if len(settings.installed_apps) > 80:
                extra_parts.append(f"… and {len(settings.installed_apps) - 80} more")
        self._os_extra_text.insert("end", "\n".join(extra_parts) or "# Captured automatically when you click 'Capture Now'\n")
        # WiFi
        self._populate_wifi_rows(settings.wifi_profiles)
        # Label — rich summary
        if self._os_captured_label:
            self._os_captured_label.configure(
                text=(
                    f"Last captured: {settings.captured_at}  •  "
                    f"{len(settings.wifi_profiles)} WiFi  •  "
                    f"{len(settings.installed_apps)} apps  •  "
                    f"host: {settings.hostname}"
                )
            )
        self._os_settings = settings

    def _build_os_settings_from_ui(self) -> OSSettings:
        """Collect UI fields into an OSSettings object."""
        settings = self._os_settings or OSSettings()
        settings.os_theme = self._os_theme_var.get().strip() or "dark"
        settings.wallpaper_path = self._os_wallpaper_var.get().strip()
        settings.hostname = self._os_hostname_var.get().strip()
        settings.wifi_profiles = self._get_os_wifi_profiles()
        # Parse env vars
        env: Dict[str, str] = {}
        for line in self._os_env_text.get("1.0", "end").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                env[k.strip()] = v.strip()
        settings.env_vars = env
        if not settings.captured_at:
            settings.captured_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        return settings

    def _save_os_settings(self) -> None:
        password = self.password_var.get()
        storage = self.storage_var.get().strip()
        if not password:
            messagebox.showerror("OS State", "Enter the master password first.")
            return
        if not storage:
            messagebox.showerror("OS State", "Choose the ShadowSync storage folder first.")
            return
        settings = self._build_os_settings_from_ui()
        self._set_busy(True, "Saving OS state vault…")

        def task() -> None:
            try:
                settings.save(Path(storage), password)
                self._os_settings = settings
                self.log_queue.put(f"OS state saved to: {os_settings_vault_path(Path(storage))}")
            except Exception as exc:
                msg = str(exc)
                self.after(0, lambda m=msg: messagebox.showerror("OS State", m))
            finally:
                self.log_queue.put(("busy", False, ""))

        threading.Thread(target=task, daemon=True).start()

    def _load_os_settings(self) -> None:
        password = self.password_var.get()
        storage = self.storage_var.get().strip()
        if not password:
            messagebox.showerror("OS State", "Enter the master password first.")
            return
        if not storage:
            messagebox.showerror("OS State", "Choose the ShadowSync storage folder first.")
            return
        self._set_busy(True, "Loading OS state vault…")

        def task() -> None:
            try:
                settings = OSSettings.load(Path(storage), password)
                self.after(0, lambda s=settings: self._populate_os_fields(s))
                self.log_queue.put(f"OS state loaded from vault (captured: {settings.captured_at})")
            except ShadowSyncError as exc:
                msg = str(exc)
                self.after(0, lambda m=msg: messagebox.showerror("OS State", m))
            finally:
                self.log_queue.put(("busy", False, ""))

        threading.Thread(target=task, daemon=True).start()

    def _restore_os_settings(self) -> None:
        password = self.password_var.get()
        storage = self.storage_var.get().strip()
        if not password:
            messagebox.showerror("OS State", "Enter the master password first.")
            return
        if not storage:
            messagebox.showerror("OS State", "Choose the ShadowSync storage folder first.")
            return
        vault_path = os_settings_vault_path(Path(storage))
        if not vault_path.exists():
            messagebox.showinfo("OS State", "No OS state vault found. Capture and save first.")
            return
        if not messagebox.askyesno("OS State", "Restore OS settings from vault?\n\nThis will overwrite WiFi profiles, wallpaper, and other OS settings on this machine."):
            return
        self._set_busy(True, "Restoring OS state…")

        def task() -> None:
            try:
                settings = OSSettings.load(Path(storage), password)
                worker = OSSettingsWorker(self.log_queue)
                worker.restore(settings)
                self.log_queue.put("OS state restore complete.")
            except ShadowSyncError as exc:
                msg = str(exc)
                self.after(0, lambda m=msg: messagebox.showerror("OS State", m))
            except Exception as exc:
                self.log_queue.put(f"OS restore error: {exc}")
            finally:
                self.log_queue.put(("busy", False, ""))

        threading.Thread(target=task, daemon=True).start()

    # ─────────────────────────────────────────────────────────────────────────
    # Hydrate Tab
    # ─────────────────────────────────────────────────────────────────────────

    def _build_hydrate_tab(self, parent) -> None:
        C = self.C
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(0, weight=1)

        outer_scroll = ctk.CTkScrollableFrame(parent, fg_color="transparent", scrollbar_button_color=C["ghost"], scrollbar_button_hover_color=C["ghost2"])
        outer_scroll.grid(row=0, column=0, sticky="nsew")
        outer_scroll.grid_columnconfigure(0, weight=1)

        card = ctk.CTkFrame(outer_scroll, fg_color=C["card"], corner_radius=12)
        card.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        card.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(card, text="⚡ Hydrate — Session Personalisation", font=("Segoe UI", 18, "bold"), text_color=C["purple"]).grid(row=0, column=0, columnspan=3, sticky="w", padx=20, pady=(20, 5))

        if not _IS_LINUX:
            ctk.CTkLabel(card, text="ℹ GNOME/NetworkManager hooks (dark mode, wallpaper) are Linux/Tails only. Git backup and auto-push work everywhere.", text_color=C["muted"], font=("Segoe UI", 11), wraplength=600, justify="left").grid(row=1, column=0, columnspan=3, sticky="w", padx=20, pady=(0, 10))

        # Appearance
        ctk.CTkLabel(card, text="APPEARANCE", font=("Segoe UI", 11, "bold"), text_color=C["purple"]).grid(row=2, column=0, sticky="w", padx=20, pady=5)
        self._h_darkmode_var = ctk.BooleanVar(value=True)
        ctk.CTkSwitch(card, text="Enable dark mode (GNOME)", variable=self._h_darkmode_var, progress_color=C["purple"]).grid(row=3, column=0, columnspan=3, sticky="w", padx=20, pady=5)

        ctk.CTkLabel(card, text="WALLPAPER", font=("Segoe UI", 11, "bold"), text_color=C["label"]).grid(row=4, column=0, sticky="w", padx=20, pady=10)
        self._h_wallpaper_var = ctk.StringVar(value="/live/mount/medium/wallpaper.jpg")
        wp_f = ctk.CTkFrame(card, fg_color="transparent")
        wp_f.grid(row=4, column=1, sticky="ew", pady=10, padx=(0, 20))
        wp_f.grid_columnconfigure(0, weight=1)
        ctk.CTkEntry(wp_f, textvariable=self._h_wallpaper_var, fg_color=C["input_bg"], border_color=C["ghost"]).grid(row=0, column=0, sticky="ew")
        ctk.CTkButton(wp_f, text="Browse", width=80, fg_color=C["ghost"], hover_color=C["ghost2"], command=self._h_browse_wallpaper).grid(row=0, column=1, padx=(10, 0))

        # Simple WiFi fallback (Hydrate = quick connect)
        ctk.CTkLabel(card, text="QUICK WI-FI (FALLBACK)", font=("Segoe UI", 11, "bold"), text_color=C["purple"]).grid(row=5, column=0, sticky="w", padx=20, pady=(20, 5))
        ctk.CTkLabel(card, text="For full WiFi profile restore with passwords, use the OS State tab.", text_color=C["muted"], font=("Segoe UI", 10)).grid(row=6, column=0, columnspan=3, sticky="w", padx=20, pady=(0, 5))
        self._h_wifi_vars = []
        for i in range(3):
            row = 7 + i
            ctk.CTkLabel(card, text=f"SSID {i+1}", font=("Segoe UI", 11, "bold"), text_color=C["label"]).grid(row=row, column=0, sticky="w", padx=20, pady=5)
            wifi_f = ctk.CTkFrame(card, fg_color="transparent")
            wifi_f.grid(row=row, column=1, sticky="ew", pady=5, padx=(0, 20))
            ssid_v, pwd_v = ctk.StringVar(), ctk.StringVar()
            ctk.CTkEntry(wifi_f, textvariable=ssid_v, placeholder_text="SSID", fg_color=C["input_bg"], border_color=C["ghost"], width=200).pack(side="left")
            ctk.CTkLabel(wifi_f, text="Password", font=("Segoe UI", 11, "bold"), text_color=C["label"]).pack(side="left", padx=10)
            ctk.CTkEntry(wifi_f, textvariable=pwd_v, show="●", fg_color=C["input_bg"], border_color=C["ghost"], width=200).pack(side="left")
            self._h_wifi_vars.append((ssid_v, pwd_v))

        # Git Backup
        ctk.CTkLabel(card, text="GIT BACKUP", font=("Segoe UI", 11, "bold"), text_color=C["purple"]).grid(row=11, column=0, sticky="w", padx=20, pady=(20, 5))

        # Git host selector
        ctk.CTkLabel(card, text="GIT HOST", font=("Segoe UI", 11, "bold"), text_color=C["label"]).grid(row=12, column=0, sticky="w", padx=20, pady=5)
        self._h_git_host_var = ctk.StringVar(value="github")
        host_f = ctk.CTkFrame(card, fg_color="transparent")
        host_f.grid(row=12, column=1, sticky="w", pady=5)
        for host in ("github", "gitlab", "custom"):
            ctk.CTkRadioButton(host_f, text=host.capitalize(), variable=self._h_git_host_var, value=host, text_color=C["text"]).pack(side="left", padx=(0, 15))

        git_fields = [
            ("REMOTE URL", "_h_git_remote_var", "", False),
            ("BRANCH", "_h_git_branch_var", "main", False),
            ("IDENTITY NAME", "_h_git_name_var", "ShadowSync User", False),
            ("IDENTITY EMAIL", "_h_git_email_var", "", False),
            ("ACCESS TOKEN (PAT)", "_h_git_token_var", "", True),
        ]
        for i, (lbl, attr, default, secret) in enumerate(git_fields):
            r = 13 + i
            ctk.CTkLabel(card, text=lbl, font=("Segoe UI", 11, "bold"), text_color=C["label"]).grid(row=r, column=0, sticky="w", padx=20, pady=5)
            var = ctk.StringVar(value=default)
            setattr(self, attr, var)
            ctk.CTkEntry(card, textvariable=var, show="●" if secret else "", fg_color=C["input_bg"], border_color=C["ghost"]).grid(row=r, column=1, sticky="ew", padx=(0, 20), pady=5)

        # Auto-push options
        ctk.CTkLabel(card, text="AUTO-PUSH", font=("Segoe UI", 11, "bold"), text_color=C["purple"]).grid(row=19, column=0, sticky="w", padx=20, pady=(20, 5))
        self._h_auto_push_var = ctk.BooleanVar(value=False)
        ctk.CTkSwitch(card, text="Auto-push vault to Git on app close / shutdown", variable=self._h_auto_push_var, progress_color=C["purple"], command=self._on_auto_push_toggle).grid(row=20, column=0, columnspan=3, sticky="w", padx=20, pady=5)
        self._h_push_os_var = ctk.BooleanVar(value=True)
        ctk.CTkSwitch(card, text="Include OS State vault in auto-push", variable=self._h_push_os_var, progress_color=C["accent"]).grid(row=21, column=0, columnspan=3, sticky="w", padx=20, pady=5)

        # Actions
        actions_f = ctk.CTkFrame(card, fg_color="transparent")
        actions_f.grid(row=22, column=0, columnspan=3, sticky="w", padx=20, pady=20)
        ctk.CTkButton(actions_f, text="⚡ Hydrate Now", font=("Segoe UI", 13, "bold"), fg_color=C["purple"], hover_color=C["purple2"], command=self._hydrate_now).pack(side="left")
        ctk.CTkButton(actions_f, text="💾 Save Config", fg_color=C["ghost"], hover_color=C["ghost2"], command=self._save_hydrate_config).pack(side="left", padx=(10, 0))
        ctk.CTkButton(actions_f, text="☁ Push to Git Now", fg_color=C["ghost"], hover_color=C["ghost2"], command=self._git_push).pack(side="left", padx=(10, 0))

    def _on_auto_push_toggle(self) -> None:
        enabled = self._h_auto_push_var.get()
        cfg = self._hydrate_config
        if enabled:
            if not (cfg and cfg.git_remote):
                self._log("Auto-push: configure a Git remote URL and save the config first.")
            else:
                self._log("Auto-push enabled — vault will be pushed to Git when ShadowSync closes.")
                self._register_shutdown_hook()
        else:
            self._log("Auto-push disabled.")
            _SHUTDOWN_HOOK.unregister()

    def _register_shutdown_hook(self) -> None:
        """Wire up the shutdown hook to auto-push."""
        def shutdown_push() -> None:
            cfg = self._hydrate_config
            storage = self.storage_var.get().strip()
            if not cfg or not cfg.git_remote or not storage:
                return
            # Count apps
            apps_root = Path(storage) / "apps"
            app_count = sum(1 for p in apps_root.iterdir() if p.is_dir()) if apps_root.exists() else 0
            os_captured = bool(self._os_settings and self._os_settings.captured_at)
            summary = f"{app_count} apps" + (" | OS state" if os_captured else "")
            log_q: queue.Queue = queue.Queue()
            GitPushWorker(Path(storage), cfg, log_q, summary=summary).run()

        _SHUTDOWN_HOOK.register(shutdown_push)

    # ─────────────────────────────────────────────────────────────────────────
    # Common UI helpers
    # ─────────────────────────────────────────────────────────────────────────

    def _toggle_password_visibility(self) -> None:
        self._pw_visible = not self._pw_visible
        self._pw_entry.configure(show="" if self._pw_visible else "●")
        self._pw_eye_btn.configure(text_color=self.C["accent"] if self._pw_visible else self.C["label"])

    def _h_browse_wallpaper(self) -> None:
        path = filedialog.askopenfilename(
            title="Choose wallpaper image",
            filetypes=[("Images", "*.jpg *.jpeg *.png *.webp"), ("All files", "*")],
        )
        if path:
            self._h_wallpaper_var.set(path)

    # ─────────────────────────────────────────────────────────────────────────
    # Hydrate config serialization
    # ─────────────────────────────────────────────────────────────────────────

    def _ui_to_hydrate_config(self) -> HydrateConfig:
        wifi_profiles = []
        for ssid_v, pwd_v in self._h_wifi_vars:
            ssid = ssid_v.get().strip()
            if ssid:
                wifi_profiles.append({"ssid": ssid, "password": pwd_v.get()})
        return HydrateConfig(
            dark_mode=self._h_darkmode_var.get(),
            wallpaper_path=self._h_wallpaper_var.get().strip(),
            wifi_profiles=wifi_profiles,
            git_remote=self._h_git_remote_var.get().strip(),
            git_branch=self._h_git_branch_var.get().strip() or "main",
            git_name=self._h_git_name_var.get().strip(),
            git_email=self._h_git_email_var.get().strip(),
            git_token=self._h_git_token_var.get().strip(),
            git_host=self._h_git_host_var.get().strip(),
            auto_push_on_close=self._h_auto_push_var.get(),
            push_includes_os_state=self._h_push_os_var.get(),
        )

    def _populate_hydrate_fields(self, cfg: HydrateConfig) -> None:
        self._h_darkmode_var.set(cfg.dark_mode)
        self._h_wallpaper_var.set(cfg.wallpaper_path)
        for i, (ssid_v, pwd_v) in enumerate(self._h_wifi_vars):
            if i < len(cfg.wifi_profiles):
                ssid_v.set(cfg.wifi_profiles[i].get("ssid", ""))
                pwd_v.set(cfg.wifi_profiles[i].get("password", ""))
            else:
                ssid_v.set("")
                pwd_v.set("")
        self._h_git_remote_var.set(cfg.git_remote)
        self._h_git_branch_var.set(cfg.git_branch)
        self._h_git_name_var.set(cfg.git_name)
        self._h_git_email_var.set(cfg.git_email)
        self._h_git_token_var.set(cfg.git_token)
        self._h_git_host_var.set(cfg.git_host)
        self._h_auto_push_var.set(cfg.auto_push_on_close)
        self._h_push_os_var.set(cfg.push_includes_os_state)
        self._hydrate_config = cfg
        if cfg.auto_push_on_close and cfg.git_remote:
            self._register_shutdown_hook()

    def _try_autoload_hydrate(self) -> None:
        password = self.password_var.get()
        storage = self.storage_var.get().strip()
        if not password or not storage:
            return
        threading.Thread(target=self._autoload_hydrate_task, daemon=True).start()

    def _autoload_hydrate_task(self) -> None:
        try:
            cfg = HydrateConfig.load(Path(self.storage_var.get()), self.password_var.get())
            self._hydrate_config = cfg
            self.after(0, lambda: self._populate_hydrate_fields(cfg))
            self.log_queue.put("Hydrate config loaded from vault.")
        except ShadowSyncError:
            pass
        except Exception as exc:
            self.log_queue.put(f"Hydrate config auto-load skipped: {exc}")

    # ─────────────────────────────────────────────────────────────────────────
    # Hydrate action handlers
    # ─────────────────────────────────────────────────────────────────────────

    def _hydrate_now(self) -> None:
        if not _IS_LINUX:
            messagebox.showinfo("Hydrate", "GNOME hooks are only available on Linux/Tails.")
            return
        cfg = self._ui_to_hydrate_config()
        self._log("Hydrate: starting personalisation hooks…")
        self._set_busy(True, "Hydrating session…")

        def task() -> None:
            try:
                HydrateWorker(cfg, self.log_queue).run()
            except Exception as exc:
                self.log_queue.put(f"Hydrate error: {exc}")
            finally:
                self.log_queue.put(("busy", False, ""))

        threading.Thread(target=task, daemon=True).start()

    def _save_hydrate_config(self) -> None:
        password = self.password_var.get()
        if not password:
            messagebox.showerror("Hydrate", "Enter the master password first.")
            return
        storage = self.storage_var.get().strip()
        if not storage:
            messagebox.showerror("Hydrate", "Choose the ShadowSync storage folder first.")
            return
        cfg = self._ui_to_hydrate_config()
        self._set_busy(True, "Saving hydrate config…")

        def task() -> None:
            try:
                cfg.save(Path(storage), password)
                self._hydrate_config = cfg
                self.log_queue.put("Hydrate config saved to encrypted vault.")
                if cfg.auto_push_on_close and cfg.git_remote:
                    self.after(0, self._register_shutdown_hook)
            except ShadowSyncError as exc:
                msg = str(exc)
                self.after(0, lambda m=msg: messagebox.showerror("Hydrate", m))
            finally:
                self.log_queue.put(("busy", False, ""))

        threading.Thread(target=task, daemon=True).start()

    def _git_push(self) -> None:
        password = self.password_var.get()
        storage = self.storage_var.get().strip()
        if not password:
            messagebox.showerror("Hydrate", "Enter the master password first.")
            return
        if not storage:
            messagebox.showerror("Hydrate", "Choose the ShadowSync storage folder first.")
            return
        cfg = self._ui_to_hydrate_config()
        if not cfg.git_remote:
            messagebox.showerror("Hydrate", "Enter a Git remote URL.")
            return
        self._log("Git Push: preparing vault commit…")
        self._set_busy(True, "Pushing to Git…")

        def task() -> None:
            try:
                apps_root = Path(storage) / "apps"
                app_count = sum(1 for p in apps_root.iterdir() if p.is_dir()) if apps_root.exists() else 0
                summary = f"{app_count} apps"
                GitPushWorker(Path(storage), cfg, self.log_queue, summary=summary).run()
            except Exception as exc:
                self.log_queue.put(f"Git Push error: {exc}")
            finally:
                self.log_queue.put(("busy", False, ""))

        threading.Thread(target=task, daemon=True).start()

    # ─────────────────────────────────────────────────────────────────────────
    # Browse / vault action handlers
    # ─────────────────────────────────────────────────────────────────────────

    def _preset_changed(self, _event: object) -> None:
        preset_name = self.profile_kind_var.get()
        value = self.presets.get(preset_name, "")
        if value:
            self.profile_var.set(value)
            self.app_name_var.set(preset_name)

    def _browse_storage(self) -> None:
        path = filedialog.askdirectory(title="Choose ShadowSync storage folder")
        if path:
            self.storage_var.set(path)
            self.approved_executable_path = ""
            self.approved_storage_root = ""
            self.sandbox_next_launch = False

    def _browse_profile(self) -> None:
        path = filedialog.askdirectory(title="Choose app profile folder")
        if path:
            self.profile_var.set(path)
            self.profile_kind_var.set("Custom")

    def _browse_executable(self) -> None:
        path = filedialog.askopenfilename(title="Choose app executable or AppImage")
        if path:
            executable = Path(path)
            detected_name = display_app_name(executable.name)

            def accept(sandbox: bool = False) -> None:
                self.exec_var.set(str(executable))
                self.app_name_var.set(detected_name)
                self.approved_executable_path = str(executable.expanduser().resolve())
                self.approved_storage_root = str(Path(self.storage_var.get()).expanduser().resolve())
                self.sandbox_next_launch = sandbox
                self._log(f"Executable accepted: {executable}")

            def reject() -> None:
                self.exec_var.set("")
                self.approved_executable_path = ""
                self.approved_storage_root = ""
                self.sandbox_next_launch = False
                self._log(f"Executable rejected after hash verdict: {executable}")

            self._verify_executable_then(executable, detected_name, accept, reject)

    def _clear_executable_approval(self) -> None:
        self.approved_executable_path = ""
        self.approved_storage_root = ""
        self.sandbox_next_launch = False

    def _mode_changed(self) -> None:
        if self.mode_var.get() == MODE_FUSE:
            self._log("FUSE mode selected. This requires Linux/Tails with gocryptfs.")
        else:
            self._log("DIY sync-on-close mode selected.")
        self._try_autoload_hydrate()

    def _build_run_options(self) -> RunOptions:
        if not self.password_var.get():
            raise ShadowSyncError("Enter the master password first.")
        if not self.exec_var.get():
            raise ShadowSyncError("Choose the app executable or AppImage.")
        executable_path = str(Path(self.exec_var.get()).expanduser().resolve())
        if executable_path != self.approved_executable_path:
            raise ShadowSyncError("Use Browse to select and verify the executable before launching.")
        storage_root = str(Path(self.storage_var.get()).expanduser().resolve())
        if storage_root != self.approved_storage_root:
            raise ShadowSyncError("Storage changed after verification. Re-select the executable with Browse.")
        if not self.profile_var.get():
            raise ShadowSyncError("Choose the profile folder.")
        app_name = self.app_name_var.get().strip()
        if not app_name:
            app_name = infer_app_name(Path(self.exec_var.get()), self.profile_kind_var.get())
            self.app_name_var.set(app_name)
        profile_name = self.profile_name_var.get().strip() or "Default"
        self.profile_name_var.set(profile_name)
        return RunOptions(
            storage_root=Path(self.storage_var.get()),
            app_name=app_name,
            profile_name=profile_name,
            profile_dir=Path(self.profile_var.get()),
            executable=Path(self.exec_var.get()),
            password=self.password_var.get(),
            mode=self.mode_var.get(),
            wipe_after=self.wipe_var.get(),
            sandbox_app=self.sandbox_next_launch,
        )

    def _start(self) -> None:
        if self.worker_thread and self.worker_thread.is_alive():
            messagebox.showinfo("ShadowSync", "ShadowSync is already running.")
            return
        try:
            options = self._build_run_options()
        except ShadowSyncError as exc:
            messagebox.showerror("ShadowSync", str(exc))
            return
        self.worker = ShadowSyncWorker(options, self.log_queue)
        self.worker_thread = threading.Thread(target=self._run_worker, daemon=True)
        self.worker_thread.start()
        C = self.C
        self.state_label.configure(text="Running", text_color=C["run_green"])
        self._status_dot.configure(text_color=C["run_green"])
        self._try_autoload_hydrate()

    def _run_worker(self) -> None:
        try:
            assert self.worker is not None
            self.worker.run()
        except ShadowSyncError as exc:
            message = str(exc)
            self.log_queue.put(f"Error: {message}")
            self.after(0, lambda message=message: messagebox.showerror("ShadowSync", message))
        except Exception as exc:
            message = f"Unexpected error: {exc}"
            self.log_queue.put(message)
            self.after(0, lambda message=message: messagebox.showerror("ShadowSync", message))
        finally:
            self.after(0, lambda: self._set_busy(False))
            self.after(0, lambda: self.state_label.configure(text="Locked"))

    def _save_now(self) -> None:
        try:
            if self.worker and self.worker_thread and self.worker_thread.is_alive():
                self.worker.save_now()
            else:
                options = self._build_run_options()
                if options.mode == MODE_FUSE:
                    raise ShadowSyncError("FUSE mode saves on the fly. Launch it first.")
                self._set_busy(True, "Encrypting portable vault...")

                def save_task() -> None:
                    try:
                        paths = app_storage_paths(options.storage_root, options.app_name, options.profile_name)
                        PortableVault(paths["portable_vault"]).save_from(options.profile_dir.expanduser().resolve(), options.password)
                        self.log_queue.put(f"Encrypted vault saved: {paths['portable_vault']}")
                    except ShadowSyncError as exc:
                        message = str(exc)
                        self.after(0, lambda message=message: messagebox.showerror("ShadowSync", message))
                    finally:
                        self.log_queue.put(("busy", False, ""))

                threading.Thread(target=save_task, daemon=True).start()
        except ShadowSyncError as exc:
            messagebox.showerror("ShadowSync", str(exc))

    # ─────────────────────────────────────────────────────────────────────────
    # Files tab actions
    # ─────────────────────────────────────────────────────────────────────────

    def _add_files_to_vault(self) -> None:
        try:
            password = self._file_vault_password()
        except ShadowSyncError as exc:
            messagebox.showerror("ShadowSync", str(exc))
            return
        paths = [Path(p) for p in filedialog.askopenfilenames(title="Choose files to encrypt")]
        if not paths:
            return
        self._import_manual_items(paths, password)

    def _add_folder_to_vault(self) -> None:
        try:
            password = self._file_vault_password()
        except ShadowSyncError as exc:
            messagebox.showerror("ShadowSync", str(exc))
            return
        path = filedialog.askdirectory(title="Choose folder to encrypt")
        if not path:
            return
        self._import_manual_items([Path(path)], password)

    def _export_files_vault(self) -> None:
        try:
            password = self._file_vault_password()
        except ShadowSyncError as exc:
            messagebox.showerror("ShadowSync", str(exc))
            return
        destination = filedialog.askdirectory(title="Choose export folder")
        if not destination:
            return
        vault = PortableVault(self._get_active_files_vault_path())
        if not vault.exists():
            messagebox.showinfo("ShadowSync", "No manual files vault exists on the selected drive yet.")
            return
        self._set_busy(True, "Decrypting manual files vault...")

        def export_task() -> None:
            try:
                vault.extract_to(Path(destination), password)
                self.log_queue.put(f"Manual files exported to: {destination}")
            except ShadowSyncError as exc:
                message = str(exc)
                self.after(0, lambda message=message: messagebox.showerror("ShadowSync", message))
            finally:
                self.log_queue.put(("busy", False, ""))

        threading.Thread(target=export_task, daemon=True).start()

    def _import_manual_items(self, sources: list[Path], password: str) -> None:
        vault_path = self._get_active_files_vault_path()

        # Check that the target drive/directory is writable before starting
        vault_dir = vault_path.parent
        try:
            vault_dir.mkdir(parents=True, exist_ok=True)
        except (OSError, PermissionError) as exc:
            drive = self._files_drive_var.get() if hasattr(self, "_files_drive_var") else str(vault_dir)
            messagebox.showerror(
                "Files Vault — Write Error",
                f"Cannot create vault directory on drive:\n{vault_dir}\n\n"
                f"Error: {exc}\n\n"
                "The drive may be read-only or unmounted. On Tails, check that the USB drive "
                "is mounted with write access (right-click → Mount in Files Manager).",
            )
            return

        if not os.access(str(vault_dir), os.W_OK):
            drive = self._files_drive_var.get() if hasattr(self, "_files_drive_var") else str(vault_dir)
            messagebox.showerror(
                "Files Vault — Read-Only Drive",
                f"The selected drive is read-only:\n{drive}\n\n"
                "Cannot save encrypted files to a read-only drive.\n\n"
                "On Tails:\n"
                "• Use a USB drive mounted with write access\n"
                "• Or change the TARGET DRIVE to your home folder (~)",
            )
            return

        vault = PortableVault(vault_path)
        self._set_busy(True, "Encrypting manual files vault...")
        self._log(f"Saving vault to: {vault_path}")

        def import_task() -> None:
            staging = Path(tempfile.mkdtemp(prefix="shadowsync-files-"))
            try:
                if vault.exists():
                    vault.restore_to(staging, password)
                added_names = []
                for source in sources:
                    resolved = source.expanduser().resolve()
                    added_names.append(resolved.name)
                    copy_into_unique(resolved, staging)
                vault.save_from(staging, password)
                if vault_path.exists():
                    vault_size = vault_path.stat().st_size
                    size_str = self._format_file_size(vault_size)
                    self.log_queue.put(f"Added {len(sources)} item(s) to drive vault: {', '.join(added_names)}  [vault size: {size_str}]")
                    self.log_queue.put(f"Vault saved at: {vault_path}")
                else:
                    self.log_queue.put(f"Warning: vault file not found after save at {vault_path}")
                self.after(100, self._refresh_files_view)
                self.after(100, self._update_drive_path_label)
            except ShadowSyncError as exc:
                message = str(exc)
                self.log_queue.put(f"Error: {message}")
                self.after(0, lambda message=message: messagebox.showerror("ShadowSync", message))
            except OSError as exc:
                message = f"File import failed: {exc}"
                self.log_queue.put(f"Error: {message}")
                self.after(0, lambda message=message: messagebox.showerror("ShadowSync", message))
            finally:
                wipe_directory(staging)
                self.log_queue.put(("busy", False, ""))


        threading.Thread(target=import_task, daemon=True).start()


    def _file_vault_password(self) -> str:
        password = self.password_var.get()
        if not password:
            raise ShadowSyncError("Enter the master password first.")
        return password

    # ─────────────────────────────────────────────────────────────────────────
    # Worker controls
    # ─────────────────────────────────────────────────────────────────────────

    def _stop_worker(self) -> None:
        if self.worker:
            self.worker.stop()

    def _panic(self) -> None:
        if not self.worker:
            wipe_directory(Path(self.profile_var.get()).expanduser().resolve())
            self._log("Panic cleanup wiped the selected profile folder.")
            self.destroy()
            return
        if self.worker_thread and self.worker_thread.is_alive():
            self.worker.panic()
        self._log("Panic requested. Closing ShadowSync.")
        self.after(250, self.destroy)

    # ─────────────────────────────────────────────────────────────────────────
    # History Tab — Git commit timeline with per-app and per-OS restore
    # ─────────────────────────────────────────────────────────────────────────

    def _build_history_tab(self, parent) -> None:
        C = self.C
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(1, weight=1)

        # Header
        header_card = ctk.CTkFrame(parent, fg_color=C["card"], corner_radius=12)
        header_card.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 0))
        header_card.grid_columnconfigure(0, weight=1)

        title_row = ctk.CTkFrame(header_card, fg_color="transparent")
        title_row.grid(row=0, column=0, sticky="ew", padx=20, pady=(15, 5))
        title_row.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(title_row, text="📜 Backup History — Git Timeline", font=("Segoe UI", 18, "bold"), text_color=C["accent"]).grid(row=0, column=0, sticky="w")
        ctk.CTkButton(title_row, text="🔄 Refresh History", width=140, font=("Segoe UI", 12), fg_color=C["ghost"], hover_color=C["ghost2"], command=self._refresh_history).grid(row=0, column=1, sticky="e")

        ctk.CTkLabel(header_card, text="Each auto-push creates a timestamped branch. Click a commit to see its contents and restore individual app vaults or OS settings.",
                     text_color=C["muted"], font=("Segoe UI", 11), wraplength=780, justify="left").grid(row=1, column=0, sticky="w", padx=20, pady=(0, 15))

        # Commit list (left) + detail panel (right)
        body = ctk.CTkFrame(parent, fg_color="transparent")
        body.grid(row=1, column=0, sticky="nsew", padx=10, pady=(8, 10))
        body.grid_columnconfigure(0, weight=2)
        body.grid_columnconfigure(1, weight=3)
        body.grid_rowconfigure(0, weight=1)

        # ── Left: commit list ──
        commits_card = ctk.CTkFrame(body, fg_color=C["card"], corner_radius=12)
        commits_card.grid(row=0, column=0, sticky="nsew", padx=(0, 5))
        commits_card.grid_columnconfigure(0, weight=1)
        commits_card.grid_rowconfigure(0, weight=1)

        ctk.CTkLabel(commits_card, text="Backup Commits", font=("Segoe UI", 13, "bold"), text_color=C["label"]).pack(anchor="w", padx=15, pady=(12, 5))
        self._history_scroll = ctk.CTkScrollableFrame(commits_card, fg_color="transparent", scrollbar_button_color=C["ghost"])
        self._history_scroll.pack(fill="both", expand=True, padx=5, pady=(0, 10))
        self._history_scroll.grid_columnconfigure(0, weight=1)
        self._history_commits_frame = self._history_scroll

        self._history_empty_label = ctk.CTkLabel(
            self._history_scroll,
            text="No backup history yet.\n\nPush to Git first or click Refresh.",
            font=("Segoe UI", 12), text_color=C["muted"], justify="center",
        )
        self._history_empty_label.grid(row=0, column=0, pady=30)
        self._history_commit_list: List[GitCommitInfo] = []
        self._history_selected_commit: Optional[GitCommitInfo] = None

        # ── Right: detail panel ──
        detail_card = ctk.CTkFrame(body, fg_color=C["card"], corner_radius=12)
        detail_card.grid(row=0, column=1, sticky="nsew", padx=(5, 0))
        detail_card.grid_columnconfigure(0, weight=1)
        detail_card.grid_rowconfigure(1, weight=1)

        detail_header = ctk.CTkFrame(detail_card, fg_color="transparent")
        detail_header.pack(fill="x", padx=15, pady=(12, 5))
        self._history_detail_title = ctk.CTkLabel(detail_header, text="Select a commit →", font=("Segoe UI", 13, "bold"), text_color=C["label"])
        self._history_detail_title.pack(anchor="w")
        self._history_detail_date = ctk.CTkLabel(detail_header, text="", font=("Segoe UI", 11), text_color=C["muted"])
        self._history_detail_date.pack(anchor="w")

        self._history_detail_scroll = ctk.CTkScrollableFrame(detail_card, fg_color="transparent", scrollbar_button_color=C["ghost"])
        self._history_detail_scroll.pack(fill="both", expand=True, padx=5, pady=(0, 10))
        self._history_detail_scroll.grid_columnconfigure(0, weight=1)

    def _refresh_history(self) -> None:
        storage = self.storage_var.get().strip()
        if not storage:
            self._log("Choose the ShadowSync storage folder first.")
            return
        self._log("Loading Git history...")
        self._set_busy(True, "Fetching commit history...")

        def task() -> None:
            try:
                worker = GitHistoryWorker(Path(storage), self.log_queue)
                commits = worker.fetch_commits()
                self.after(0, lambda c=commits: self._render_history(c))
            except Exception as exc:
                self.log_queue.put(f"Git history error: {exc}")
            finally:
                self.log_queue.put(("busy", False, ""))

        threading.Thread(target=task, daemon=True).start()

    def _render_history(self, commits: List[GitCommitInfo]) -> None:
        C = self.C
        frame = self._history_commits_frame
        for w in frame.winfo_children():
            w.destroy()

        self._history_commit_list = commits

        if not commits:
            ctk.CTkLabel(frame, text="No backup history found.\n\nPush to Git with auto-push enabled\nto build a timeline.", font=("Segoe UI", 12), text_color=C["muted"], justify="center").grid(row=0, column=0, pady=30)
            return

        self._log(f"Git history: {len(commits)} backup commit(s) found.")
        for idx, commit in enumerate(commits):
            is_backup = "backup-" in commit.branch
            branch_short = commit.branch.replace("remotes/origin/", "").replace("origin/", "")
            date_short = commit.author_date[:16] if len(commit.author_date) >= 16 else commit.author_date

            row = ctk.CTkFrame(frame, fg_color=C["sidebar"] if idx % 2 == 0 else C["card"], corner_radius=8, cursor="hand2")
            row.grid(row=idx, column=0, sticky="ew", padx=4, pady=3)
            row.grid_columnconfigure(1, weight=1)

            # Branch icon
            icon = "☁" if is_backup else "🔖"
            icon_color = C["accent"] if is_backup else C["purple"]
            ctk.CTkLabel(row, text=icon, font=("Segoe UI", 16), text_color=icon_color, width=30).grid(row=0, column=0, padx=(10, 5), pady=10, rowspan=2)

            ctk.CTkLabel(row, text=branch_short, font=("Segoe UI", 11, "bold"), text_color=C["text"], anchor="w").grid(row=0, column=1, sticky="w", padx=5, pady=(10, 0))
            subject_short = commit.subject[:60] + ("…" if len(commit.subject) > 60 else "")
            ctk.CTkLabel(row, text=subject_short, font=("Segoe UI", 10), text_color=C["muted"], anchor="w").grid(row=1, column=1, sticky="w", padx=5, pady=(0, 10))

            badges = ctk.CTkFrame(row, fg_color="transparent")
            badges.grid(row=0, column=2, rowspan=2, padx=(5, 10), pady=8)
            if commit.has_apps:
                ctk.CTkLabel(badges, text=f"📦 {len(commit.app_names)}", font=("Segoe UI", 10), text_color=C["green"], width=50).pack()
            if commit.has_os:
                ctk.CTkLabel(badges, text="🖥 OS", font=("Segoe UI", 10), text_color=C["purple"], width=50).pack()

            ctk.CTkLabel(row, text=date_short, font=("Segoe UI", 9), text_color=C["log_ts"], width=110, anchor="e").grid(row=0, column=3, rowspan=2, padx=(0, 10), pady=10)

            row.bind("<Button-1>", lambda e, c=commit: self._select_history_commit(c))
            for child in row.winfo_children():
                child.bind("<Button-1>", lambda e, c=commit: self._select_history_commit(c))

    def _select_history_commit(self, commit: GitCommitInfo) -> None:
        C = self.C
        self._history_selected_commit = commit
        branch_short = commit.branch.replace("remotes/origin/", "").replace("origin/", "")
        self._history_detail_title.configure(text=f"🔍 {branch_short}", text_color=C["accent"])
        self._history_detail_date.configure(text=f"{commit.author_date[:19]}  •  commit {commit.commit_hash[:8]}")

        detail_frame = self._history_detail_scroll
        for w in detail_frame.winfo_children():
            w.destroy()

        row_idx = 0

        # ── Subject ──
        ctk.CTkLabel(detail_frame, text="Commit message", font=("Segoe UI", 11, "bold"), text_color=C["label"]).grid(row=row_idx, column=0, sticky="w", padx=10, pady=(10, 2))
        row_idx += 1
        ctk.CTkLabel(detail_frame, text=commit.subject, font=("Segoe UI", 11), text_color=C["text"], wraplength=400, justify="left").grid(row=row_idx, column=0, sticky="w", padx=10, pady=(0, 10))
        row_idx += 1

        # ── OS State restore ──
        if commit.has_os:
            os_card = ctk.CTkFrame(detail_frame, fg_color=C["sidebar"], corner_radius=8)
            os_card.grid(row=row_idx, column=0, sticky="ew", padx=8, pady=5)
            os_card.grid_columnconfigure(0, weight=1)
            row_idx += 1
            ctk.CTkLabel(os_card, text="🖥 OS Settings", font=("Segoe UI", 13, "bold"), text_color=C["green"]).grid(row=0, column=0, sticky="w", padx=15, pady=(12, 5))
            ctk.CTkLabel(os_card, text="WiFi profiles, wallpaper, env vars, installed apps, shell config", font=("Segoe UI", 10), text_color=C["muted"]).grid(row=1, column=0, sticky="w", padx=15, pady=(0, 5))
            ctk.CTkButton(
                os_card, text="♻️ Restore OS Settings from this commit",
                font=("Segoe UI", 11), fg_color=C["green"], text_color="#000", hover_color=C["green2"],
                command=lambda c=commit: self._restore_os_from_commit(c),
            ).grid(row=2, column=0, sticky="w", padx=15, pady=(5, 12))

        # ── App vaults ──
        if commit.app_names:
            ctk.CTkLabel(detail_frame, text=f"📦 Apps in this backup ({len(commit.app_names)})", font=("Segoe UI", 13, "bold"), text_color=C["accent"]).grid(row=row_idx, column=0, sticky="w", padx=10, pady=(10, 5))
            row_idx += 1

            for app_safe_name in commit.app_names:
                app_display = display_app_name(app_safe_name)
                app_card = ctk.CTkFrame(detail_frame, fg_color=C["sidebar"], corner_radius=8)
                app_card.grid(row=row_idx, column=0, sticky="ew", padx=8, pady=4)
                app_card.grid_columnconfigure(0, weight=1)
                row_idx += 1

                info_row = ctk.CTkFrame(app_card, fg_color="transparent")
                info_row.grid(row=0, column=0, sticky="ew", padx=12, pady=(10, 5))
                info_row.grid_columnconfigure(0, weight=1)
                ctk.CTkLabel(info_row, text=f"📦 {app_display}", font=("Segoe UI", 12, "bold"), text_color=C["text"]).grid(row=0, column=0, sticky="w")
                ctk.CTkLabel(info_row, text=f"({app_safe_name})", font=("Segoe UI", 10), text_color=C["muted"]).grid(row=1, column=0, sticky="w")

                btn_row = ctk.CTkFrame(app_card, fg_color="transparent")
                btn_row.grid(row=1, column=0, sticky="w", padx=12, pady=(0, 10))
                ctk.CTkButton(
                    btn_row, text="♻️ Restore Default Profile",
                    width=170, font=("Segoe UI", 11), fg_color=C["accent"], text_color="#000", hover_color=C["accent2"],
                    command=lambda c=commit, a=app_safe_name: self._restore_app_from_commit(c, a, "Default"),
                ).pack(side="left", padx=(0, 8))
                ctk.CTkButton(
                    btn_row, text="📂 Restore to Folder…",
                    width=150, font=("Segoe UI", 11), fg_color=C["ghost"], hover_color=C["ghost2"],
                    command=lambda c=commit, a=app_safe_name: self._restore_app_from_commit_pick(c, a),
                ).pack(side="left")

        if not commit.has_os and not commit.app_names:
            ctk.CTkLabel(detail_frame, text="This commit has no app vaults or OS settings.", font=("Segoe UI", 12), text_color=C["muted"]).grid(row=row_idx, column=0, padx=10, pady=20)

    def _restore_app_from_commit(self, commit: GitCommitInfo, app_safe_name: str, profile_name: str = "Default") -> None:
        password = self.password_var.get()
        storage = self.storage_var.get().strip()
        if not password:
            messagebox.showerror("History", "Enter the master password first.")
            return
        if not storage:
            messagebox.showerror("History", "Choose the ShadowSync storage folder.")
            return
        destination = Path(storage) / "apps" / app_safe_name / "profiles" / profile_name / "restored_data"
        if not messagebox.askyesno("History — Restore App",
            f"Restore '{display_app_name(app_safe_name)}' ({profile_name}) from commit {commit.commit_hash[:8]}?\n\n"
            f"Files will be extracted to:\n{destination}\n\n"
            "Existing files will NOT be overwritten."):
            return
        self._set_busy(True, f"Restoring {display_app_name(app_safe_name)} from history…")

        def task() -> None:
            try:
                worker = GitRestoreWorker(Path(storage), self.log_queue)
                ok = worker.restore_app_vault(commit.commit_hash, app_safe_name, profile_name, destination, password)
                if ok:
                    self.log_queue.put(f"App '{display_app_name(app_safe_name)}' restored from commit {commit.commit_hash[:8]} → {destination}")
                else:
                    self.log_queue.put(f"Restore failed for '{app_safe_name}' — vault not found in that commit.")
            except Exception as exc:
                self.log_queue.put(f"Restore error: {exc}")
            finally:
                self.log_queue.put(("busy", False, ""))

        threading.Thread(target=task, daemon=True).start()

    def _restore_app_from_commit_pick(self, commit: GitCommitInfo, app_safe_name: str) -> None:
        password = self.password_var.get()
        storage = self.storage_var.get().strip()
        if not password:
            messagebox.showerror("History", "Enter the master password first.")
            return
        destination = filedialog.askdirectory(title=f"Restore {display_app_name(app_safe_name)} to folder")
        if not destination:
            return
        self._set_busy(True, f"Restoring {display_app_name(app_safe_name)}…")

        def task() -> None:
            try:
                worker = GitRestoreWorker(Path(storage), self.log_queue)
                # Try all profiles
                paths_root = Path(storage) / "apps" / app_safe_name / "profiles"
                profiles_tried = []
                r = subprocess.run(
                    ["git", "-C", storage, "ls-tree", "--name-only", f"{commit.commit_hash}:apps/{app_safe_name}/profiles"],
                    capture_output=True, text=True, check=False,
                )
                profile_names = [n.strip() for n in r.stdout.splitlines() if n.strip()] if r.returncode == 0 else ["Default"]
                for pname in profile_names:
                    ok = worker.restore_app_vault(commit.commit_hash, app_safe_name, pname, Path(destination) / pname, password)
                    if ok:
                        profiles_tried.append(pname)
                if profiles_tried:
                    self.log_queue.put(f"Restored profiles: {', '.join(profiles_tried)} → {destination}")
                else:
                    self.log_queue.put(f"No profiles found in commit {commit.commit_hash[:8]} for {app_safe_name}.")
            except Exception as exc:
                self.log_queue.put(f"Restore error: {exc}")
            finally:
                self.log_queue.put(("busy", False, ""))

        threading.Thread(target=task, daemon=True).start()

    def _restore_os_from_commit(self, commit: GitCommitInfo) -> None:
        password = self.password_var.get()
        storage = self.storage_var.get().strip()
        if not password:
            messagebox.showerror("History", "Enter the master password first.")
            return
        if not messagebox.askyesno("History — Restore OS Settings",
            f"Restore OS settings from commit {commit.commit_hash[:8]}?\n\n"
            "This will:\n• Load WiFi profiles from that snapshot\n• Update the OS State tab fields\n• NOT immediately apply to the OS (use OS State → Restore for that)"):
            return
        self._set_busy(True, "Restoring OS settings from history…")

        def task() -> None:
            try:
                worker = GitRestoreWorker(Path(storage), self.log_queue)
                settings = worker.restore_os_vault(commit.commit_hash, Path(storage), password)
                if settings:
                    self.after(0, lambda s=settings: self._populate_os_fields(s))
                    self.log_queue.put(f"OS settings loaded from commit {commit.commit_hash[:8]}. "
                                       f"Review in the OS State tab, then click 'Restore from Vault' to apply.")
                else:
                    self.log_queue.put(f"OS settings vault not found in commit {commit.commit_hash[:8]}.")
            except Exception as exc:
                self.log_queue.put(f"OS restore from history error: {exc}")
            finally:
                self.log_queue.put(("busy", False, ""))

        threading.Thread(target=task, daemon=True).start()

    def _on_close(self) -> None:
        """Handle window close — optionally auto-push before exiting."""
        if self.worker and self.worker_thread and self.worker_thread.is_alive():
            if not messagebox.askyesno("ShadowSync", "Stop the running app and close ShadowSync?"):
                return
            self.worker.stop()

        cfg = self._hydrate_config
        storage = self.storage_var.get().strip()
        password = self.password_var.get()

        if cfg and cfg.auto_push_on_close and cfg.git_remote and storage and password:
            if messagebox.askyesno(
                "ShadowSync — Auto Push",
                "Auto-push is enabled.\n\nPush vault to Git before closing?\n(This may take a few seconds)",
                icon="question",
            ):
                self._do_auto_push_then_close(cfg, storage, password)
                return

        self.destroy()

    def _do_auto_push_then_close(self, cfg: HydrateConfig, storage: str, password: str) -> None:
        """Show a progress dialog, push in background, then destroy."""
        C = self.C
        dlg = ctk.CTkToplevel(self)
        dlg.title("Auto-pushing…")
        dlg.geometry("420x140")
        dlg.configure(fg_color=C["bg"])
        dlg.transient(self)
        dlg.grab_set()
        ctk.CTkLabel(dlg, text="☁ Pushing vault to Git…", font=("Segoe UI", 14, "bold"), text_color=C["accent"]).pack(pady=(20, 10))
        bar = ctk.CTkProgressBar(dlg, mode="indeterminate", progress_color=C["accent"])
        bar.pack(fill="x", padx=30, pady=5)
        bar.start()
        self._push_status_label = ctk.CTkLabel(dlg, text="Preparing…", font=("Segoe UI", 11), text_color=C["muted"])
        self._push_status_label.pack()

        def task() -> None:
            log_q: queue.Queue = queue.Queue()
            try:
                apps_root = Path(storage) / "apps"
                app_count = sum(1 for p in apps_root.iterdir() if p.is_dir()) if apps_root.exists() else 0
                os_state_note = " | OS state" if (self._os_settings and self._os_settings.captured_at) else ""
                summary = f"{app_count} apps{os_state_note}"
                GitPushWorker(Path(storage), cfg, log_q, summary=summary).run()
                # Drain log
                msgs = []
                while not log_q.empty():
                    msgs.append(str(log_q.get_nowait()))
                last = msgs[-1] if msgs else "Done."
                self.after(0, lambda m=last: self._push_status_label.configure(text=m, text_color=self.C["log_ok"]))
            except Exception as exc:
                self.after(0, lambda e=str(exc): self._push_status_label.configure(text=f"Push error: {e}", text_color=self.C["log_err"]))
            finally:
                bar.stop()
                self.after(1200, lambda: (dlg.destroy(), self.destroy()))

        threading.Thread(target=task, daemon=True).start()

    # ─────────────────────────────────────────────────────────────────────────
    # Log / drain
    # ─────────────────────────────────────────────────────────────────────────

    def _drain_log(self) -> None:
        while True:
            try:
                message = self.log_queue.get_nowait()
            except queue.Empty:
                break
            if isinstance(message, tuple) and message and message[0] == "busy":
                _tag, active, text = message
                self._set_busy(bool(active), str(text))
            elif isinstance(message, tuple) and message and message[0] == "heartbeat":
                self._pulse_heartbeat()
            else:
                self._log(str(message))
        self.after(150, self._drain_log)

    def _log(self, message: str) -> None:
        timestamp = time.strftime("%H:%M:%S")
        msg_lower = message.lower()
        if "error" in msg_lower or "wrong" in msg_lower or "fail" in msg_lower or "blocked" in msg_lower:
            body_tag = "err"
        elif "done" in msg_lower or "saved" in msg_lower or "trusted" in msg_lower or "locked" in msg_lower or "mounted" in msg_lower or "restored" in msg_lower or "captured" in msg_lower:
            body_tag = "ok"
        elif "warning" in msg_lower or "skipped" in msg_lower or "panic" in msg_lower:
            body_tag = "warn"
        elif "ready" in msg_lower or "scanning" in msg_lower or "calculating" in msg_lower or "loading" in msg_lower:
            body_tag = "info"
        else:
            body_tag = "body"
        self.log_text.insert("end", f"[{timestamp}] ", "ts")
        self.log_text.insert("end", f"{message}\n", body_tag)
        self.log_text.see("end")

    def _set_busy(self, active: bool, message: str = "") -> None:
        C = self.C
        if active:
            self.progress.grid()
            self.progress.start(12)
            self.state_label.configure(text=message or "Working", text_color=C["accent"])
            self._status_dot.configure(text_color=C["accent"])
        else:
            self.progress.stop()
            self.progress.grid_remove()
            if self.worker_thread and self.worker_thread.is_alive():
                self.state_label.configure(text="Running", text_color=C["run_green"])
                self._status_dot.configure(text_color=C["run_green"])
            else:
                self.state_label.configure(text="Locked", text_color=C["lock_blue"])
                self._status_dot.configure(text_color=C["lock_blue"])

    def _verify_executable_then(self, executable: Path, app_name: str, on_accept, on_reject=None) -> None:
        password = self.password_var.get()
        if not password:
            messagebox.showerror("ShadowSync", "Enter the master password before selecting an executable.")
            return
        storage_root = Path(self.storage_var.get())
        self._set_busy(True, "Scanning executable...")
        self._log(f"Calculating SHA-256 for {executable.name}...")

        def verify_task() -> None:
            try:
                verdict = verify_executable_hash(executable, app_name, storage_root, password)
            except (OSError, ShadowSyncError) as exc:
                message = f"Could not scan executable: {exc}"
                self.after(0, lambda message=message: messagebox.showerror("ShadowSync", message))
                self.log_queue.put(("busy", False, ""))
                return
            self.log_queue.put(("busy", False, ""))
            self.after(0, lambda verdict=verdict: self._show_security_verdict(verdict, executable, on_accept, on_reject))

        threading.Thread(target=verify_task, daemon=True).start()

    def _show_security_verdict(self, verdict: SecurityVerdict, executable: Path, on_accept, on_reject=None) -> None:
        if verdict.status == VERDICT_MISMATCH:
            messagebox.showerror("Corrupted or Tampered", security_verdict_message(verdict))
            self._log(f"Executable blocked: {verdict.sha256}")
            if on_reject:
                on_reject()
            return
        if verdict.status == VERDICT_VERIFIED:
            accepted = messagebox.askyesno("Trusted Executable", security_verdict_message(verdict), icon="info")
            sandbox = False
        else:
            accepted = messagebox.askyesno("First-Time Execution Warning", security_verdict_message(verdict), icon="warning")
            sandbox = True
        self._log(f"Executable scan verdict: {verdict.title} ({verdict.sha256})")
        if accepted:
            if verdict.status == VERDICT_FIRST_RUN:
                try:
                    registry = TofuRegistry(Path(self.storage_var.get()))
                    registry.load(self.password_var.get())
                    registry.trust(verdict.app_name, executable, verdict.sha256)
                    registry.save(self.password_var.get())
                    self._log(f"TOFU registry locked signature for {verdict.app_name}.")
                except ShadowSyncError as exc:
                    messagebox.showerror("ShadowSync", str(exc))
                    if on_reject:
                        on_reject()
                    return
            on_accept(sandbox)
        elif on_reject:
            on_reject()

    def _pulse_heartbeat(self) -> None:
        C = self.C
        self.heartbeat_dot.configure(text="● Heartbeat saved", text_color=C["run_green"])
        self.after(1200, lambda: self.heartbeat_dot.configure(text="● Heartbeat active", text_color=C["accent"]))

    def _refresh_profile_names(self) -> None:
        app_name = self.app_name_var.get().strip() or "CustomApp"
        paths = app_storage_paths(Path(self.storage_var.get()), app_name)
        profiles_root = paths["app_root"] / "profiles"
        names = ["Default"]
        if profiles_root.exists():
            names.extend(sorted(p.name for p in profiles_root.iterdir() if p.is_dir() and p.name != "Default"))
        self.profile_combo.configure(values=names)
        if self.profile_name_var.get() not in names:
            self.profile_name_var.set("Default")
        self._log(f"Loaded {len(names)} profile slot(s) for {app_name}.")

    def _start_appimage_scan(self) -> None:
        threading.Thread(target=self._scan_appimages, daemon=True).start()

    def _scan_appimages(self) -> None:
        storage_root = Path(self.storage_var.get()).expanduser().resolve()
        existing = self._existing_app_names(storage_root)
        candidates = []
        try:
            for path in self._iter_appimage_scan_paths():
                if path.is_file() and path.name.lower().endswith(".appimage"):
                    app_name = display_app_name(path.name)
                    if sanitize_app_name(app_name) not in existing:
                        candidates.append((app_name, path.resolve()))
        except OSError:
            return
        if candidates:
            app_name, path = candidates[0]
            self.after(0, lambda: self._prompt_new_appimage(app_name, path))

    def _iter_appimage_scan_paths(self):
        roots = self._appimage_scan_roots()
        seen_roots = set()
        for root in roots:
            try:
                resolved = root.expanduser().resolve()
            except OSError:
                continue
            if resolved in seen_roots or not resolved.exists():
                continue
            seen_roots.add(resolved)
            yield from depth_limited_files(resolved, APPIMAGE_SCAN_DEPTH)

    def _appimage_scan_roots(self) -> list[Path]:
        cwd = Path.cwd()
        roots = [cwd, cwd / "Apps", cwd / "AppImages", cwd / "Downloads"]
        downloads = Path.home() / "Downloads"
        if downloads != cwd / "Downloads":
            roots.append(downloads)
        return roots

    def _existing_app_names(self, storage_root: Path) -> set[str]:
        apps_root = storage_root / "apps"
        if not apps_root.exists():
            return set()
        return {p.name for p in apps_root.iterdir() if p.is_dir()}

    def _prompt_new_appimage(self, app_name: str, path: Path) -> None:
        if self.worker_thread and self.worker_thread.is_alive():
            return
        self._log(f"New AppImage detected: {app_name}. Running hash verification...")
        if not self.password_var.get():
            self._log(f"Detected {app_name}. Enter the master password, then select it with Browse to Trust & Lock.")
            return

        def accept(sandbox: bool = False) -> None:
            self.app_name_var.set(app_name)
            self.profile_name_var.set("Default")
            self.exec_var.set(str(path))
            self.approved_executable_path = str(path.expanduser().resolve())
            self.approved_storage_root = str(Path(self.storage_var.get()).expanduser().resolve())
            self.sandbox_next_launch = sandbox
            guessed_path = guess_profile_path(app_name)
            self.profile_var.set(guessed_path)
            self.profile_kind_var.set("Custom")
            self._refresh_profile_names()
            self._highlight_profile_path()
            self._log(f"Auto-configured {app_name}. Review the highlighted profile path before launch.")

        def reject() -> None:
            self.approved_executable_path = ""
            self.approved_storage_root = ""
            self.sandbox_next_launch = False
            self._log(f"Detected {app_name}, setup skipped after hash verdict.")

        self._verify_executable_then(path, app_name, accept, reject)

    def _highlight_profile_path(self) -> None:
        entry = getattr(self, "profile_entry", None)
        if not entry:
            return
        entry.focus_set()
        entry.selection_range(0, "end")

    # ─────────────────────────────────────────────────────────────────────────
    # Storage scan
    # ─────────────────────────────────────────────────────────────────────────

    def _start_storage_scan(self) -> None:
        current = Path(self.storage_var.get()).expanduser().resolve()
        if current.exists() and is_valid_shadowsync_store(current):
            self._log(f"Storage folder found at: {current}")
            self._update_drive_label(current)
            return
        self._log("Scanning drives for ShadowSync storage...")
        threading.Thread(target=self._scan_storage_roots, daemon=True).start()

    def _scan_storage_roots(self) -> None:
        try:
            stores = find_shadowsync_stores(max_depth=3)
        except Exception as exc:
            self.log_queue.put(f"Storage scan error: {exc}")
            return
        if not stores:
            self.log_queue.put("No existing ShadowSync storage found. Using default location.")
            return
        if len(stores) == 1:
            store = stores[0]
            self.log_queue.put(f"Auto-detected storage: {store}")
            self.after(0, lambda s=str(store): self._apply_detected_storage(s))
        else:
            self.log_queue.put(f"Found {len(stores)} ShadowSync storage locations.")
            self.after(0, lambda ss=stores: self._prompt_detected_storage(ss))

    def _apply_detected_storage(self, path: str) -> None:
        self.storage_var.set(path)
        self.approved_executable_path = ""
        self.approved_storage_root = ""
        self.sandbox_next_launch = False
        self._log(f"Storage folder auto-set to: {path}")
        self._update_drive_label(Path(path))

    def _update_drive_label(self, path: Path) -> None:
        try:
            drive = path.anchor or str(path)
            self._drive_label.configure(text=f"💾 Drive: {drive}")
        except Exception:
            pass

    def _prompt_detected_storage(self, stores: list[Path]) -> None:
        C = self.C
        dialog = ctk.CTkToplevel(self)
        dialog.title("ShadowSync — Select Storage")
        dialog.geometry("620x440")
        dialog.configure(fg_color=C["bg"])
        dialog.transient(self)
        dialog.grab_set()
        dialog.lift()
        dialog.focus_force()

        ctk.CTkLabel(dialog, text="🔍 Multiple Storage Locations Found", font=("Segoe UI", 16, "bold"), text_color=C["accent"]).pack(padx=20, pady=(20, 5))
        ctk.CTkLabel(dialog, text="ShadowSync found encrypted vaults on multiple drives.\nSelect which one to use:", text_color=C["muted"], font=("Segoe UI", 11)).pack(padx=20, pady=(0, 15))

        scroll = ctk.CTkScrollableFrame(dialog, fg_color=C["card"], corner_radius=10)
        scroll.pack(fill="both", expand=True, padx=20, pady=(0, 15))
        scroll.grid_columnconfigure(0, weight=1)

        selected_var = ctk.StringVar(value=str(stores[0]))

        for idx, store in enumerate(stores):
            store_str = str(store)
            apps_dir = store / "apps"
            app_count = 0
            if apps_dir.exists():
                app_count = sum(1 for p in apps_dir.iterdir() if p.is_dir())
            files_vault = store / "files" / "manual-files.ssvault"
            has_files = files_vault.exists()
            os_vault = store / "os_settings" / "os_state.ssvault"
            has_os = os_vault.exists()

            parts = []
            if app_count:
                parts.append(f"{app_count} app{'s' if app_count != 1 else ''}")
            if has_files:
                parts.append("files vault")
            if has_os:
                parts.append("OS state")
            if (store / "user_registry.enc").exists():
                parts.append("TOFU registry")
            detail = ", ".join(parts) if parts else "empty store"

            row = ctk.CTkFrame(scroll, fg_color=C["sidebar"], corner_radius=8)
            row.grid(row=idx, column=0, sticky="ew", padx=5, pady=4)
            row.grid_columnconfigure(1, weight=1)
            ctk.CTkRadioButton(row, text="", variable=selected_var, value=store_str, fg_color=C["accent"], border_color=C["ghost"], width=20).grid(row=0, column=0, padx=(15, 5), pady=12, rowspan=2)
            ctk.CTkLabel(row, text=store_str, font=("Segoe UI", 12, "bold"), text_color=C["text"], anchor="w").grid(row=0, column=1, sticky="w", padx=5, pady=(12, 0))
            ctk.CTkLabel(row, text=f"📦 {detail}", font=("Segoe UI", 11), text_color=C["muted"], anchor="w").grid(row=1, column=1, sticky="w", padx=5, pady=(0, 12))

        btn_frame = ctk.CTkFrame(dialog, fg_color="transparent")
        btn_frame.pack(padx=20, pady=(0, 20))

        def apply_selection() -> None:
            self._apply_detected_storage(selected_var.get())
            dialog.destroy()

        def use_default() -> None:
            self._log("Using default storage location.")
            dialog.destroy()

        ctk.CTkButton(btn_frame, text="✓ Use Selected", font=("Segoe UI", 13, "bold"), fg_color=C["accent"], text_color="#000", hover_color=C["accent2"], command=apply_selection).pack(side="left", padx=(0, 10))
        ctk.CTkButton(btn_frame, text="Use Default", fg_color=C["ghost"], hover_color=C["ghost2"], command=use_default).pack(side="left")

    # ─────────────────────────────────────────────────────────────────────────
    # Files view rendering
    # ─────────────────────────────────────────────────────────────────────────

    def _toggle_files_view_mode(self) -> None:
        if self._files_view_mode == "list":
            self._files_view_mode = "grid"
            self._view_toggle_btn.configure(text="▦ Grid")
        else:
            self._files_view_mode = "list"
            self._view_toggle_btn.configure(text="☰ List")
        self._render_files_view()

    def _refresh_files_view(self) -> None:
        password = self.password_var.get()
        if not password:
            self._log("Enter the master password to view vault contents.")
            return
        vault_path = self._get_active_files_vault_path()
        vault = PortableVault(vault_path)
        if not vault.exists():
            self._files_manifest = []
            self._render_files_view()
            self._update_files_status()
            return
        self._set_busy(True, "Loading vault contents...")
        self._log(f"Scanning vault on {self._files_drive_var.get() if hasattr(self, '_files_drive_var') else 'drive'}…")

        def scan_task() -> None:
            staging = Path(tempfile.mkdtemp(prefix="shadowsync-scan-"))
            try:
                vault.restore_to(staging, password)
                manifest = []
                for item in sorted(staging.iterdir(), key=lambda p: (p.is_file(), p.name.lower())):
                    entry = {
                        "name": item.name,
                        "is_dir": item.is_dir(),
                        "size": self._dir_size(item) if item.is_dir() else item.stat().st_size,
                        "children": sum(1 for _ in item.rglob("*")) if item.is_dir() else 0,
                    }
                    if item.is_file():
                        lower = item.name.lower()
                        entry["is_app"] = lower.endswith((".appimage", ".exe", ".app"))
                    else:
                        entry["is_app"] = False
                    manifest.append(entry)
                self._files_manifest = manifest
                self.log_queue.put(f"Vault scan complete: {len(manifest)} item(s) found.")
            except ShadowSyncError as exc:
                self.log_queue.put(f"Error scanning vault: {exc}")
                self._files_manifest = []
            finally:
                wipe_directory(staging)
                self.log_queue.put(("busy", False, ""))
                self.after(0, self._render_files_view)
                self.after(0, self._update_files_status)

        threading.Thread(target=scan_task, daemon=True).start()

    def _render_files_view(self) -> None:
        scroll = self._files_scroll
        for widget in scroll.winfo_children():
            widget.destroy()

        if not self._files_manifest:
            C = self.C
            ctk.CTkLabel(scroll, text="\n\n📭  Vault is empty\n\nAdd files or folders with the buttons above.\nThey will be encrypted and stored securely.", font=("Segoe UI", 13), text_color=C["muted"], justify="center").grid(row=0, column=0, sticky="nsew", pady=40)
            return

        if self._files_view_mode == "list":
            self._render_list_view(scroll)
        else:
            self._render_grid_view(scroll)

    def _render_list_view(self, parent) -> None:
        C = self.C
        header = ctk.CTkFrame(parent, fg_color=C["ghost"], corner_radius=6, height=32)
        header.grid(row=0, column=0, sticky="ew", padx=5, pady=(5, 2))
        header.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(header, text="  ", width=35, font=("Segoe UI", 11), text_color=C["muted"]).grid(row=0, column=0, padx=(10, 0), pady=6)
        ctk.CTkLabel(header, text="Name", font=("Segoe UI", 11, "bold"), text_color=C["muted"], anchor="w").grid(row=0, column=1, sticky="w", padx=5, pady=6)
        ctk.CTkLabel(header, text="Type", width=80, font=("Segoe UI", 11, "bold"), text_color=C["muted"]).grid(row=0, column=2, padx=5, pady=6)
        ctk.CTkLabel(header, text="Size", width=80, font=("Segoe UI", 11, "bold"), text_color=C["muted"]).grid(row=0, column=3, padx=(5, 15), pady=6)

        for idx, item in enumerate(self._files_manifest):
            row_frame = ctk.CTkFrame(parent, fg_color=C["card"] if idx % 2 == 0 else C["sidebar"], corner_radius=6, height=38)
            row_frame.grid(row=idx + 1, column=0, sticky="ew", padx=5, pady=1)
            row_frame.grid_columnconfigure(1, weight=1)
            if item["is_app"]:
                icon, icon_color = "📦", C["purple"]
            elif item["is_dir"]:
                icon, icon_color = "📁", "#f59e0b"
            else:
                icon, icon_color = "📄", C["accent"]
            ctk.CTkLabel(row_frame, text=icon, width=35, font=("Segoe UI", 14), text_color=icon_color).grid(row=0, column=0, padx=(10, 0), pady=8)
            ctk.CTkLabel(row_frame, text=item["name"], font=("Segoe UI", 12), text_color=C["text"], anchor="w").grid(row=0, column=1, sticky="w", padx=5, pady=8)
            if item["is_app"]:
                type_text = "App"
            elif item["is_dir"]:
                type_text = f"Folder ({item['children']})"
            else:
                type_text = "File"
            ctk.CTkLabel(row_frame, text=type_text, width=80, font=("Segoe UI", 11), text_color=C["muted"]).grid(row=0, column=2, padx=5, pady=8)
            size_str = self._format_file_size(item["size"])
            ctk.CTkLabel(row_frame, text=size_str, width=80, font=("Segoe UI", 11), text_color=C["muted"]).grid(row=0, column=3, padx=(5, 15), pady=8)

    def _render_grid_view(self, parent) -> None:
        C = self.C
        cols = 4
        for i in range(cols):
            parent.grid_columnconfigure(i, weight=1)
        for idx, item in enumerate(self._files_manifest):
            row = idx // cols
            col = idx % cols
            card = ctk.CTkFrame(parent, fg_color=C["sidebar"], corner_radius=10, width=140, height=120)
            card.grid(row=row, column=col, padx=6, pady=6, sticky="nsew")
            card.grid_propagate(False)
            card.grid_columnconfigure(0, weight=1)
            if item["is_app"]:
                icon, icon_color = "📦", C["purple"]
            elif item["is_dir"]:
                icon, icon_color = "📁", "#f59e0b"
            else:
                icon, icon_color = "📄", C["accent"]
            ctk.CTkLabel(card, text=icon, font=("Segoe UI", 28), text_color=icon_color).grid(row=0, column=0, pady=(15, 5))
            name = item["name"]
            display_name = name if len(name) <= 16 else name[:14] + "…"
            ctk.CTkLabel(card, text=display_name, font=("Segoe UI", 11), text_color=C["text"]).grid(row=1, column=0, padx=8)
            size_str = self._format_file_size(item["size"])
            ctk.CTkLabel(card, text=size_str, font=("Segoe UI", 10), text_color=C["muted"]).grid(row=2, column=0, pady=(0, 10))

    def _update_files_status(self) -> None:
        if self._files_status_label is None:
            return
        count = len(self._files_manifest)
        vault_path = self._get_active_files_vault_path()
        if vault_path.exists():
            vault_size = self._format_file_size(vault_path.stat().st_size)
            text = f"{count} item{'s' if count != 1 else ''}  •  Vault size: {vault_size}  •  Drive: {self._files_drive_var.get() if hasattr(self, '_files_drive_var') else '—'}"
        elif count == 0:
            text = "0 items  •  No vault on selected drive"
        else:
            text = f"{count} item{'s' if count != 1 else ''}  •  Vault file missing"
        self._files_status_label.configure(text=text)

    @staticmethod
    def _format_file_size(size_bytes: int) -> str:
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes / (1024 * 1024):.1f} MB"
        else:
            return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"

    @staticmethod
    def _dir_size(path: Path) -> int:
        total = 0
        try:
            for f in path.rglob("*"):
                if f.is_file():
                    total += f.stat().st_size
        except OSError:
            pass
        return total

    # ─────────────────────────────────────────────────────────────────────────
    # Stored Apps panel
    # ─────────────────────────────────────────────────────────────────────────

    def _refresh_stored_apps(self) -> None:
        storage = self.storage_var.get().strip()
        if not storage:
            self._log("Choose the ShadowSync storage folder first.")
            return
        apps_root = Path(storage).expanduser().resolve() / "apps"
        frame = self._stored_apps_frame
        if frame is None:
            return

        for widget in frame.winfo_children():
            widget.destroy()

        if not apps_root.exists() or not any(apps_root.iterdir()):
            C = self.C
            ctk.CTkLabel(frame, text="No stored app vaults found. Launch an app with ShadowSync to create one.", text_color=C["muted"], font=("Segoe UI", 11)).grid(row=0, column=0, sticky="w", padx=5, pady=5)
            return

        C = self.C
        row_idx = 0
        for app_dir in sorted(apps_root.iterdir()):
            if not app_dir.is_dir():
                continue
            app_name = display_app_name(app_dir.name)
            profiles_dir = app_dir / "profiles"
            profile_count = 0
            total_size = 0
            if profiles_dir.exists():
                for profile_dir in profiles_dir.iterdir():
                    if profile_dir.is_dir():
                        profile_count += 1
                        vault_file = profile_dir / "profile.ssvault"
                        if vault_file.exists():
                            total_size += vault_file.stat().st_size

            row = ctk.CTkFrame(frame, fg_color=C["sidebar"] if row_idx % 2 == 0 else C["card"], corner_radius=6, height=40)
            row.grid(row=row_idx, column=0, sticky="ew", padx=2, pady=2)
            row.grid_columnconfigure(1, weight=1)
            ctk.CTkLabel(row, text="📦", font=("Segoe UI", 14), text_color=C["purple"]).grid(row=0, column=0, padx=(10, 5), pady=8)
            ctk.CTkLabel(row, text=app_name, font=("Segoe UI", 12, "bold"), text_color=C["text"], anchor="w").grid(row=0, column=1, sticky="w", padx=5, pady=8)
            ctk.CTkLabel(row, text=f"{profile_count} profile{'s' if profile_count != 1 else ''}", font=("Segoe UI", 11), text_color=C["muted"], width=90).grid(row=0, column=2, padx=5, pady=8)
            ctk.CTkLabel(row, text=self._format_file_size(total_size), font=("Segoe UI", 11), text_color=C["muted"], width=70).grid(row=0, column=3, padx=(5, 10), pady=8)

            safe_name = app_dir.name
            row.bind("<Button-1>", lambda e, n=app_name, s=safe_name: self._select_stored_app(n, s))
            for child in row.winfo_children():
                child.bind("<Button-1>", lambda e, n=app_name, s=safe_name: self._select_stored_app(n, s))

            row_idx += 1

        self._log(f"Found {row_idx} stored app vault(s).")

    def _select_stored_app(self, display_name: str, safe_name: str) -> None:
        self.app_name_var.set(display_name)
        self.profile_kind_var.set("Custom")
        guessed = guess_profile_path(display_name)
        self.profile_var.set(guessed)
        self._refresh_profile_names()
        self._log(f"Selected stored app: {display_name}. Set the executable and password to launch.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> int:
    if AESGCM is None:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(
            "ShadowSync",
            "The Python package 'cryptography' is required.\n\nInstall it with:\npython -m pip install cryptography",
        )
        return 1
    app = ShadowSyncApp()
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
