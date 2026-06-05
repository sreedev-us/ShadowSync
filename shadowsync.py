#!/usr/bin/env python3
"""
ShadowSync: encrypted cross-platform persistence for amnesic environments.

The vault format is portable across Windows, Tails, and other Linux systems:
profile data is zipped, encrypted with AES-GCM, and protected by a password
through PBKDF2-HMAC-SHA256.
"""

from __future__ import annotations

import io
import hashlib
import json
import os
import platform
import queue
import shutil
import stat
import subprocess
import tempfile
import threading
import time
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ImportError:  # pragma: no cover - shown through the GUI bootstrap.
    AESGCM = None  # type: ignore[assignment]

import tkinter as tk
from tkinter import filedialog, messagebox, ttk


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
_IS_LINUX = platform.system().lower() == "linux"


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
        if not source.exists():
            raise ShadowSyncError(f"Profile folder does not exist: {source}")
        zip_bytes = io.BytesIO()
        with zipfile.ZipFile(zip_bytes, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for path in sorted(source.rglob("*")):
                if path.is_file():
                    archive.write(path, path.relative_to(source).as_posix())
        encrypted = self._encrypt(zip_bytes.getvalue(), password)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_bytes(encrypted)
        os.replace(tmp, self.path)

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


def user_registry_path(storage_root: Path) -> Path:
    return storage_root.expanduser().resolve() / "user_registry.enc"


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
        detail = (
            f"This executable matches the signature ShadowSync previously locked for {verdict.matched_registry_name}."
        )
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
        ".git",
        ".qodo",
        "__pycache__",
        "System Volume Information",
        "$RECYCLE.BIN",
        "lost+found",
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
        "--die-with-parent",
        "--unshare-all",
        "--share-net",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--ro-bind-try",
        "/tmp/.X11-unix",
        "/tmp/.X11-unix",
        "--ro-bind-try",
        "/tmp/.ICE-unix",
        "/tmp/.ICE-unix",
        "--tmpfs",
        str(Path.home()),
        "--ro-bind",
        "/usr",
        "/usr",
        "--ro-bind",
        "/etc",
        "/etc",
        "--ro-bind",
        "/lib",
        "/lib",
        "--ro-bind",
        "/lib64",
        "/lib64",
        "--ro-bind",
        "/bin",
        "/bin",
        "--ro-bind",
        str(executable.parent),
        "/app",
        "--chdir",
        "/app",
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
    for name in ("DISPLAY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "PULSE_SERVER", "PIPEWIRE_REMOTE", "XAUTHORITY"):
        value = os.environ.get(name)
        if value:
            args.extend(["--setenv", name, value])
    return args


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
    import hashlib

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
# Hydrate — data model
# ---------------------------------------------------------------------------

@dataclass
class HydrateConfig:
    """All personalisation settings stored in the encrypted hydrate vault."""
    dark_mode: bool = True
    wallpaper_path: str = "/live/mount/medium/wallpaper.jpg"
    wifi_profiles: list = None  # list of {"ssid": str, "password": str}
    git_remote: str = ""
    git_branch: str = "main"
    git_name: str = "Tails User"
    git_email: str = ""
    git_token: str = ""  # PAT; injected at runtime, never written to .git/config

    def __post_init__(self) -> None:
        if self.wifi_profiles is None:
            self.wifi_profiles = []

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

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
        )

    # ------------------------------------------------------------------
    # Vault I/O
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # Individual hooks
    # ------------------------------------------------------------------

    def _apply_dark_mode(self) -> None:
        try:
            subprocess.run(
                ["gsettings", "set", "org.gnome.desktop.interface",
                 "color-scheme", "prefer-dark"],
                check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            self._log("Hydrate: dark mode applied.")
        except FileNotFoundError:
            self._log("Hydrate: gsettings not found — skipping dark mode.")
        except subprocess.CalledProcessError as exc:
            self._log(f"Hydrate: dark mode failed: {exc.stderr.strip()}")

    def _apply_wallpaper(self) -> None:
        uri = self.config.wallpaper_path.strip()
        # Ensure file:// URI format
        if not uri.startswith(("file://", "http://", "https://")):
            uri = "file://" + uri
        try:
            # Set for both light and dark to cover X11 and Wayland
            for key in ("picture-uri", "picture-uri-dark"):
                subprocess.run(
                    ["gsettings", "set", "org.gnome.desktop.background", key, uri],
                    check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                )
            self._log(f"Hydrate: wallpaper set → {uri}")
        except FileNotFoundError:
            self._log("Hydrate: gsettings not found — skipping wallpaper.")
        except subprocess.CalledProcessError as exc:
            self._log(f"Hydrate: wallpaper failed: {exc.stderr.strip()}")

    def _apply_wifi(self) -> None:
        for idx, profile in enumerate(self.config.wifi_profiles, start=1):
            ssid = str(profile.get("ssid", "")).strip()
            pwd = str(profile.get("password", "")).strip()
            if not ssid:
                continue
            self._log(f"Hydrate: connecting Wi-Fi profile {idx} ({ssid})…")
            try:
                cmd = ["nmcli", "dev", "wifi", "connect", ssid]
                if pwd:
                    cmd += ["password", pwd]
                result = subprocess.run(
                    cmd, check=False,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                    timeout=20,
                )
                if result.returncode == 0:
                    self._log(f"Hydrate: Wi-Fi connected to {ssid}.")
                    return  # success — stop trying further profiles
                self._log(f"Hydrate: Wi-Fi profile {idx} failed ({ssid}): {result.stderr.strip()}")
            except FileNotFoundError:
                self._log("Hydrate: nmcli not found — skipping Wi-Fi.")
                return
            except subprocess.TimeoutExpired:
                self._log(f"Hydrate: Wi-Fi profile {idx} timed out.")
        self._log("Hydrate: all Wi-Fi profiles exhausted without a successful connection.")

    def _log(self, message: str) -> None:
        self.log.put(message)


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
    ) -> None:
        self.storage_root = storage_root.expanduser().resolve()
        self.config = config
        self.log = log

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
            commit_msg = f"ShadowSync vault backup — {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}"
            self._git("commit", "--allow-empty", "-m", commit_msg)
            # Push WITHOUT --force to preserve history
            self._git_push(branch)
            self._log(f"Git Push: vault pushed successfully to branch '{branch}'.")
        except ShadowSyncError as exc:
            self._log(f"Git Push error: {exc}")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _write_gitignore(self) -> None:
        gitignore = self.storage_root / ".gitignore"
        content = "*.tmp\n__pycache__/\n*.pyc\n.DS_Store\n"
        try:
            gitignore.write_text(content, encoding="utf-8")
        except OSError:
            pass

    def _set_remote(self, remote_url: str, token: str) -> None:
        """Set the remote URL, embedding the PAT at runtime without persisting it."""
        # Build authenticated URL if token provided
        if token:
            # Insert token into https://token@host/... format
            if remote_url.startswith("https://"):
                authed_url = "https://" + token + "@" + remote_url[len("https://"):]
            else:
                authed_url = remote_url
        else:
            authed_url = remote_url

        # Check if remote exists
        result = subprocess.run(
            ["git", "-C", str(self.storage_root), "remote", "get-url", "origin"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
        )
        if result.returncode == 0:
            # Update existing remote URL (in-memory only for this session)
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
        """Push to remote. No --force, so history is always preserved."""
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
# Original RunOptions dataclass (unchanged)
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
                self._log("Continuing with a clean DIY profile or existing portable vault.")
                return
            self._busy(True, "Encrypting portable vault from FUSE storage...")
            try:
                try:
                    PortableVault(portable_vault).save_from(staging, self.options.password)
                finally:
                    self._busy(False)
            except ShadowSyncError as exc:
                self._log(f"FUSE-to-DIY migration failed: {exc}")
                self._log("Continuing without migration so the app is still usable.")
                return
            self._log("Migration complete. FUSE storage kept as a backup.")
        finally:
            try:
                bridge.unmount()
            except ShadowSyncError:
                pass
            wipe_directory(staging)

    def _launch(self, executable: Path) -> subprocess.Popen:
        if platform.system().lower() != "windows":
            mode = executable.stat().st_mode
            executable.chmod(mode | stat.S_IXUSR)
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


class ShadowSyncApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("ShadowSync")
        self.geometry("980x860")
        self.minsize(860, 780)
        self.configure(bg="#101820")
        self.presets = default_profile_paths()
        self.log_queue: queue.Queue[object] = queue.Queue()
        self.worker: Optional[ShadowSyncWorker] = None
        self.worker_thread: Optional[threading.Thread] = None
        self.approved_executable_path = ""
        self.approved_storage_root = ""
        self.sandbox_next_launch = False
        # Hydrate state
        self._hydrate_config: Optional[HydrateConfig] = None
        self._hydrate_expanded = tk.BooleanVar(value=False)
        self._build_styles()
        self._build_ui()
        self.after(150, self._drain_log)
        self.after(900, self._start_appimage_scan)
        self.bind_all("<Control-Shift-P>", lambda _event: self._panic())
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_styles(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TFrame", background="#101820")
        style.configure("Panel.TFrame", background="#f7f8fb")
        style.configure("Card.TFrame", background="#ffffff", relief="flat")
        style.configure("HydrateCard.TFrame", background="#0f0a1e", relief="flat")
        style.configure("TLabel", background="#f7f8fb", foreground="#17212b", font=("Segoe UI", 10))
        style.configure("Title.TLabel", font=("Segoe UI", 24, "bold"), foreground="#ffffff", background="#101820")
        style.configure("Sub.TLabel", font=("Segoe UI", 11), foreground="#b7c3d0", background="#101820")
        style.configure("Field.TLabel", font=("Segoe UI", 10, "bold"), foreground="#27313c", background="#ffffff")
        style.configure("HydrateField.TLabel", font=("Segoe UI", 10, "bold"), foreground="#c4b5fd", background="#0f0a1e")
        style.configure("HydrateSect.TLabel", font=("Segoe UI", 9, "bold"), foreground="#7c3aed", background="#0f0a1e")
        style.configure("HydrateDisabled.TLabel", font=("Segoe UI", 10), foreground="#6b7a90", background="#0f0a1e")
        style.configure("Status.TLabel", font=("Segoe UI", 10), foreground="#425466", background="#ffffff")
        style.configure("TEntry", fieldbackground="#ffffff", bordercolor="#d7dce4", padding=8)
        style.configure("HydrateEntry.TEntry", fieldbackground="#1e1535", foreground="#e9d5ff", bordercolor="#6d28d9", padding=8)
        style.configure("TCheckbutton", background="#ffffff", foreground="#27313c", font=("Segoe UI", 10))
        style.configure("HydrateCheck.TCheckbutton", background="#0f0a1e", foreground="#c4b5fd", font=("Segoe UI", 10))
        style.configure("TRadiobutton", background="#ffffff", foreground="#27313c", font=("Segoe UI", 10))
        style.configure("Primary.TButton", font=("Segoe UI", 11, "bold"), padding=(16, 10), background="#0f766e", foreground="#ffffff")
        style.map("Primary.TButton", background=[("active", "#0d9488"), ("disabled", "#93a4b1")])
        style.configure("Danger.TButton", font=("Segoe UI", 11, "bold"), padding=(16, 10), background="#b42318", foreground="#ffffff")
        style.map("Danger.TButton", background=[("active", "#d92d20")])
        style.configure("Ghost.TButton", font=("Segoe UI", 10), padding=(12, 8), background="#e8eef5", foreground="#17212b")
        style.map("Ghost.TButton", background=[("active", "#dbe6ef")])
        # Hydrate-specific button styles
        style.configure("Hydrate.TButton", font=("Segoe UI", 11, "bold"), padding=(16, 10), background="#7c3aed", foreground="#ffffff")
        style.map("Hydrate.TButton", background=[("active", "#6d28d9"), ("disabled", "#3b2d5a")])
        style.configure("HydrateGhost.TButton", font=("Segoe UI", 10), padding=(12, 8), background="#1e1535", foreground="#c4b5fd")
        style.map("HydrateGhost.TButton", background=[("active", "#2d1f4a")])
        style.configure("Crypto.Horizontal.TProgressbar", troughcolor="#dce6ef", background="#0f766e", bordercolor="#dce6ef")

    def _build_ui(self) -> None:
        self.columnconfigure(1, weight=1)
        self.rowconfigure(0, weight=1)

        sidebar = ttk.Frame(self, style="TFrame", padding=(30, 34))
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.columnconfigure(0, minsize=260)
        ttk.Label(sidebar, text="ShadowSync", style="Title.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(
            sidebar,
            text="Encrypted persistence for amnesic sessions.",
            style="Sub.TLabel",
            wraplength=250,
        ).grid(row=1, column=0, sticky="w", pady=(8, 28))
        self.state_label = tk.Label(
            sidebar,
            text="Locked",
            bg="#14313a",
            fg="#8ee7d3",
            font=("Segoe UI", 12, "bold"),
            padx=16,
            pady=12,
            anchor="w",
        )
        self.state_label.grid(row=2, column=0, sticky="ew")
        self.heartbeat_dot = tk.Label(
            sidebar,
            text="● Heartbeat idle",
            bg="#101820",
            fg="#6b7a86",
            font=("Segoe UI", 10, "bold"),
            anchor="w",
            pady=8,
        )
        self.heartbeat_dot.grid(row=3, column=0, sticky="ew")
        tk.Label(
            sidebar,
            text="1. Choose a storage mode\n2. Enter the master password\n3. Select the app and profile\n4. Launch, sync, and close",
            bg="#101820",
            fg="#d6e0ea",
            justify="left",
            font=("Segoe UI", 10),
            pady=28,
        ).grid(row=4, column=0, sticky="w")

        main = ttk.Frame(self, style="Panel.TFrame", padding=(28, 28))
        main.grid(row=0, column=1, sticky="nsew")
        main.columnconfigure(0, weight=1)
        main.rowconfigure(3, weight=1)

        form = ttk.Frame(main, style="Card.TFrame", padding=(24, 22))
        form.grid(row=0, column=0, sticky="ew")
        form.columnconfigure(1, weight=1)

        self.mode_var = tk.StringVar(value=MODE_DIY)
        self.storage_var = tk.StringVar(value=str(Path.cwd() / "ShadowSyncStore"))
        self.app_name_var = tk.StringVar(value="Session")
        self.profile_name_var = tk.StringVar(value="Default")
        self.password_var = tk.StringVar()
        self.password_var.trace_add("write", lambda *_args: self._clear_executable_approval())
        self.profile_kind_var = tk.StringVar(value="Session")
        self.profile_var = tk.StringVar(value=self.presets["Session"])
        self.exec_var = tk.StringVar()
        self.wipe_var = tk.BooleanVar(value=True)

        self._mode_field(form, 0)
        self._field(form, 1, "Storage folder", self.storage_var, self._browse_storage)
        self._field(form, 2, "App name", self.app_name_var, None)
        self._profile_name_field(form, 3)
        self._password_field(form, 4)
        self._preset_field(form, 5)
        self._field(form, 6, "Profile folder", self.profile_var, self._browse_profile)
        self._field(form, 7, "Application", self.exec_var, self._browse_executable)

        options = ttk.Frame(form, style="Card.TFrame")
        options.grid(row=8, column=1, sticky="w", pady=(8, 0))
        ttk.Checkbutton(options, text="Wipe profile after close", variable=self.wipe_var).grid(row=0, column=0)

        actions = ttk.Frame(form, style="Card.TFrame")
        actions.grid(row=9, column=1, sticky="ew", pady=(22, 0))
        ttk.Button(actions, text="Open & Launch", style="Primary.TButton", command=self._start).grid(row=0, column=0, sticky="w")
        ttk.Button(actions, text="Save Vault Now", style="Ghost.TButton", command=self._save_now).grid(row=0, column=1, padx=10)
        ttk.Button(actions, text="Stop", style="Ghost.TButton", command=self._stop_worker).grid(row=0, column=2)
        ttk.Button(actions, text="Panic", style="Danger.TButton", command=self._panic).grid(row=0, column=3, padx=(10, 0))

        file_actions = ttk.Frame(form, style="Card.TFrame")
        file_actions.grid(row=10, column=1, sticky="ew", pady=(12, 0))
        ttk.Button(file_actions, text="Add Files", style="Ghost.TButton", command=self._add_files_to_vault).grid(row=0, column=0)
        ttk.Button(file_actions, text="Add Folder", style="Ghost.TButton", command=self._add_folder_to_vault).grid(row=0, column=1, padx=10)
        ttk.Button(file_actions, text="Export Files", style="Ghost.TButton", command=self._export_files_vault).grid(row=0, column=2)

        self.progress = ttk.Progressbar(form, style="Crypto.Horizontal.TProgressbar", mode="indeterminate")
        self.progress.grid(row=11, column=1, sticky="ew", pady=(16, 0))
        self.progress.grid_remove()

        # ------------------------------------------------------------------
        # Hydrate card (collapsible, below the main form)
        # ------------------------------------------------------------------
        self._build_hydrate_card(main)

        log_card = ttk.Frame(main, style="Card.TFrame", padding=(20, 18))
        log_card.grid(row=2, column=0, sticky="nsew", pady=(18, 0))
        log_card.columnconfigure(0, weight=1)
        log_card.rowconfigure(1, weight=1)
        ttk.Label(log_card, text="Activity", style="Field.TLabel").grid(row=0, column=0, sticky="w")
        self.log_text = tk.Text(
            log_card,
            height=10,
            bg="#0f1720",
            fg="#d9e7ef",
            insertbackground="#ffffff",
            relief="flat",
            padx=14,
            pady=12,
            font=("Consolas", 10),
            wrap="word",
        )
        self.log_text.grid(row=1, column=0, sticky="nsew", pady=(10, 0))
        self._log("Ready. Choose a storage mode, then enter the master password.")

    # ------------------------------------------------------------------
    # Hydrate card builder
    # ------------------------------------------------------------------

    def _build_hydrate_card(self, parent: ttk.Frame) -> None:
        """Build the collapsible Hydrate personalisation card."""
        # Toggle header — always visible
        header = tk.Frame(parent, bg="#0f0a1e", cursor="hand2")
        header.grid(row=1, column=0, sticky="ew", pady=(12, 0))
        header.columnconfigure(1, weight=1)

        self._hydrate_arrow = tk.Label(
            header, text="▶", bg="#0f0a1e", fg="#7c3aed",
            font=("Segoe UI", 12, "bold"), padx=10, pady=8,
        )
        self._hydrate_arrow.grid(row=0, column=0)
        tk.Label(
            header, text="⚡  Hydrate — Session Personalisation",
            bg="#0f0a1e", fg="#c4b5fd",
            font=("Segoe UI", 11, "bold"), pady=8,
        ).grid(row=0, column=1, sticky="w")

        # Collapsible body
        self._hydrate_body = tk.Frame(parent, bg="#0f0a1e")
        # (not gridded until expanded)

        # Bind toggle
        for widget in (header, self._hydrate_arrow):
            widget.bind("<Button-1>", lambda _e: self._toggle_hydrate())
        for child in header.winfo_children():
            child.bind("<Button-1>", lambda _e: self._toggle_hydrate())

        # Build form inside body
        self._build_hydrate_body(self._hydrate_body)

    def _build_hydrate_body(self, parent: tk.Frame) -> None:
        """Populate the Hydrate card body."""
        if not _IS_LINUX:
            # Windows — show disabled notice
            tk.Label(
                parent,
                text="⚠  Hydrate requires Linux / Tails with GNOME and NetworkManager.",
                bg="#0f0a1e", fg="#6b7a90",
                font=("Segoe UI", 10), pady=16, padx=16,
            ).pack(fill="x")
            return

        pad = {"padx": 16, "pady": 4}

        # --- Section: Appearance ---
        tk.Label(parent, text="APPEARANCE", bg="#0f0a1e", fg="#7c3aed",
                 font=("Segoe UI", 8, "bold"), anchor="w").pack(fill="x", padx=16, pady=(12, 0))
        sep1 = tk.Frame(parent, bg="#2d1f4a", height=1)
        sep1.pack(fill="x", padx=16, pady=(2, 6))

        # Dark mode checkbox
        self._h_darkmode_var = tk.BooleanVar(value=True)
        tk.Checkbutton(
            parent, text="Enable dark mode (GNOME)",
            variable=self._h_darkmode_var,
            bg="#0f0a1e", fg="#c4b5fd", selectcolor="#1e1535",
            activebackground="#0f0a1e", activeforeground="#e9d5ff",
            font=("Segoe UI", 10),
        ).pack(anchor="w", **pad)

        # Wallpaper
        wp_row = tk.Frame(parent, bg="#0f0a1e")
        wp_row.pack(fill="x", **pad)
        tk.Label(wp_row, text="Wallpaper path", bg="#0f0a1e", fg="#c4b5fd",
                 font=("Segoe UI", 10, "bold"), width=18, anchor="w").pack(side="left")
        self._h_wallpaper_var = tk.StringVar(value="/live/mount/medium/wallpaper.jpg")
        wp_entry = tk.Entry(
            wp_row, textvariable=self._h_wallpaper_var,
            bg="#1e1535", fg="#e9d5ff", insertbackground="#c4b5fd",
            relief="flat", font=("Segoe UI", 10), bd=4,
        )
        wp_entry.pack(side="left", fill="x", expand=True, padx=(8, 6))
        tk.Button(
            wp_row, text="Browse", command=self._h_browse_wallpaper,
            bg="#1e1535", fg="#c4b5fd", relief="flat",
            activebackground="#2d1f4a", activeforeground="#e9d5ff",
            font=("Segoe UI", 9), padx=10, pady=4,
        ).pack(side="left")

        # --- Section: Wi-Fi ---
        tk.Label(parent, text="WI-FI PROFILES", bg="#0f0a1e", fg="#7c3aed",
                 font=("Segoe UI", 8, "bold"), anchor="w").pack(fill="x", padx=16, pady=(14, 0))
        sep2 = tk.Frame(parent, bg="#2d1f4a", height=1)
        sep2.pack(fill="x", padx=16, pady=(2, 6))

        self._h_wifi_vars: list[tuple[tk.StringVar, tk.StringVar]] = []
        for i in range(2):
            row = tk.Frame(parent, bg="#0f0a1e")
            row.pack(fill="x", **pad)
            tk.Label(
                row, text=f"SSID {i + 1}", bg="#0f0a1e", fg="#c4b5fd",
                font=("Segoe UI", 10, "bold"), width=8, anchor="w",
            ).pack(side="left")
            ssid_v = tk.StringVar()
            tk.Entry(
                row, textvariable=ssid_v,
                bg="#1e1535", fg="#e9d5ff", insertbackground="#c4b5fd",
                relief="flat", font=("Segoe UI", 10), bd=4, width=20,
            ).pack(side="left", padx=(8, 8))
            tk.Label(
                row, text="Password", bg="#0f0a1e", fg="#c4b5fd",
                font=("Segoe UI", 10, "bold"),
            ).pack(side="left")
            pwd_v = tk.StringVar()
            tk.Entry(
                row, textvariable=pwd_v, show="●",
                bg="#1e1535", fg="#e9d5ff", insertbackground="#c4b5fd",
                relief="flat", font=("Segoe UI", 10), bd=4, width=20,
            ).pack(side="left", padx=(8, 0))
            self._h_wifi_vars.append((ssid_v, pwd_v))

        # --- Section: Git ---
        tk.Label(parent, text="GIT BACKUP", bg="#0f0a1e", fg="#7c3aed",
                 font=("Segoe UI", 8, "bold"), anchor="w").pack(fill="x", padx=16, pady=(14, 0))
        sep3 = tk.Frame(parent, bg="#2d1f4a", height=1)
        sep3.pack(fill="x", padx=16, pady=(2, 6))

        git_fields = [
            ("Remote URL",   "_h_git_remote_var",  "",      False),
            ("Branch",       "_h_git_branch_var",  "main",  False),
            ("Identity name","_h_git_name_var",    "Tails User", False),
            ("Identity email","_h_git_email_var",  "",      False),
            ("Access token (PAT)", "_h_git_token_var", "",  True),
        ]
        for label, attr, default, is_secret in git_fields:
            row = tk.Frame(parent, bg="#0f0a1e")
            row.pack(fill="x", **pad)
            tk.Label(
                row, text=label, bg="#0f0a1e", fg="#c4b5fd",
                font=("Segoe UI", 10, "bold"), width=18, anchor="w",
            ).pack(side="left")
            var = tk.StringVar(value=default)
            setattr(self, attr, var)
            show = "●" if is_secret else ""
            tk.Entry(
                row, textvariable=var, show=show,
                bg="#1e1535", fg="#e9d5ff", insertbackground="#c4b5fd",
                relief="flat", font=("Segoe UI", 10), bd=4,
            ).pack(side="left", fill="x", expand=True, padx=(8, 0))

        # --- Action buttons ---
        btn_row = tk.Frame(parent, bg="#0f0a1e")
        btn_row.pack(fill="x", padx=16, pady=(16, 16))

        def _hbtn(text, cmd, primary=False):
            bg = "#7c3aed" if primary else "#1e1535"
            abg = "#6d28d9" if primary else "#2d1f4a"
            return tk.Button(
                btn_row, text=text, command=cmd,
                bg=bg, fg="#ffffff", relief="flat",
                activebackground=abg, activeforeground="#ffffff",
                font=("Segoe UI", 10, "bold") if primary else ("Segoe UI", 10),
                padx=14, pady=8, cursor="hand2",
            )

        _hbtn("⚡ Hydrate Now", self._hydrate_now, primary=True).pack(side="left")
        _hbtn("💾 Save Config", self._save_hydrate_config).pack(side="left", padx=(10, 0))
        _hbtn("☁  Push to Git", self._git_push).pack(side="left", padx=(10, 0))

    # ------------------------------------------------------------------
    # Hydrate card toggle
    # ------------------------------------------------------------------

    def _toggle_hydrate(self) -> None:
        if self._hydrate_expanded.get():
            self._hydrate_body.grid_remove()
            self._hydrate_arrow.configure(text="▶")
            self._hydrate_expanded.set(False)
        else:
            self._hydrate_body.grid(row=2, column=0, sticky="ew")
            self._hydrate_arrow.configure(text="▼")
            self._hydrate_expanded.set(True)

    # ------------------------------------------------------------------
    # Hydrate helpers — file browse
    # ------------------------------------------------------------------

    def _h_browse_wallpaper(self) -> None:
        path = filedialog.askopenfilename(
            title="Choose wallpaper image",
            filetypes=[("Images", "*.jpg *.jpeg *.png *.webp"), ("All files", "*")],
        )
        if path:
            self._h_wallpaper_var.set(path)

    # ------------------------------------------------------------------
    # Hydrate — build config from UI fields
    # ------------------------------------------------------------------

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
        )

    def _populate_hydrate_fields(self, cfg: HydrateConfig) -> None:
        """Fill UI fields from a loaded HydrateConfig (called from background thread via after())."""
        if not _IS_LINUX:
            return
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
        self._hydrate_config = cfg

    # ------------------------------------------------------------------
    # Hydrate — background auto-load
    # ------------------------------------------------------------------

    def _try_autoload_hydrate(self) -> None:
        """Silently attempt to load the hydrate config vault in the background."""
        password = self.password_var.get()
        storage = self.storage_var.get().strip()
        if not password or not storage or not _IS_LINUX:
            return
        threading.Thread(target=self._autoload_hydrate_task, daemon=True).start()

    def _autoload_hydrate_task(self) -> None:
        try:
            cfg = HydrateConfig.load(
                Path(self.storage_var.get()),
                self.password_var.get(),
            )
            self._hydrate_config = cfg
            self.after(0, lambda: self._populate_hydrate_fields(cfg))
            self.log_queue.put("Hydrate config loaded from vault.")
        except ShadowSyncError:
            pass  # vault doesn't exist yet — that's fine
        except Exception as exc:
            self.log_queue.put(f"Hydrate config auto-load skipped: {exc}")

    # ------------------------------------------------------------------
    # Hydrate — action handlers
    # ------------------------------------------------------------------

    def _hydrate_now(self) -> None:
        if not _IS_LINUX:
            messagebox.showinfo("Hydrate", "Hydrate is only available on Linux/Tails.")
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
        if not _IS_LINUX:
            messagebox.showinfo("Hydrate", "Hydrate is only available on Linux/Tails.")
            return
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
            except ShadowSyncError as exc:
                msg = str(exc)
                self.after(0, lambda m=msg: messagebox.showerror("Hydrate", m))
            finally:
                self.log_queue.put(("busy", False, ""))

        threading.Thread(target=task, daemon=True).start()

    def _git_push(self) -> None:
        if not _IS_LINUX:
            messagebox.showinfo("Hydrate", "Git push is only available on Linux/Tails.")
            return
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
            messagebox.showerror("Hydrate", "Enter a Git remote URL in the Hydrate section.")
            return
        self._log("Git Push: preparing vault commit…")
        self._set_busy(True, "Pushing to Git…")

        def task() -> None:
            try:
                GitPushWorker(Path(storage), cfg, self.log_queue).run()
            except Exception as exc:
                self.log_queue.put(f"Git Push error: {exc}")
            finally:
                self.log_queue.put(("busy", False, ""))

        threading.Thread(target=task, daemon=True).start()

    def _field(self, parent: ttk.Frame, row: int, label: str, variable: tk.StringVar, browse) -> ttk.Label:
        label_widget = ttk.Label(parent, text=label, style="Field.TLabel")
        label_widget.grid(row=row, column=0, sticky="nw", pady=8, padx=(0, 16))
        entry = ttk.Entry(parent, textvariable=variable)
        entry.grid(row=row, column=1, sticky="ew", pady=8)
        if label == "Profile folder":
            self.profile_entry = entry
        if browse:
            ttk.Button(parent, text="Browse", style="Ghost.TButton", command=browse).grid(row=row, column=2, padx=(10, 0), pady=8)
        return label_widget

    def _mode_field(self, parent: ttk.Frame, row: int) -> None:
        ttk.Label(parent, text="Mode", style="Field.TLabel").grid(row=row, column=0, sticky="nw", pady=8, padx=(0, 16))
        modes = ttk.Frame(parent, style="Card.TFrame")
        modes.grid(row=row, column=1, sticky="w", pady=8)
        ttk.Radiobutton(
            modes,
            text="DIY sync-on-close",
            value=MODE_DIY,
            variable=self.mode_var,
            command=self._mode_changed,
        ).grid(row=0, column=0, padx=(0, 18))
        ttk.Radiobutton(
            modes,
            text="On-the-fly FUSE",
            value=MODE_FUSE,
            variable=self.mode_var,
            command=self._mode_changed,
        ).grid(row=0, column=1)

    def _password_field(self, parent: ttk.Frame, row: int) -> None:
        ttk.Label(parent, text="Master password", style="Field.TLabel").grid(row=row, column=0, sticky="nw", pady=8, padx=(0, 16))
        ttk.Entry(parent, textvariable=self.password_var, show="*").grid(row=row, column=1, sticky="ew", pady=8)

    def _profile_name_field(self, parent: ttk.Frame, row: int) -> None:
        ttk.Label(parent, text="Profile name", style="Field.TLabel").grid(row=row, column=0, sticky="nw", pady=8, padx=(0, 16))
        self.profile_combo = ttk.Combobox(parent, textvariable=self.profile_name_var, values=["Default"])
        self.profile_combo.grid(row=row, column=1, sticky="ew", pady=8)
        ttk.Button(parent, text="Refresh", style="Ghost.TButton", command=self._refresh_profile_names).grid(row=row, column=2, padx=(10, 0), pady=8)

    def _preset_field(self, parent: ttk.Frame, row: int) -> None:
        ttk.Label(parent, text="Preset", style="Field.TLabel").grid(row=row, column=0, sticky="nw", pady=8, padx=(0, 16))
        preset = ttk.Combobox(parent, textvariable=self.profile_kind_var, values=list(self.presets), state="readonly")
        preset.grid(row=row, column=1, sticky="ew", pady=8)
        preset.bind("<<ComboboxSelected>>", self._preset_changed)

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
        # When password is already entered and mode is changed, try to auto-load hydrate
        self._try_autoload_hydrate()

    def _options(self) -> RunOptions:
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
            options = self._options()
        except ShadowSyncError as exc:
            messagebox.showerror("ShadowSync", str(exc))
            return
        self.worker = ShadowSyncWorker(options, self.log_queue)
        self.worker_thread = threading.Thread(target=self._run_worker, daemon=True)
        self.worker_thread.start()
        self.state_label.configure(text="Running")
        # Auto-load hydrate config now that we know password + storage are valid
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
                options = self._options()
                if options.mode == MODE_FUSE:
                    raise ShadowSyncError("FUSE mode saves on the fly. Launch it first, then use Save Vault Now to flush writes.")
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
        vault = PortableVault(files_vault_path(Path(self.storage_var.get())))
        if not vault.exists():
            messagebox.showinfo("ShadowSync", "No manual files vault exists yet.")
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
        vault = PortableVault(files_vault_path(Path(self.storage_var.get())))
        self._set_busy(True, "Encrypting manual files vault...")

        def import_task() -> None:
            staging = Path(tempfile.mkdtemp(prefix="shadowsync-files-"))
            try:
                if vault.exists():
                    vault.restore_to(staging, password)
                for source in sources:
                    copy_into_unique(source.expanduser().resolve(), staging)
                vault.save_from(staging, password)
                self.log_queue.put(f"Added {len(sources)} item(s) to manual files vault: {vault.path}")
            except ShadowSyncError as exc:
                message = str(exc)
                self.after(0, lambda message=message: messagebox.showerror("ShadowSync", message))
            except OSError as exc:
                message = f"File import failed: {exc}"
                self.after(0, lambda message=message: messagebox.showerror("ShadowSync", message))
            finally:
                wipe_directory(staging)
                self.log_queue.put(("busy", False, ""))

        threading.Thread(target=import_task, daemon=True).start()

    def _file_vault_password(self) -> str:
        password = self.password_var.get()
        if not password:
            raise ShadowSyncError("Enter the master password first.")
        if not self.storage_var.get().strip():
            raise ShadowSyncError("Choose the ShadowSync storage folder first.")
        return password

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

    def _on_close(self) -> None:
        if self.worker and self.worker_thread and self.worker_thread.is_alive():
            if not messagebox.askyesno("ShadowSync", "Stop the running app and close ShadowSync?"):
                return
            self.worker.stop()
        self.destroy()

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
        self.log_text.insert("end", f"[{timestamp}] {message}\n")
        self.log_text.see("end")

    def _set_busy(self, active: bool, message: str = "") -> None:
        if active:
            self.progress.grid()
            self.progress.start(12)
            self.state_label.configure(text=message or "Working")
        else:
            self.progress.stop()
            self.progress.grid_remove()
            if self.worker_thread and self.worker_thread.is_alive():
                self.state_label.configure(text="Running")
            else:
                self.state_label.configure(text="Locked")

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
        self.heartbeat_dot.configure(text="● Heartbeat checked", fg="#22c55e")
        self.after(900, lambda: self.heartbeat_dot.configure(text="● Heartbeat active", fg="#8ee7d3"))

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
