"""Move a profile to another machine: `netrune profile export` / `profile import`.

A bundle is one gzip tarball with a manifest, laid out by where each file
lives in a profile (config/, cache/, state/, data/), so importing never has
to guess. What goes in:

- always: the profile's configuration (profile.toml, netsnmp.conf, aliases,
  channels, drivers, the SSH known_hosts that pins switch host keys) and the
  flat caches the helpers read (devices, APs, neighbours, AP attachments, the
  controller sidecar), so the first command on the new machine already knows
  the network;
- --with-state: the SQLite memory (identity history, merges, decisions,
  traffic samples; a validated snapshot, never the live file) and the
  configuration backups;
- --with-secrets: the SNMP communities (config/.env and the per-device
  community cache), and then the whole bundle is GPG-encrypted with a
  passphrase, so a bundle holding credentials is never written in the clear.

Never in a bundle: the SSH password vault and the named secrets. They are
encrypted to a key held behind this machine's sudo, so a copy is useless
elsewhere; the import says to run `netrune vault set` instead.
"""

from __future__ import annotations

import getpass
import io
import json
import os
import shutil
import socket
import subprocess
import tarfile
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from netops_platform.profiles import _sqlite_snapshot

BUNDLE_VERSION = 1
CONFIG_SKIP_SUFFIXES = (".lock", ".tmp", "~")
# Flat caches worth carrying; everything else in the cache directory is
# rebuilt (locks, runtime state, stale pre-v8 files).
CACHE_FILES = ("devices.db", "ap_devices.db", "neighbor.db", "ap_attachments.db", "ap_controller.db")
SECRET_CONFIG = (".env",)
SECRET_CACHE = ("snmp_cache.db",)
PASSPHRASE_ENV = "NETRUNE_BUNDLE_PASSPHRASE"
GZIP_MAGIC = b"\x1f\x8b"


class BundleError(Exception):
    pass


def _passphrase(confirm: bool) -> str:
    supplied = os.environ.get(PASSPHRASE_ENV, "")
    if supplied:
        return supplied
    if not os.isatty(0):
        raise BundleError(f"a bundle with secrets is encrypted: give its passphrase in {PASSPHRASE_ENV} "
                          "or run this in a terminal")
    first = getpass.getpass("Bundle passphrase: ")
    if not first:
        raise BundleError("an empty passphrase would not protect the communities in the bundle")
    if confirm and getpass.getpass("Again: ") != first:
        raise BundleError("the two passphrases differ")
    return first


def _gpg(args: List[str], passphrase: str, data: bytes) -> bytes:
    gpg = shutil.which("gpg")
    if not gpg:
        raise BundleError("gpg is needed to encrypt or decrypt a bundle with secrets")
    with tempfile.TemporaryDirectory(prefix="netrune-gpg-") as home:
        # A throwaway GPG home: symmetric encryption needs no keyring, and
        # the operator's own agent and keys are never touched.
        os.chmod(home, 0o700)
        read_fd, write_fd = os.pipe()
        os.write(write_fd, passphrase.encode() + b"\n")
        os.close(write_fd)
        try:
            proc = subprocess.run(
                [gpg, "--homedir", home, "--batch", "--yes", "--quiet", "--pinentry-mode", "loopback",
                 "--passphrase-fd", str(read_fd), *args],
                input=data, capture_output=True, pass_fds=(read_fd,), timeout=600)
        finally:
            os.close(read_fd)
    if proc.returncode != 0:
        detail = proc.stderr.decode(errors="replace").strip().splitlines()
        raise BundleError("gpg failed: " + (detail[-1] if detail else f"exit {proc.returncode}"))
    return proc.stdout


def _add_tree(tar: tarfile.TarFile, root: Path, prefix: str, *, skip_names: tuple = ()) -> List[str]:
    added = []
    if not root.is_dir():
        return added
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if path.is_symlink() or not path.is_file() or path.name in skip_names:
            continue
        if path.name.endswith(CONFIG_SKIP_SUFFIXES) or ".bak" in path.name or ".before-" in path.name:
            continue
        tar.add(path, arcname=f"{prefix}/{relative}", recursive=False)
        added.append(f"{prefix}/{relative}")
    return added


def export_bundle(paths: Any, destination: Path, *, with_state: bool = False, with_secrets: bool = False) -> Dict[str, Any]:
    """Write `paths`' profile to `destination`; returns the manifest."""
    destination = Path(destination).expanduser()
    if destination.exists() and destination.is_dir():
        raise BundleError(f"{destination} is a directory; name the bundle file")
    manifest: Dict[str, Any] = {
        "bundle_version": BUNDLE_VERSION, "profile": paths.profile, "created_at": int(time.time()),
        "source_host": socket.gethostname(), "with_state": with_state, "with_secrets": with_secrets, "files": [],
    }
    buffer = io.BytesIO()
    with tempfile.TemporaryDirectory(prefix="netrune-export-") as staging:
        with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
            manifest["files"] += _add_tree(tar, paths.config_dir, "config",
                                           skip_names=() if with_secrets else SECRET_CONFIG)
            for name in CACHE_FILES + (SECRET_CACHE if with_secrets else ()):
                path = paths.cache_dir / name
                if path.is_file():
                    tar.add(path, arcname=f"cache/{name}", recursive=False)
                    manifest["files"].append(f"cache/{name}")
            if with_state:
                if paths.sqlite_db.is_file():
                    snapshot = Path(staging) / "netrune.sqlite3"
                    _sqlite_snapshot(paths.sqlite_db, snapshot)
                    tar.add(snapshot, arcname="state/netrune.sqlite3", recursive=False)
                    manifest["files"].append("state/netrune.sqlite3")
                manifest["files"] += _add_tree(tar, paths.backup_dir, "data/backups")
            data = json.dumps(manifest, indent=2, sort_keys=True).encode()
            info = tarfile.TarInfo("manifest.json")
            info.size, info.mtime, info.mode = len(data), manifest["created_at"], 0o600
            tar.addfile(info, io.BytesIO(data))
    payload = buffer.getvalue()
    if with_secrets:
        payload = _gpg(["--symmetric", "--cipher-algo", "AES256", "--output", "-"], _passphrase(confirm=True), payload)
    destination.parent.mkdir(parents=True, exist_ok=True)
    staged = destination.with_name(f".{destination.name}.{os.getpid()}.tmp")
    with open(os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as handle:
        handle.write(payload)
    os.replace(staged, destination)
    manifest["bytes"] = len(payload)
    manifest["path"] = str(destination)
    return manifest


def _members(tar: tarfile.TarFile) -> List[tarfile.TarInfo]:
    """Regular files under the known roots only: no links, devices, or escapes."""
    safe = []
    for member in tar.getmembers():
        name = member.name
        parts = Path(name).parts
        if member.isdir():
            continue
        if not member.isfile() or name.startswith("/") or ".." in parts or not parts:
            raise BundleError(f"refusing bundle entry {name!r}")
        if name != "manifest.json" and parts[0] not in {"config", "cache", "state", "data"}:
            raise BundleError(f"refusing bundle entry {name!r}")
        safe.append(member)
    return safe


def read_bundle(source: Path) -> tarfile.TarFile:
    raw = Path(source).expanduser().read_bytes()
    if raw[:2] != GZIP_MAGIC:
        raw = _gpg(["--decrypt", "--output", "-"], _passphrase(confirm=False), raw)
    return tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz")


def _has_content(layout: Any) -> bool:
    """Whether a profile already holds something an import would overwrite."""
    config = layout.config_dir
    meaningful = [p for p in config.rglob("*") if p.is_file() and p.name not in {"profile.toml", "netsnmp.conf"}] if config.is_dir() else []
    database = layout.state_dir / "netrune.sqlite3"
    return bool(meaningful) or (database.is_file() and database.stat().st_size > 512 * 1024)


def import_bundle(store: Any, source: Path, *, as_name: str = "", force: bool = False) -> Dict[str, Any]:
    """Restore a bundle into a profile (its own name unless `as_name`) and select it."""
    with read_bundle(source) as tar:
        members = _members(tar)
        names = {member.name: member for member in members}
        if "manifest.json" not in names:
            raise BundleError("not a Netrune profile bundle (no manifest)")
        manifest = json.loads(tar.extractfile(names["manifest.json"]).read())
        if int(manifest.get("bundle_version") or 0) > BUNDLE_VERSION:
            raise BundleError("this bundle was written by a newer Netrune; upgrade before importing it")
        layout = store.layout(as_name or manifest.get("profile") or "default")
        if _has_content(layout) and not force:
            raise BundleError(f"profile '{layout.name}' already holds configuration or memory; "
                              "import --as NEW_NAME, or --force to replace it (the old files are kept beside the new)")
        store.ensure(layout.name)
        roots = {"config": layout.config_dir, "cache": layout.cache_dir, "state": layout.state_dir, "data": layout.data_dir}
        stamp = time.strftime("%Y%m%d-%H%M%S")
        restored = []
        for member in members:
            if member.name == "manifest.json":
                continue
            root, _, relative = member.name.partition("/")
            target = roots[root] / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists() and force:
                target.rename(target.with_name(f"{target.name}.before-import-{stamp}"))
            if root == "state":
                for sidecar in ("-wal", "-shm"):
                    Path(str(target) + sidecar).unlink(missing_ok=True)
            with tar.extractfile(member) as src, open(os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as dst:
                shutil.copyfileobj(src, dst)
            restored.append(member.name)
    store.use(layout.name)
    return {"profile": layout.name, "restored": restored, "manifest": manifest,
            "config_dir": str(layout.config_dir)}
