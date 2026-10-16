"""Profile-scoped paths and neutral configuration for Netrune.

Profiles are intentionally data-only.  They isolate inventory, trust, aliases,
ingest channels, and policy without allowing configuration to execute code.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sqlite3
import time
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping


PROFILE_SCHEMA_VERSION = 1
DEFAULT_PROFILE = "default"
PROFILE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")
LEGACY_PUBLIC_ENV_KEYS = frozenset({"ssh_user"})


def environment_value(primary: str, legacy: str = "", default: str = "") -> str:
    if primary in os.environ:
        return os.environ[primary]
    if legacy and legacy in os.environ:
        return os.environ[legacy]
    return default


def profile_name(value: Any) -> str:
    name = str(value or DEFAULT_PROFILE).strip().lower().replace(" ", "-")
    if not PROFILE_NAME_RE.fullmatch(name):
        raise ValueError("profile names use 1-48 lowercase letters, digits, '_' or '-'")
    return name


def _xdg(home: Path, variable: str, suffix: str) -> Path:
    configured = os.environ.get(variable, "").strip()
    if configured:
        return Path(configured).expanduser() / suffix
    defaults = {
        "XDG_CONFIG_HOME": home / ".config",
        "XDG_STATE_HOME": home / ".local" / "state",
        "XDG_CACHE_HOME": home / ".cache",
        "XDG_DATA_HOME": home / ".local" / "share",
    }
    return defaults[variable] / suffix


def _atomic_write(path: Path, content: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    staged = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    staged.write_text(content, encoding="utf-8")
    staged.chmod(mode)
    os.replace(staged, path)


def read_kv(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def _sqlite_readonly_uri(path: Path) -> str:
    return path.resolve().as_uri() + "?mode=ro"


def _sqlite_summary(path: Path) -> dict[str, Any]:
    """Validate a database and count non-schema rows before migration decisions."""
    connection = sqlite3.connect(_sqlite_readonly_uri(path), uri=True, timeout=30)
    try:
        quick_check = [str(row[0]) for row in connection.execute("PRAGMA quick_check").fetchall()]
        if quick_check != ["ok"]:
            raise ValueError(f"SQLite quick_check failed for {path}: {', '.join(quick_check)}")
        tables = [
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name<>'schema_meta' "
                "ORDER BY name"
            )
        ]
        rows = 0
        populated: list[str] = []
        for table in tables:
            quoted = '"' + table.replace('"', '""') + '"'
            count = int(connection.execute(f"SELECT COUNT(*) FROM {quoted}").fetchone()[0])
            rows += count
            if count:
                populated.append(table)
        return {
            "bytes": path.stat().st_size,
            "data_rows": rows,
            "populated_tables": populated,
            "quick_check": "ok",
        }
    finally:
        connection.close()


def _sqlite_snapshot(source: Path, destination: Path) -> None:
    """Create and validate an atomic SQLite backup, including committed WAL data."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    staged = destination.with_name(f".{destination.name}.{os.getpid()}.{time.time_ns()}.tmp")
    source_connection: sqlite3.Connection | None = None
    staged_connection: sqlite3.Connection | None = None
    try:
        source_connection = sqlite3.connect(_sqlite_readonly_uri(source), uri=True, timeout=30)
        quick_check = [str(row[0]) for row in source_connection.execute("PRAGMA quick_check").fetchall()]
        if quick_check != ["ok"]:
            raise ValueError(f"SQLite quick_check failed for {source}: {', '.join(quick_check)}")
        staged_connection = sqlite3.connect(staged, timeout=30)
        source_connection.backup(staged_connection)
        copied_check = [str(row[0]) for row in staged_connection.execute("PRAGMA quick_check").fetchall()]
        if copied_check != ["ok"]:
            raise ValueError(f"SQLite backup validation failed for {source}: {', '.join(copied_check)}")
        staged_connection.close()
        staged_connection = None
        source_connection.close()
        source_connection = None
        staged.chmod(0o600)
        os.replace(staged, destination)
    finally:
        if staged_connection is not None:
            staged_connection.close()
        if source_connection is not None:
            source_connection.close()
        staged.unlink(missing_ok=True)
        Path(str(staged) + "-wal").unlink(missing_ok=True)
        Path(str(staged) + "-shm").unlink(missing_ok=True)


def _copy_renamed_root(source: Path, destination: Path) -> dict[str, Any]:
    """Atomically copy one legacy NetOps XDG root into its Netrune root."""
    if not source.is_dir():
        return {"action": "source-not-found", "source": str(source), "destination": str(destination)}
    if destination.exists():
        return {"action": "skipped-existing-destination", "source": str(source), "destination": str(destination)}
    destination.parent.mkdir(parents=True, exist_ok=True)
    staged = destination.with_name(f".{destination.name}.{os.getpid()}.{time.time_ns()}.migration")
    copied_databases: list[str] = []
    try:
        shutil.copytree(
            source,
            staged,
            symlinks=True,
            ignore=shutil.ignore_patterns("netops.sqlite3", "netops.sqlite3-wal", "netops.sqlite3-shm"),
        )
        for database in source.rglob("netops.sqlite3"):
            relative = database.relative_to(source)
            target = staged / relative.parent / "netrune.sqlite3"
            _sqlite_snapshot(database, target)
            copied_databases.append(str(relative))
        os.replace(staged, destination)
    finally:
        if staged.exists():
            shutil.rmtree(staged)
    return {
        "action": "copied",
        "source": str(source),
        "destination": str(destination),
        "sqlite_backups": copied_databases,
    }


def migrate_netops_xdg_roots(home: Path) -> dict[str, Any]:
    """Perform the one-time, non-destructive NetOps-to-Netrune state copy."""
    if environment_value("NETRUNE_DISABLE_LEGACY_STATE_MIGRATION", default="").lower() in {"1", "true", "yes"}:
        return {"action": "disabled", "roots": []}
    explicit = any(
        os.environ.get(name, "").strip()
        for name in (
            "NETRUNE_CONFIG_DIR", "NETRUNE_STATE_DIR", "NETRUNE_CACHE_DIR", "NETRUNE_DATA_DIR",
            "NETOPS_CONFIG_DIR", "NETOPS_STATE_DIR", "NETOPS_CACHE_DIR", "NETOPS_DATA_DIR",
        )
    )
    if explicit:
        return {"action": "explicit-paths", "roots": []}
    roots = []
    for variable in ("XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME"):
        roots.append(_copy_renamed_root(_xdg(home, variable, "netops"), _xdg(home, variable, "netrune")))
    copied = [row for row in roots if row["action"] == "copied"]
    if copied:
        state_root = _xdg(home, "XDG_STATE_HOME", "netrune")
        state_root.mkdir(parents=True, exist_ok=True)
        manifest = {
            "schema_version": 1,
            "migration": "netops-to-netrune",
            "recorded_at": int(time.time()),
            "recorded_at_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "source_files_unchanged": True,
            "roots": roots,
        }
        _atomic_write(state_root / "migration-from-netops.json", json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return {"action": "copied" if copied else "not-needed", "roots": roots}


def _migration_backup_path(database: Path) -> Path:
    backup_dir = database.parent / "migration-backups"
    backup_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    candidate = backup_dir / f"{database.name}.pre-legacy-import-{stamp}.bak"
    sequence = 1
    while candidate.exists():
        candidate = backup_dir / f"{database.name}.pre-legacy-import-{stamp}-{sequence}.bak"
        sequence += 1
    return candidate


def _migrate_legacy_database(source: Path, destination: Path) -> dict[str, Any]:
    """Import legacy SQLite state without overwriting a populated profile."""
    if not source.is_file():
        return {"action": "source-not-found", "source": None, "destination_before": None, "backup": ""}

    source_summary = _sqlite_summary(source)
    destination_summary = _sqlite_summary(destination) if destination.is_file() else None
    if destination_summary and int(destination_summary["data_rows"]) > 0:
        return {
            "action": "skipped-populated-destination",
            "source": source_summary,
            "destination_before": destination_summary,
            "backup": "",
        }
    if int(source_summary["data_rows"]) == 0:
        return {
            "action": "skipped-empty-source",
            "source": source_summary,
            "destination_before": destination_summary,
            "backup": "",
        }

    candidate = destination.with_name(f".{destination.name}.{os.getpid()}.legacy-import")
    candidate.unlink(missing_ok=True)
    _sqlite_snapshot(source, candidate)
    backup = ""
    try:
        if destination_summary is not None:
            checkpoint = sqlite3.connect(destination, timeout=30)
            try:
                result = checkpoint.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
                if result and int(result[0]) != 0:
                    raise RuntimeError(f"destination database is busy: {destination}")
            finally:
                checkpoint.close()
            backup_path = _migration_backup_path(destination)
            _sqlite_snapshot(destination, backup_path)
            backup = str(backup_path)
        for suffix in ("-wal", "-shm"):
            Path(str(destination) + suffix).unlink(missing_ok=True)
        os.replace(candidate, destination)
        destination.chmod(0o600)
    finally:
        candidate.unlink(missing_ok=True)
        Path(str(candidate) + "-wal").unlink(missing_ok=True)
        Path(str(candidate) + "-shm").unlink(missing_ok=True)

    return {
        "action": "replaced-schema-only-destination" if destination_summary is not None else "copied",
        "source": source_summary,
        "destination_before": destination_summary,
        "destination_after": _sqlite_summary(destination),
        "backup": backup,
    }


def _looks_secret_name(name: str) -> bool:
    lowered = name.lower()
    return any(token in lowered for token in ("password", "passwd", "secret", "token", "api_key", "private_key"))


def flatten_profile(payload: Mapping[str, Any]) -> dict[str, str]:
    values: dict[str, str] = {}
    for section, item in payload.items():
        if section == "schema_version":
            continue
        if isinstance(item, Mapping):
            for key, value in item.items():
                if isinstance(value, list):
                    values[str(key)] = ",".join(str(entry) for entry in value)
                elif isinstance(value, bool):
                    values[str(key)] = "true" if value else "false"
                elif value is not None:
                    values[str(key)] = str(value)
        elif item is not None:
            values[str(section)] = str(item)
    return values


NEUTRAL_PROFILE = """schema_version = 1

[network]
subnets = ""
core_switch_ip = ""
core_iperf_server = ""
target_abbreviation_prefix = ""

[access]
ssh_user = ""

[identity]
strip_prefixes = []
ap_similarity_threshold = 85
switch_similarity_threshold = 75
continuity_window_days = 14
continuity_confidence_floor = 55
continuity_cluster_min_members = 3
continuity_attention_ttl_days = 30

[discovery]
cisco_wlc_ip = ""
cisco_wlc_ap_ip_filter = ""
cisco_wlc_ap_name_contains = ""
cisco_wlc_ap_name_prefix = ""
ruckus_vsz_ip = ""

[policy]
ssh_host_key_mode = "accept-new"
device_writes_enabled = false
plugin_writes_enabled = false
vault_password_ttl_hours = 72
vault_expiry_window_minutes = 20
vault_expiry_warning_hours = 12
"""


COMPAT_CONFIG = """# Netrune profile compatibility configuration
subnets=""
core_switch_ip=""
core_iperf_server=""
target_abbreviation_prefix=""
ssh_user=""
cisco_wlc_ip=""
cisco_wlc_ap_ip_filter=""
cisco_wlc_ap_name_contains=""
cisco_wlc_ap_name_prefix=""
ruckus_vsz_ip=""
ssh_host_key_mode="accept-new"
device_writes_enabled="false"
plugin_writes_enabled="false"
vault_password_ttl_hours="72"
vault_expiry_window_minutes="20"
vault_expiry_warning_hours="12"
"""


@dataclass(frozen=True)
class ProfileLayout:
    name: str
    home: Path
    config_root: Path
    state_root: Path
    cache_root: Path
    data_root: Path
    config_dir: Path
    state_dir: Path
    cache_dir: Path
    data_dir: Path
    explicit_legacy_paths: bool = False

    @classmethod
    def resolve(cls, selected: str = "", home: Path | None = None) -> "ProfileLayout":
        home = Path(home or Path.home())
        explicit_config = environment_value("NETRUNE_CONFIG_DIR", "NETOPS_CONFIG_DIR").strip()
        explicit_cache = environment_value("NETRUNE_CACHE_DIR", "NETOPS_CACHE_DIR").strip()
        selected = selected or environment_value("NETRUNE_PROFILE", "NETOPS_PROFILE")
        config_root = _xdg(home, "XDG_CONFIG_HOME", "netrune")
        active_file = config_root / "active_profile"
        if not selected and active_file.is_file():
            selected = active_file.read_text(encoding="utf-8", errors="ignore").strip()
        name = profile_name(selected or DEFAULT_PROFILE)
        if explicit_config or explicit_cache:
            config_dir = Path(explicit_config or config_root).expanduser()
            cache_dir = Path(explicit_cache or _xdg(home, "XDG_CACHE_HOME", "netrune")).expanduser()
            state_dir = Path(environment_value("NETRUNE_STATE_DIR", "NETOPS_STATE_DIR", str(cache_dir))).expanduser()
            data_dir = Path(environment_value("NETRUNE_DATA_DIR", "NETOPS_DATA_DIR", str(state_dir))).expanduser()
            return cls(name, home, config_dir, state_dir, cache_dir, data_dir, config_dir, state_dir, cache_dir, data_dir, True)
        state_root = _xdg(home, "XDG_STATE_HOME", "netrune")
        cache_root = _xdg(home, "XDG_CACHE_HOME", "netrune")
        data_root = _xdg(home, "XDG_DATA_HOME", "netrune")
        return cls(
            name,
            home,
            config_root,
            state_root,
            cache_root,
            data_root,
            config_root / "profiles" / name,
            state_root / "profiles" / name,
            cache_root / "profiles" / name,
            data_root / "profiles" / name,
            False,
        )

    def to_dict(self) -> dict[str, Any]:
        return {key: str(value) if isinstance(value, Path) else value for key, value in asdict(self).items()}


class ProfileStore:
    def __init__(self, home: Path | None = None):
        self.home = Path(home or Path.home())
        self.rename_migration = migrate_netops_xdg_roots(self.home)
        self.base = ProfileLayout.resolve(home=self.home)

    @property
    def active_file(self) -> Path:
        return self.base.config_root / "active_profile"

    def active(self) -> str:
        return ProfileLayout.resolve(home=self.home).name

    def list(self) -> list[dict[str, Any]]:
        root = self.base.config_root / "profiles"
        active = self.active()
        rows: list[dict[str, Any]] = []
        if root.is_dir():
            for path in sorted(root.iterdir()):
                if path.is_dir() and PROFILE_NAME_RE.fullmatch(path.name):
                    profile_file = path / "profile.toml"
                    rows.append({
                        "name": path.name,
                        "active": path.name == active,
                        "configured": profile_file.is_file(),
                        "updated_at": int(profile_file.stat().st_mtime) if profile_file.is_file() else None,
                    })
        if not rows and self.base.explicit_legacy_paths:
            rows.append({"name": active, "active": True, "configured": (self.base.config_dir / "profile.toml").is_file(), "updated_at": None})
        return rows

    def layout(self, name: str) -> ProfileLayout:
        return ProfileLayout.resolve(profile_name(name), self.home)

    def ensure(self, name: str, *, activate: bool = False) -> ProfileLayout:
        layout = self.layout(name)
        for path in (layout.config_dir, layout.state_dir, layout.cache_dir, layout.data_dir):
            path.mkdir(parents=True, exist_ok=True)
            path.chmod(0o700)
        profile_file = layout.config_dir / "profile.toml"
        if not profile_file.exists():
            _atomic_write(profile_file, NEUTRAL_PROFILE)
        compat = layout.config_dir / "netsnmp.conf"
        if not compat.exists():
            _atomic_write(compat, COMPAT_CONFIG)
        (layout.config_dir / "channels").mkdir(mode=0o700, exist_ok=True)
        (layout.config_dir / "drivers").mkdir(mode=0o700, exist_ok=True)
        if activate:
            self.use(layout.name)
        return layout

    def use(self, name: str) -> ProfileLayout:
        layout = self.ensure(name)
        self.base.config_root.mkdir(parents=True, exist_ok=True)
        self.base.config_root.chmod(0o700)
        _atomic_write(self.active_file, layout.name + "\n")
        return layout

    def load(self, name: str) -> dict[str, str]:
        layout = self.layout(name)
        profile_file = layout.config_dir / "profile.toml"
        if not profile_file.is_file():
            return {}
        with profile_file.open("rb") as stream:
            payload = tomllib.load(stream)
        if int(payload.get("schema_version") or 0) != PROFILE_SCHEMA_VERSION:
            raise ValueError(f"unsupported profile schema: {payload.get('schema_version')}")
        return flatten_profile(payload)

    def show(self, name: str) -> dict[str, Any]:
        layout = self.layout(name)
        return {
            "name": layout.name,
            "active": layout.name == self.active(),
            "layout": layout.to_dict(),
            "settings": self.load(layout.name),
        }

    def migrate_legacy(self, destination: str = "legacy-local") -> dict[str, Any]:
        destination = profile_name(destination)
        target = self.ensure(destination)
        legacy_config = self.home / ".config" / "netsnmp"
        legacy_cache = self.home / ".cache" / "netsnmp"
        copied: list[str] = []
        skipped: list[str] = []
        legacy_compat = legacy_config / "netsnmp.conf"
        target_compat = target.config_dir / "netsnmp.conf"
        legacy_environment = read_kv(legacy_config / ".env")
        imported_public_environment = {
            key: value
            for key, value in legacy_environment.items()
            if key in LEGACY_PUBLIC_ENV_KEYS and value
        }
        if legacy_compat.is_file() or imported_public_environment:
            existing_text = target_compat.read_text(encoding="utf-8", errors="replace") if target_compat.is_file() else ""
            existing = read_kv(target_compat)
            imported = {key: value for key, value in read_kv(legacy_compat).items() if not _looks_secret_name(key)}
            imported.update(imported_public_environment)
            if existing_text == COMPAT_CONFIG or not existing_text.strip():
                merged = {**existing, **imported}
            else:
                merged = {**imported, **existing}
            lines = ["# Netrune profile compatibility configuration migrated from legacy state"]
            lines.extend(f'{key}="{str(value).replace(chr(34), chr(92) + chr(34))}"' for key, value in sorted(merged.items()))
            rendered = "\n".join(lines) + "\n"
            if not target_compat.is_file() or target_compat.read_text(encoding="utf-8", errors="replace") != rendered:
                _atomic_write(target_compat, rendered)
                if legacy_compat.is_file():
                    copied.append(str(legacy_compat))
            elif legacy_compat.is_file():
                skipped.append(str(legacy_compat))
        for source, destination_dir in ((legacy_config, target.config_dir), (legacy_cache, target.cache_dir)):
            if not source.is_dir() or source.resolve() == destination_dir.resolve():
                continue
            for item in source.iterdir():
                if item.name == "netsnmp.conf":
                    continue
                if item.name == ".env":
                    skipped.append(str(item))
                    continue
                if source == legacy_cache and item.name in {"netops.sqlite3", "netops.sqlite3-wal", "netops.sqlite3-shm"}:
                    continue
                output = destination_dir / item.name
                if output.exists():
                    skipped.append(str(item))
                    continue
                if item.is_file():
                    shutil.copy2(item, output)
                    output.chmod(0o600)
                    copied.append(str(item))
                elif item.is_dir():
                    shutil.copytree(item, output, ignore=shutil.ignore_patterns(".env", "*.tmp", "*.lock"))
                    for copied_file in output.rglob("*"):
                        copied_file.chmod(0o700 if copied_file.is_dir() else 0o600)
                    copied.append(str(item))
        source_db = legacy_cache / "netops.sqlite3"
        destination_db = target.state_dir / "netrune.sqlite3"
        database_migration = _migrate_legacy_database(source_db, destination_db)
        if database_migration["action"] in {"copied", "replaced-schema-only-destination"}:
            copied.append(str(source_db))
        elif source_db.is_file():
            skipped.append(str(source_db))
        pending_secrets = sorted(
            key for key, value in legacy_environment.items()
            if value and key not in LEGACY_PUBLIC_ENV_KEYS
        )
        stamp = int(time.time())
        manifest = {
            "schema_version": 2,
            "source_config": str(legacy_config),
            "source_cache": str(legacy_cache),
            "destination_profile": destination,
            "copied": copied,
            "skipped": skipped,
            "pending_secret_names": pending_secrets,
            "imported_public_keys": sorted(imported_public_environment),
            "database_migration": database_migration,
            "source_files_unchanged": True,
            "recorded_at": stamp,
        }
        manifest_text = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
        _atomic_write(target.state_dir / "legacy-migration.json", manifest_text)
        manifest["manifest_sha256"] = hashlib.sha256(manifest_text.encode()).hexdigest()
        return manifest


def profile_environment(layout: ProfileLayout) -> dict[str, str]:
    canonical = {
        "NETRUNE_PROFILE": layout.name,
        "NETRUNE_CONFIG_DIR": str(layout.config_dir),
        "NETRUNE_STATE_DIR": str(layout.state_dir),
        "NETRUNE_CACHE_DIR": str(layout.cache_dir),
        "NETRUNE_DATA_DIR": str(layout.data_dir),
        "NETRUNE_SQLITE_DB": str(layout.state_dir / "netrune.sqlite3"),
        "NETRUNE_SSH_KNOWN_HOSTS_FILE": str(layout.config_dir / "known_hosts"),
        "NETRUNE_SECRETS_FILE": str(layout.data_dir / "secrets.gpg"),
        "NETRUNE_AI_ALIASES": str(layout.config_dir / "aliases.yaml"),
        "NETRUNE_AUTO_CONFIGURE": "false",
    }
    compatibility = {key.replace("NETRUNE_", "NETOPS_", 1): value for key, value in canonical.items()}
    return {**compatibility, **canonical}
