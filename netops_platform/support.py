"""Redacted support-bundle creation."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import tarfile
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from netops_platform import version as platform_version


REDACT_KEY = re.compile(r"pass|secret|token|community|credential|private[_-]?key|api[_-]?key", re.I)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
MAC_RE = re.compile(r"(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b|\b[0-9a-f]{4}(?:\.[0-9a-f]{4}){2}\b")


def _redact(value: Any, key: str = "") -> Any:
    if REDACT_KEY.search(key):
        return "[redacted]" if value not in (None, "") else value
    if isinstance(value, dict):
        return {str(name): _redact(item, str(name)) for name, item in value.items()}
    if isinstance(value, list):
        return [_redact(item) for item in value]
    if isinstance(value, str):
        value = IP_RE.sub("[ip]", value)
        value = MAC_RE.sub("[mac]", value)
        value = value.replace(str(Path.home()), "~")
    return value


def _token(value: Any, prefix: str) -> str:
    text = str(value or "")
    if not text:
        return ""
    return f"{prefix}-{hashlib.sha256(text.encode('utf-8')).hexdigest()[:12]}"


def _configuration_summary(values: dict[str, Any]) -> dict[str, Any]:
    visible = {
        "ssh_host_key_mode", "device_writes_enabled", "plugin_writes_enabled",
        "vault_password_ttl_hours", "vault_expiry_window_minutes",
        "vault_expiry_warning_hours", "ap_similarity_threshold",
        "switch_similarity_threshold",
    }
    return {
        key: value if key in visible else ("configured" if value not in (None, "", [], {}) else "not-configured")
        for key, value in values.items()
    }


def _rfc3339(value: int) -> str:
    return datetime.fromtimestamp(value, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _database_summary(state: Any) -> dict[str, Any]:
    """Return operational metadata without profile names or filesystem paths."""
    status = state.db_status_payload()
    return {
        "ok": bool(status.get("ok")),
        "schema_version": status.get("schema_version"),
        "expected_schema_version": status.get("expected_schema_version"),
        "counts": status.get("counts") or {},
        "files": status.get("files") or {},
    }


def _built_in_driver_reports(app: Any) -> list[dict[str, Any]]:
    registry = getattr(app, "device_drivers", None)
    if registry is None:
        # Compatibility for v8 applications created before per-profile registries.
        from netops_platform.devices import REGISTRY

        registry = REGISTRY
    return [driver.report() for driver in registry.all() if driver.source == "built-in"]


def create_support_bundle(app: Any, output: Path | None = None) -> dict[str, Any]:
    stamp = int(time.time())
    output = Path(output or (app.paths.data_dir / "support" / f"netops-support-{stamp}.tar.gz"))
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="netops-support-") as directory:
        root = Path(directory) / "netops-support"
        root.mkdir()
        payloads = {
            "system.json": {
                "recorded_at": stamp,
                "recorded_at_iso": _rfc3339(stamp),
                "python": platform.python_version(),
                "platform": platform.platform(),
                "wsl": "microsoft" in platform.release().lower(),
                "version": platform_version(),
                "profile": _token(app.paths.profile, "profile"),
            },
            "configuration.json": _configuration_summary(app.config.public_safe()),
            "database.json": _database_summary(app.state),
            "integrity.json": app.state.integrity_check(),
            "drivers.json": {
                "built_in": _built_in_driver_reports(app),
                "profile_manifests": [
                    {
                        "status": row.get("status"),
                        "family": _token(row.get("family"), "driver"),
                        "error": _redact(row.get("error") or ""),
                    }
                    for row in app.driver_manifest_report
                ],
            },
            "plugins.json": [
                {
                    "group": descriptor.group,
                    "enabled": descriptor.enabled,
                    "api_version": descriptor.api_version,
                    "load_status": descriptor.load_status,
                    "error": _redact(descriptor.error),
                }
                for descriptor in app.plugin_manager.discover()
            ],
            "recent_runs.json": {
                "ingest": app.state.rows("SELECT status,COUNT(*) AS runs,SUM(received) AS received,SUM(accepted) AS accepted,SUM(duplicates) AS duplicates,SUM(rejected) AS rejected,MAX(finished_at) AS last_finished_at FROM ingest_runs GROUP BY status ORDER BY status"),
                "paths": app.state.rows("SELECT status,mode,COUNT(*) AS runs,MIN(confidence) AS minimum_confidence,MAX(finished_at) AS last_finished_at FROM path_runs GROUP BY status,mode ORDER BY status,mode"),
                "diagnostics": app.state.rows("SELECT kind,status,COUNT(*) AS runs,MAX(created_at) AS last_recorded_at FROM diagnostic_runs GROUP BY kind,status ORDER BY kind,status"),
            },
            "README.txt": "This bundle is redacted. Inventory rows, raw evidence, secret values, known hosts, aliases, and configuration backups are excluded.\n",
        }
        manifest: dict[str, str] = {}
        for name, payload in payloads.items():
            path = root / name
            if isinstance(payload, str):
                content = payload
            else:
                content = json.dumps(_redact(payload), indent=2, sort_keys=True, default=str) + "\n"
            path.write_text(content, encoding="utf-8")
            manifest[name] = hashlib.sha256(content.encode("utf-8")).hexdigest()
        (root / "MANIFEST.sha256.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        staged = output.with_name(f".{output.name}.{os.getpid()}.tmp")
        descriptor = os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(descriptor)
        with tarfile.open(staged, "w:gz") as archive:
            archive.add(root, arcname=root.name)
        os.replace(staged, output)
        output.chmod(0o600)
    return {
        "ok": True,
        "path": str(output),
        "sha256": _file_sha256(output),
        "bytes": output.stat().st_size,
        "recorded_at": stamp,
        "recorded_at_iso": _rfc3339(stamp),
        "redacted": True,
        "excluded": ["inventory", "raw evidence", "secrets", "known hosts", "aliases", "configuration backups"],
    }


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
