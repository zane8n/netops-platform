"""Private, atomic persistence for local TUI preferences."""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
from typing import Any


DEFAULTS: dict[str, Any] = {
    "preferences_version": 2,
    "theme": "auto",
    "density": "compact",
    "ascii_borders": False,
    "last_view": "operations",
    "pinned_entities": [],
    "pinned_actions": [],
    "saved_filters": {},
    "visible_columns": {},
}


class PreferenceStore:
    def __init__(self, path: Path | None = None):
        configured = os.environ.get("NETOPS_TUI_CONFIG", "").strip()
        config_root = Path(os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config")))
        self.path = path or (Path(configured).expanduser() if configured else config_root / "netops" / "tui.json")

    def load(self) -> dict[str, Any]:
        payload = dict(DEFAULTS)
        try:
            stored = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(stored, dict):
                try:
                    stored_version = int(stored.get("preferences_version") or 1)
                except (TypeError, ValueError):
                    stored_version = 1
                if stored_version < 2:
                    if stored.get("theme") == "netops-dark":
                        stored["theme"] = "auto"
                    if stored.get("last_view") == "overview":
                        stored["last_view"] = "operations"
                payload.update(stored)
        except (OSError, ValueError, TypeError):
            pass
        return self._normalize(payload)

    @staticmethod
    def _normalize(payload: dict[str, Any]) -> dict[str, Any]:
        normalized = dict(DEFAULTS)
        theme = str(payload.get("theme") or "")
        normalized["theme"] = theme if theme in {"auto", "netops-dark", "netops-light"} else DEFAULTS["theme"]
        density = str(payload.get("density") or "")
        normalized["density"] = density if density in {"compact", "comfortable"} else DEFAULTS["density"]
        normalized["ascii_borders"] = bool(payload.get("ascii_borders", False))
        normalized["last_view"] = str(payload.get("last_view") or DEFAULTS["last_view"])[:40]
        for key in ("pinned_entities", "pinned_actions"):
            values = payload.get(key) if isinstance(payload.get(key), list) else []
            normalized[key] = [str(value)[:200] for value in values[:100] if str(value).strip()]
        filters = payload.get("saved_filters") if isinstance(payload.get("saved_filters"), dict) else {}
        normalized["saved_filters"] = {str(key)[:100]: str(value)[:500] for key, value in list(filters.items())[:100] if str(value)}
        columns = payload.get("visible_columns") if isinstance(payload.get("visible_columns"), dict) else {}
        normalized["visible_columns"] = {
            str(key)[:100]: [str(value)[:100] for value in values[:100]]
            for key, values in list(columns.items())[:100]
            if isinstance(values, list)
        }
        return normalized

    def save(self, payload: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            self.path.parent.chmod(0o700)
        except OSError:
            pass
        merged = self._normalize(payload)
        descriptor, staged_name = tempfile.mkstemp(prefix=".tui.", suffix=".tmp", dir=str(self.path.parent))
        staged = Path(staged_name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(merged, handle, indent=2, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(staged, self.path)
            self.path.chmod(0o600)
        finally:
            if staged.exists():
                staged.unlink()
