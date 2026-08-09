"""Trusted, explicitly enabled Python plugin discovery for NetOps."""

from __future__ import annotations

import json
import os
import re
import stat
import tomllib
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path
from typing import Any, Iterable

from netops_platform.contracts import PluginDescriptorV1


PLUGIN_API_VERSION = "1"
PLUGIN_GROUPS = (
    "netops.ingest",
    "netops.device_drivers",
    "netops.parsers",
    "netops.exporters",
)
PLUGIN_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    staged = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    staged.write_text(content, encoding="utf-8")
    staged.chmod(0o600)
    os.replace(staged, path)


@dataclass(frozen=True)
class LoadedPlugin:
    descriptor: PluginDescriptorV1
    implementation: Any | None = None


class PluginManager:
    """Discovers standard entry points without importing disabled plugins."""

    def __init__(self, config_dir: Path):
        self.config_dir = Path(config_dir)
        self.state_file = self.config_dir / "plugins.toml"

    def _enabled(self) -> set[str]:
        if not self.state_file.is_file():
            return set()
        info = self.state_file.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError("plugins.toml must be a current-user regular file with mode 0600 or stricter")
        with self.state_file.open("rb") as stream:
            payload = tomllib.load(stream)
        if int(payload.get("schema_version") or 0) != 1:
            raise ValueError("plugins.toml schema_version must be 1")
        plugins = payload.get("plugins", {})
        if not isinstance(plugins, dict) or not isinstance(plugins.get("enabled", []), list):
            raise ValueError("plugins.toml plugins.enabled must be an array")
        values = {str(value).strip() for value in plugins.get("enabled", []) if str(value).strip()}
        for plugin_id in values:
            self._split_plugin_id(plugin_id)
        return values

    def _write_enabled(self, enabled: Iterable[str]) -> None:
        values = sorted(set(enabled))
        for plugin_id in values:
            self._split_plugin_id(plugin_id)
        rendered = ", ".join(json.dumps(value) for value in values)
        _atomic_write(
            self.state_file,
            "schema_version = 1\n\n[plugins]\n"
            f"enabled = [{rendered}]\n",
        )

    @staticmethod
    def plugin_id(group: str, name: str) -> str:
        return f"{group}:{name}"

    @staticmethod
    def _split_plugin_id(plugin_id: str) -> tuple[str, str]:
        group, separator, name = str(plugin_id).partition(":")
        if not separator or group not in PLUGIN_GROUPS or not PLUGIN_NAME_RE.fullmatch(name):
            raise ValueError("plugin id must be <supported-group>:<entry-point-name>")
        return group, name

    def _entry_points(self) -> list[Any]:
        discovered = metadata.entry_points()
        rows: list[Any] = []
        for group in PLUGIN_GROUPS:
            if hasattr(discovered, "select"):
                rows.extend(discovered.select(group=group))
            else:  # pragma: no cover - compatibility for old importlib.metadata
                rows.extend(discovered.get(group, ()))
        return rows

    @staticmethod
    def _distribution(entry_point: Any) -> tuple[str, str]:
        distribution = getattr(entry_point, "dist", None)
        if distribution is None:
            return "unknown", "unknown"
        name = str(distribution.metadata.get("Name") or "unknown")
        return name, str(distribution.version or "unknown")

    def discover(self) -> list[PluginDescriptorV1]:
        enabled = self._enabled()
        entries = self._entry_points()
        counts: dict[tuple[str, str], int] = {}
        for entry in entries:
            key = (entry.group, entry.name)
            counts[key] = counts.get(key, 0) + 1
        rows: list[PluginDescriptorV1] = []
        for entry in sorted(entries, key=lambda item: (item.group, item.name, item.value)):
            distribution, version = self._distribution(entry)
            plugin_id = self.plugin_id(entry.group, entry.name)
            collision = counts[(entry.group, entry.name)] > 1
            rows.append(PluginDescriptorV1(
                name=entry.name,
                distribution=distribution,
                version=version,
                group=entry.group,
                entry_point=entry.value,
                api_version="unknown",
                enabled=plugin_id in enabled,
                source=f"distribution:{distribution}",
                load_status="collision" if collision else ("enabled" if plugin_id in enabled else "disabled"),
                error="multiple installed distributions expose this group/name" if collision else "",
            ))
        discovered_ids = {self.plugin_id(item.group, item.name) for item in rows}
        for plugin_id in sorted(enabled - discovered_ids):
            group, name = self._split_plugin_id(plugin_id)
            rows.append(PluginDescriptorV1(
                name=name,
                distribution="unknown",
                version="unknown",
                group=group,
                entry_point="unknown",
                api_version="unknown",
                enabled=True,
                source="profile-state",
                load_status="missing",
                error="enabled entry point is not installed",
            ))
        return rows

    def descriptor(self, plugin_id: str) -> PluginDescriptorV1:
        self._split_plugin_id(plugin_id)
        matches = [
            descriptor for descriptor in self.discover()
            if self.plugin_id(descriptor.group, descriptor.name) == plugin_id
        ]
        if len(matches) != 1:
            if not matches:
                raise ValueError(f"plugin not found: {plugin_id}")
            raise ValueError(f"plugin id is ambiguous: {plugin_id}")
        return matches[0]

    def set_enabled(self, plugin_id: str, enabled: bool) -> PluginDescriptorV1:
        self.descriptor(plugin_id)
        current = self._enabled()
        previous = set(current)
        if enabled:
            current.add(plugin_id)
        else:
            current.discard(plugin_id)
        self._write_enabled(current)
        if enabled:
            loaded = [
                item.descriptor for item in self.load_enabled()
                if self.plugin_id(item.descriptor.group, item.descriptor.name) == plugin_id
            ]
            if len(loaded) != 1 or loaded[0].load_status != "loaded":
                self._write_enabled(previous)
                detail = loaded[0].error if loaded else "plugin did not load"
                raise ValueError(f"plugin could not be enabled: {detail}")
            return loaded[0]
        return self.descriptor(plugin_id)

    @staticmethod
    def _api_version(implementation: Any) -> str:
        value = getattr(implementation, "NETOPS_PLUGIN_API_VERSION", None)
        if value is None and hasattr(implementation, "plugin_descriptor"):
            descriptor = implementation.plugin_descriptor()
            value = descriptor.get("api_version") if isinstance(descriptor, dict) else getattr(descriptor, "api_version", None)
        return str(value or "")

    @staticmethod
    def _capabilities(implementation: Any) -> tuple[str, ...]:
        value = getattr(implementation, "NETOPS_PLUGIN_CAPABILITIES", ())
        if callable(value):
            value = value()
        return tuple(str(item) for item in (value or ()))

    @staticmethod
    def _validate_interface(group: str, implementation: Any) -> None:
        required = {
            "netops.ingest": "read_records",
            "netops.parsers": "parse",
            "netops.exporters": "export",
        }
        if group in required and not callable(getattr(implementation, required[group], None)):
            raise RuntimeError(f"{group} plugin must expose {required[group]}()")
        if group == "netops.device_drivers":
            from netops_platform.devices import DeviceDriver

            if not isinstance(implementation, DeviceDriver) and not callable(getattr(implementation, "netops_device_drivers", None)):
                raise RuntimeError("netops.device_drivers plugin must expose netops_device_drivers() or one DeviceDriver")

    def load_enabled(self, group: str = "") -> list[LoadedPlugin]:
        if group and group not in PLUGIN_GROUPS:
            raise ValueError(f"unsupported plugin group: {group}")
        enabled = self._enabled()
        descriptors = self.discover()
        collision_ids = {
            self.plugin_id(item.group, item.name)
            for item in descriptors if item.load_status == "collision"
        }
        output: list[LoadedPlugin] = [
            LoadedPlugin(item)
            for item in descriptors
            if item.enabled and item.load_status in {"collision", "missing"} and (not group or item.group == group)
        ]
        for entry in sorted(self._entry_points(), key=lambda item: (item.group, item.name, item.value)):
            plugin_id = self.plugin_id(entry.group, entry.name)
            if plugin_id not in enabled or plugin_id in collision_ids or (group and entry.group != group):
                continue
            distribution, version = self._distribution(entry)
            try:
                implementation = entry.load()
                api_version = self._api_version(implementation)
                if api_version != PLUGIN_API_VERSION:
                    raise RuntimeError(f"plugin API {api_version or 'missing'} is incompatible with {PLUGIN_API_VERSION}")
                capabilities = self._capabilities(implementation)
                normalized_capabilities = tuple(re.sub(r"[^a-z0-9]+", "-", value.strip().lower()).strip("-") for value in capabilities)
                prohibited = {"write", "shell", "subprocess", "process", "exec", "execute", "system"}
                if any(prohibited.intersection(value.split("-")) for value in normalized_capabilities):
                    raise RuntimeError("third-party write and shell capabilities are prohibited")
                self._validate_interface(entry.group, implementation)
                descriptor = PluginDescriptorV1(
                    name=entry.name,
                    distribution=distribution,
                    version=version,
                    group=entry.group,
                    entry_point=entry.value,
                    api_version=api_version,
                    enabled=True,
                    source=f"distribution:{distribution}",
                    capabilities=capabilities,
                    load_status="loaded",
                )
                output.append(LoadedPlugin(descriptor, implementation))
            except Exception as exc:
                output.append(LoadedPlugin(PluginDescriptorV1(
                    name=entry.name,
                    distribution=distribution,
                    version=version,
                    group=entry.group,
                    entry_point=entry.value,
                    api_version="unknown",
                    enabled=True,
                    source=f"distribution:{distribution}",
                    load_status="failed",
                    error=str(exc),
                )))
        return output
