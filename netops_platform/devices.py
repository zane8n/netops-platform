#!/usr/bin/env python3
"""Extensible device-family detection, capabilities, and command planning.

The public core deals in semantic operations such as ``mac_lookup`` or
``neighbors``.  This module is the only place that translates those operations
into vendor CLI commands.  Drivers are deliberately data-oriented and can be
registered by future integrations without changing traversal or inventory
code.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys
import tomllib
from dataclasses import asdict, dataclass, field, replace
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


class UnsupportedDeviceAction(ValueError):
    """Raised when a family cannot safely provide a semantic operation."""


def _evidence(*values: Any) -> str:
    return " ".join(str(value or "") for value in values).upper()


def _clean_mac(value: Any) -> str:
    return re.sub(r"[^0-9a-f]", "", str(value or "").lower())


def format_mac(value: Any, style: str) -> str:
    clean = _clean_mac(value)
    if len(clean) != 12:
        raise ValueError("MAC address must contain exactly 12 hexadecimal digits")
    if style == "dotted":
        return ".".join(clean[index:index + 4] for index in range(0, 12, 4))
    if style == "hyphen-six":
        return f"{clean[:6]}-{clean[6:]}"
    if style == "colon":
        return ":".join(clean[index:index + 2] for index in range(0, 12, 2))
    return clean


@dataclass(frozen=True)
class DeviceDetection:
    family: str
    vendor: str
    os_name: str
    device_kind: str
    confidence: int
    reasons: Tuple[str, ...] = ()
    model_profile: str = "generic"
    firmware_profile: str = "unverified"

    def as_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["reasons"] = list(self.reasons)
        return payload


@dataclass(frozen=True)
class DeviceDriver:
    family: str
    vendor: str
    os_name: str
    device_kind: str
    support_level: str
    pager_commands: Tuple[str, ...] = ()
    logout_commands: Tuple[str, ...] = ("exit",)
    command_templates: Mapping[str, Tuple[str, ...]] = field(default_factory=dict)
    capabilities: Mapping[str, str] = field(default_factory=dict)
    parser_templates: Mapping[str, str] = field(default_factory=dict)
    detection_patterns: Mapping[str, Tuple[str, ...]] = field(default_factory=dict)
    detection_confidence: int = 0
    firmware_profiles: Tuple[str, ...] = ()
    source: str = "built-in"
    notes: Tuple[str, ...] = ()

    def capability(self, name: str) -> str:
        return str(self.capabilities.get(name) or "unsupported")

    def supports(self, name: str) -> bool:
        return self.capability(name) not in {"unsupported", "inventory-only"}

    def _render(self, operation: str, values: Mapping[str, Any]) -> List[str]:
        templates = self.command_templates.get(operation)
        if templates is None:
            raise UnsupportedDeviceAction(
                f"{operation.replace('_', ' ')} is not defined for {self.family}"
            )
        return [template.format(**values) for template in templates]

    def command_plan(self, operation: str, **values: Any) -> List[str]:
        """Return a complete non-interactive command stream for an operation."""
        operation = operation.strip().lower().replace("-", "_")
        commands: List[str] = list(self.pager_commands)
        if operation == "show":
            command = str(values.get("command") or "").strip()
            if not command:
                raise ValueError("show operation requires a command")
            commands.append(command)
        elif operation == "config":
            requested = [str(item).strip() for item in values.get("commands") or [] if str(item).strip()]
            if not requested:
                raise ValueError("config operation requires at least one command")
            approved_profile = str(values.get("firmware_profile") or "")
            writes_enabled = bool(values.get("writes_enabled"))
            if (
                self.source != "built-in"
                or self.capability("configuration") != "firmware-gated"
                or approved_profile not in self.firmware_profiles
                or not writes_enabled
            ):
                raise UnsupportedDeviceAction(
                    f"configuration is not enabled for a certified {self.family} firmware profile"
                )
            commands.extend(self._render("config_enter", values))
            commands.extend(requested)
            commands.extend(self._render("config_exit", values))
            commands.extend(self._render("save", values))
        else:
            if operation == "mac_lookup":
                values = dict(values)
                values.setdefault("mac_dotted", format_mac(values.get("mac"), "dotted"))
                values.setdefault("mac_hyphen", format_mac(values.get("mac"), "hyphen-six"))
                values.setdefault("mac_colon", format_mac(values.get("mac"), "colon"))
                values.setdefault("mac_plain", format_mac(values.get("mac"), "plain"))
            commands.extend(self._render(operation, values))
        commands.extend(self.logout_commands)
        return commands

    def report(self) -> Dict[str, Any]:
        return {
            "family": self.family,
            "vendor": self.vendor,
            "os_name": self.os_name,
            "device_kind": self.device_kind,
            "support_level": self.support_level,
            "capabilities": dict(sorted(self.capabilities.items())),
            "parser_templates": dict(sorted(self.parser_templates.items())),
            "detection_patterns": {
                key: list(values) for key, values in sorted(self.detection_patterns.items())
            },
            "detection_confidence": self.detection_confidence,
            "firmware_profiles": list(self.firmware_profiles),
            "source": self.source,
            "read_only": self.source != "built-in" or self.capability("configuration") != "firmware-gated",
            "notes": list(self.notes),
        }


class DeviceDriverRegistry:
    def __init__(self) -> None:
        self._drivers: Dict[str, DeviceDriver] = {}

    def register(self, driver: DeviceDriver, *, replace: bool = False) -> None:
        if driver.family in self._drivers and not replace:
            raise ValueError(f"device driver already registered: {driver.family}")
        self._drivers[driver.family] = driver

    def get(self, family: str) -> DeviceDriver:
        return self._drivers.get(str(family or "").lower(), self._drivers["unknown"])

    def all(self) -> List[DeviceDriver]:
        return [self._drivers[key] for key in sorted(self._drivers)]

    def clone(self) -> "DeviceDriverRegistry":
        registry = DeviceDriverRegistry()
        registry._drivers = dict(self._drivers)
        return registry

    def load_python_plugins(self, plugins: Iterable[Any]) -> List[Dict[str, Any]]:
        """Register enabled trusted drivers after enforcing external read-only policy."""
        reports: List[Dict[str, Any]] = []
        forbidden = {"config", "config_enter", "config_exit", "save", "vlan_write", "reload", "erase"}
        for loaded in plugins:
            descriptor = loaded.descriptor
            if descriptor.load_status != "loaded" or loaded.implementation is None:
                reports.append({
                    "status": descriptor.load_status,
                    "plugin": f"{descriptor.group}:{descriptor.name}",
                    "error": descriptor.error,
                })
                continue
            try:
                implementation = loaded.implementation
                provided = (
                    implementation.netops_device_drivers()
                    if callable(getattr(implementation, "netops_device_drivers", None))
                    else implementation
                )
                candidates = [provided] if isinstance(provided, DeviceDriver) else list(provided or ())
                if not candidates or any(not isinstance(driver, DeviceDriver) for driver in candidates):
                    raise ValueError("plugin must return one or more DeviceDriver values")
                normalized: List[DeviceDriver] = []
                families: set[str] = set()
                for driver in candidates:
                    if driver.family in families or driver.family in self._drivers:
                        raise ValueError(f"device driver already registered: {driver.family}")
                    families.add(driver.family)
                    if not driver.detection_patterns or not 1 <= int(driver.detection_confidence) <= 95:
                        raise ValueError(f"external driver requires bounded detection patterns: {driver.family}")
                    if any(str(operation).replace("-", "_") in forbidden for operation in driver.command_templates):
                        raise ValueError(f"external driver defines a write operation: {driver.family}")
                    for operation, commands in driver.command_templates.items():
                        for command in commands:
                            self._read_command(command, context=f"{driver.family}.{operation}")
                    for command in (*driver.pager_commands, *driver.logout_commands):
                        self._read_command(command, context=f"{driver.family}.session")
                    parsers = dict(driver.parser_templates)
                    if any(not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{1,127}", value) for value in parsers.values()):
                        raise ValueError(f"external driver parser identifiers are invalid: {driver.family}")
                    capabilities = dict(driver.capabilities)
                    capabilities["configuration"] = "unsupported"
                    capabilities["vlan_write"] = "unsupported"
                    normalized.append(replace(
                        driver,
                        support_level="external-read-only",
                        capabilities=capabilities,
                        firmware_profiles=(),
                        source=f"plugin:{descriptor.distribution}:{descriptor.name}",
                        notes=tuple(driver.notes) + ("Trusted Python plugin driver; writes are prohibited.",),
                    ))
                for driver in normalized:
                    self.register(driver)
                    reports.append({
                        "status": "loaded",
                        "family": driver.family,
                        "plugin": f"{descriptor.group}:{descriptor.name}",
                        "source": driver.source,
                    })
            except Exception as exc:
                reports.append({
                    "status": "rejected",
                    "plugin": f"{descriptor.group}:{descriptor.name}",
                    "error": str(exc),
                })
        return reports

    @staticmethod
    def _read_command(value: Any, *, context: str) -> str:
        command = str(value).strip()
        if not command or len(command) > 512:
            raise ValueError(f"invalid read command: {context}")
        if any(character in command for character in ("\n", "\r", "\x00", ";", "|", "&", "`", "$", ">", "<")):
            raise ValueError(f"unsafe read command: {context}")
        rendered = re.sub(r"\{[a-zA-Z_][a-zA-Z0-9_]*\}", "VALUE", command).strip().lower()
        read_prefixes = (
            "show ", "display ", "get ", "ping ", "traceroute ", "tracert ",
            "terminal length ", "terminal width ", "no page", "skip-page-display",
            "environment no more", "exit", "quit",
        )
        if not any(rendered == prefix.rstrip() or rendered.startswith(prefix) for prefix in read_prefixes):
            raise ValueError(f"declarative command is not an approved read operation: {context}")
        return command

    def load_declarative(self, directory: Path) -> List[Dict[str, Any]]:
        """Load local read-only command maps; no code or write operation is accepted."""
        reports: List[Dict[str, Any]] = []
        if not Path(directory).is_dir():
            return reports
        forbidden = {"config", "config_enter", "config_exit", "save", "vlan_write", "reload", "erase"}
        for path in sorted(Path(directory).glob("*.toml")):
            try:
                with path.open("rb") as stream:
                    payload = tomllib.load(stream)
                if int(payload.get("schema_version") or 0) != 1:
                    raise ValueError("schema_version must be 1")
                section = payload.get("driver") or {}
                family = str(section.get("family") or "").strip().lower()
                if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,62}", family):
                    raise ValueError("driver.family is invalid")
                raw_commands = payload.get("commands") or {}
                if any(str(operation).replace("-", "_") in forbidden for operation in raw_commands):
                    raise ValueError("declarative drivers cannot define write operations")
                templates: Dict[str, Tuple[str, ...]] = {}
                for operation, raw in raw_commands.items():
                    values = [raw] if isinstance(raw, str) else list(raw or [])
                    commands = tuple(
                        self._read_command(value, context=str(operation))
                        for value in values if str(value).strip()
                    )
                    if not commands:
                        raise ValueError(f"invalid read command template: {operation}")
                    templates[str(operation).replace("-", "_")] = commands
                pager_commands = tuple(
                    self._read_command(value, context="driver.pager_commands")
                    for value in section.get("pager_commands") or ()
                )
                logout_commands = tuple(
                    self._read_command(value, context="driver.logout_commands")
                    for value in section.get("logout_commands") or ("exit",)
                )
                capabilities = {str(key): str(value) for key, value in dict(payload.get("capabilities") or {}).items()}
                capabilities["configuration"] = "unsupported"
                capabilities["vlan_write"] = "unsupported"
                parsers = {str(key): str(value) for key, value in dict(payload.get("parsers") or {}).items()}
                if any(not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{1,127}", value) for value in parsers.values()):
                    raise ValueError("parser template identifiers must be stable lowercase IDs")
                raw_match = dict(payload.get("match") or {})
                confidence = int(raw_match.pop("confidence", 80))
                if not 1 <= confidence <= 95:
                    raise ValueError("match.confidence must be between 1 and 95")
                allowed_match_fields = {"any", "platform", "model", "sysdescr", "hostname", "device_kind"}
                if set(raw_match) - allowed_match_fields:
                    raise ValueError("match contains an unsupported evidence field")
                detection_patterns: Dict[str, Tuple[str, ...]] = {}
                for field_name, raw_patterns in raw_match.items():
                    values = [raw_patterns] if isinstance(raw_patterns, str) else list(raw_patterns or [])
                    patterns = tuple(str(value).strip() for value in values if str(value).strip())
                    if not patterns or any(len(pattern) > 256 for pattern in patterns):
                        raise ValueError(f"invalid match patterns for {field_name}")
                    for pattern in patterns:
                        try:
                            re.compile(pattern, re.I)
                        except re.error as exc:
                            raise ValueError(f"invalid match regex for {field_name}: {exc}") from exc
                    detection_patterns[field_name] = patterns
                if not detection_patterns:
                    raise ValueError("declarative drivers require at least one match pattern")
                driver = DeviceDriver(
                    family=family,
                    vendor=str(section.get("vendor") or "Third party"),
                    os_name=str(section.get("operating_system") or family),
                    device_kind=str(section.get("device_kind") or "switch"),
                    support_level="external-read-only",
                    pager_commands=pager_commands,
                    logout_commands=logout_commands,
                    command_templates=templates,
                    capabilities=capabilities,
                    parser_templates=parsers,
                    detection_patterns=detection_patterns,
                    detection_confidence=confidence,
                    source=f"profile:{path.name}",
                    notes=("External declarative driver; writes are prohibited.",),
                )
                self.register(driver)
                reports.append({"path": str(path), "family": family, "status": "loaded"})
            except Exception as exc:
                reports.append({"path": str(path), "status": "rejected", "error": str(exc)})
        return reports

    def detect(
        self,
        *,
        platform: Any = "",
        model: Any = "",
        sysdescr: Any = "",
        hostname: Any = "",
        device_kind: Any = "",
    ) -> DeviceDetection:
        evidence_fields = {
            "platform": str(platform or ""),
            "model": str(model or ""),
            "sysdescr": str(sysdescr or ""),
            "hostname": str(hostname or ""),
            "device_kind": str(device_kind or ""),
        }
        evidence = _evidence(*evidence_fields.values())
        reasons: List[str] = []

        def matched(pattern: str, reason: str) -> bool:
            if re.search(pattern, evidence, re.I):
                reasons.append(reason)
                return True
            return False

        external_matches: List[Tuple[int, str, Tuple[str, ...]]] = []
        for driver in self.all():
            if not driver.detection_patterns:
                continue
            matched_fields: List[str] = []
            for field_name, patterns in driver.detection_patterns.items():
                subject = evidence if field_name == "any" else evidence_fields[field_name]
                if any(re.search(pattern, subject, re.I) for pattern in patterns):
                    matched_fields.append(field_name)
            if matched_fields and len(matched_fields) == len(driver.detection_patterns):
                external_matches.append((driver.detection_confidence, driver.family, tuple(matched_fields)))
        if external_matches:
            confidence, family, fields = max(external_matches, key=lambda item: (item[0], item[1]))
            reasons.append("profile driver matched " + ", ".join(fields))
        elif matched(r"\b(?:SMARTZONE|VIRTUAL[ -]?SMARTZONE|VSZ|SZ100|SZ144|SZ300)\b", "SmartZone product marker"):
            family, confidence = "ruckus-smartzone", 98
        elif re.search(r"\b(?:RUCKUS|ZONEFLEX|UNLEASHED)\b", evidence, re.I) and re.search(
            r"\b(?:R\d{3,4}|T\d{3,4}|H\d{3,4}|AP)\b", evidence, re.I
        ):
            reasons.extend(("Ruckus wireless marker", "wireless access-point model or role"))
            family, confidence = "ruckus-ap", 94
        elif matched(r"\b(?:FASTIRON|FOUNDRY|BROCADE|RUCKUS|ICX\s*\d{4})\b", "FastIron/ICX product marker"):
            family, confidence = "ruckus-fastiron", 96 if "ICX" in evidence or "FASTIRON" in evidence else 86
        elif matched(r"\b(?:ARUBAOS-CX|AOS-CX|ARUBA[ -]?CX)\b", "Aruba AOS-CX operating-system marker") or matched(
            r"\bCX\s*(?:4100|6000|6100|6200|6300|6400|8100|8320|8325|8360|8400|9300|10000)\b",
            "Aruba CX platform marker",
        ):
            family, confidence = "aruba-aos-cx", 98
        elif matched(r"\b(?:ARUBA|PROCURVE|HEWLETT[ -]?PACKARD|HP)\b", "Aruba/ProCurve vendor marker"):
            # Generic Aruba evidence maps to AOS-S only when no CX marker exists.
            family, confidence = "aruba-aos-switch", 88
        elif matched(r"\b(?:NX-OS|NEXUS|N[3579]K|CISCO NEXUS)\b", "Cisco NX-OS platform marker"):
            family, confidence = "cisco-nxos", 98
        elif matched(r"\b(?:CISCO|IOS(?:-XE)?|CATALYST|WS-C\d|C\d{4})\b", "Cisco IOS platform marker"):
            family, confidence = "cisco-ios", 95
        else:
            family, confidence = "unknown", 0
            reasons.append("no registered family signature matched")
        driver = self.get(family)
        return DeviceDetection(
            family=driver.family,
            vendor=driver.vendor,
            os_name=driver.os_name,
            device_kind=driver.device_kind,
            confidence=confidence,
            reasons=tuple(reasons),
            model_profile=self._model_profile(family, evidence),
            firmware_profile=self._firmware_profile(family, evidence),
        )

    @staticmethod
    def _model_profile(family: str, evidence: str) -> str:
        patterns = {
            "cisco-nxos": ((r"\bN9K|NEXUS 9", "nexus-9000"), (r"\bN3K|NEXUS 3", "nexus-3000")),
            "cisco-ios": ((r"\bC9[2346]\d\d", "catalyst-9000"), (r"\bWS-C", "catalyst-classic")),
            "aruba-aos-cx": ((r"\bCX\s*6", "cx-6000-series"), (r"\bCX\s*8", "cx-8000-series")),
            "ruckus-fastiron": ((r"\bICX\s*7", "icx-7000-series"), (r"\bICX\s*6", "icx-6000-series")),
        }
        for pattern, profile in patterns.get(family, ()):
            if re.search(pattern, evidence, re.I):
                return profile
        return "generic"

    @staticmethod
    def _firmware_profile(family: str, evidence: str) -> str:
        patterns = {
            "cisco-nxos": ((r"NX-?OS(?:[^0-9]|:)+9\.", "nxos-9.x"), (r"NX-?OS(?:[^0-9]|:)+10\.", "nxos-10.x")),
            "cisco-ios": ((r"IOS XE[^0-9]*17\.", "ios-xe-17.x"), (r"IOS[^0-9]*15\.", "ios-15.x")),
            "aruba-aos-switch": ((r"\bWC\.16\.", "aos-s-16.x"),),
            "aruba-aos-cx": ((r"\b(?:(?:FL|LL|ML)\.)?10\.\d", "aos-cx-10.x"),),
            "ruckus-fastiron": ((r"\b08\.0\.", "fastiron-08.x"), (r"\b09\.0\.", "fastiron-09.x"), (r"\b10\.0\.", "fastiron-10.x")),
        }
        for pattern, profile in patterns.get(family, ()):
            if re.search(pattern, evidence, re.I):
                return profile
        return "unverified"


COMMON_READ_CAPABILITIES = {
    "inventory": "supported",
    "configuration_backup": "supported",
    "vlan_read": "supported",
    "mac_table": "supported",
    "lldp": "supported",
    "interface_health": "supported",
    "core_ping": "supported",
    "fdb": "supported",
    "vlan_membership": "supported",
    "stp": "supported",
    "lag": "supported",
    "svi": "supported",
    "vrf": "supported",
    "routes": "supported",
    "arp_nd": "supported",
    "interface_policy": "reference-only",
    "neighbors": "supported",
}


def _driver(
    family: str,
    vendor: str,
    os_name: str,
    *,
    support_level: str,
    pager: Sequence[str],
    logout: Sequence[str] = ("exit",),
    templates: Mapping[str, Sequence[str]],
    capabilities: Mapping[str, str],
    notes: Sequence[str] = (),
    device_kind: str = "switch",
    parser_templates: Mapping[str, str] | None = None,
    firmware_profiles: Sequence[str] = (),
) -> DeviceDriver:
    return DeviceDriver(
        family=family,
        vendor=vendor,
        os_name=os_name,
        device_kind=device_kind,
        support_level=support_level,
        pager_commands=tuple(pager),
        logout_commands=tuple(logout),
        command_templates={key: tuple(value) for key, value in templates.items()},
        capabilities=dict(capabilities),
        parser_templates=dict(parser_templates or {}),
        firmware_profiles=tuple(firmware_profiles),
        notes=tuple(notes),
    )


REGISTRY = DeviceDriverRegistry()

REGISTRY.register(_driver(
    "cisco-ios", "Cisco", "IOS/IOS-XE CLI", support_level="established-read",
    pager=("terminal length 0",),
    templates={
        "inventory": ("show version", "show inventory"),
        "backup": ("show running-config",),
        "vlan_inspect": ("show vlan id {vlan}", "show interfaces trunk"),
        "vlan_locate": ("show vlan id {vlan}", "show interfaces trunk"),
        "mac_lookup": ("show mac address-table | include {mac_dotted}",),
        "arp_lookup": ("show arp | include {lookup}",),
        "core_lookup": ("show arp | include {lookup}", "show mac address-table | include {lookup}"),
        "ping": ("ping {destination} repeat {count} timeout {timeout}",),
        "neighbors": ("show lldp neighbors detail", "show cdp neighbors detail"),
        "fdb": ("show mac address-table",),
        "vlan_membership": ("show vlan id {vlan}", "show interfaces trunk"),
        "stp": ("show spanning-tree vlan {vlan}",),
        "lag": ("show etherchannel summary",),
        "svi": ("show interfaces vlan {vlan}",),
        "vrf": ("show vrf",),
        "routes": ("show ip route {destination}", "show ipv6 route {destination}"),
        "arp_nd": ("show ip arp {destination}", "show ipv6 neighbors | include {destination}"),
        "interface_policy": ("show running-config interface {interface}", "show access-lists"),
        "interface_health": ("show interfaces {interface}",),
        "cable_status": ("show cable-diagnostics tdr interface {interface}",),
        "cable_start": ("test cable-diagnostics tdr interface {interface}",),
        "config_enter": ("configure terminal",),
        "config_exit": ("end",),
        "save": ("write memory",),
    },
    capabilities={**COMMON_READ_CAPABILITIES, "cdp": "supported", "cable_status": "supported", "cable_test": "supported", "configuration": "firmware-gated", "vlan_write": "firmware-gated"},
    firmware_profiles=("ios-15.x", "ios-xe-17.x"),
    notes=("Writes require an explicitly enabled profile and an accepted model/firmware fixture.",),
))

REGISTRY.register(_driver(
    "cisco-nxos", "Cisco", "NX-OS", support_level="established-read",
    pager=("terminal length 0",),
    templates={
        "inventory": ("show version", "show inventory"),
        "backup": ("show running-config",),
        "vlan_inspect": ("show vlan id {vlan}", "show interface trunk"),
        "vlan_locate": ("show vlan id {vlan}", "show interface trunk"),
        "mac_lookup": ("show mac address-table address {mac_dotted}",),
        "arp_lookup": ("show ip arp | include {lookup}",),
        "core_lookup": ("show ip arp | include {lookup}", "show mac address-table | include {lookup}"),
        "ping": ("ping {destination} count {count} timeout {timeout}",),
        "neighbors": ("show lldp neighbors detail", "show cdp neighbors detail"),
        "fdb": ("show mac address-table",),
        "vlan_membership": ("show vlan id {vlan}", "show interface trunk"),
        "stp": ("show spanning-tree vlan {vlan}",),
        "lag": ("show port-channel summary",),
        "svi": ("show interface vlan {vlan}",),
        "vrf": ("show vrf",),
        "routes": ("show ip route {destination}", "show ipv6 route {destination}"),
        "arp_nd": ("show ip arp {destination}", "show ipv6 neighbors | include {destination}"),
        "interface_policy": ("show running-config interface {interface}", "show access-lists"),
        "interface_health": ("show interface {interface}",),
        "cable_status": ("show interface {interface} transceiver details",),
        "config_enter": ("configure terminal",),
        "config_exit": ("end",),
        "save": ("copy running-config startup-config",),
    },
    capabilities={**COMMON_READ_CAPABILITIES, "cdp": "supported", "cable_status": "optics-only", "cable_test": "unsupported", "configuration": "firmware-gated", "vlan_write": "firmware-gated"},
    firmware_profiles=("nxos-9.x", "nxos-10.x"),
    notes=("NX-OS is selected independently from IOS; writes remain firmware- and profile-gated.",),
))

REGISTRY.register(_driver(
    "aruba-aos-switch", "HPE Aruba Networking", "AOS-Switch", support_level="broad-read-field-validation",
    pager=("no page",), logout=("exit", "y"),
    templates={
        "inventory": ("show version", "show system", "show modules"),
        "backup": ("show running-config",),
        "vlan_inspect": ("show vlan {vlan}", "show running-config"),
        "vlan_locate": ("show vlan {vlan}", "show running-config"),
        "mac_lookup": ("show mac-address {mac_hyphen}",),
        "arp_lookup": ("show arp | include {lookup}",),
        "core_lookup": ("show arp | include {lookup}", "show mac-address | include {lookup}"),
        "ping": ("ping {destination} repetitions {count}",),
        "neighbors": ("show lldp info remote-device",),
        "fdb": ("show mac-address",),
        "vlan_membership": ("show vlan {vlan}", "show running-config"),
        "stp": ("show spanning-tree vlan {vlan}",),
        "lag": ("show trunks",),
        "svi": ("show ip", "show vlan {vlan}"),
        "vrf": ("show vrf",),
        "routes": ("show ip route {destination}",),
        "arp_nd": ("show arp | include {destination}",),
        "interface_policy": ("show running-config interface {interface}",),
        "interface_health": ("show interfaces {interface}", "show interfaces brief {interface}"),
        "cable_status": ("show cable-diagnostics {interface}",),
        "cable_start": ("test cable-diagnostics {interface}",),
        "config_enter": ("configure",),
        "config_exit": ("end",),
        "save": ("write memory",),
    },
    capabilities={**COMMON_READ_CAPABILITIES, "vrf": "model-dependent", "cdp": "unsupported", "cable_status": "supported", "cable_test": "supported", "configuration": "unsupported", "vlan_write": "unsupported"},
    firmware_profiles=("aos-s-16.x",),
    notes=("Read commands cover ProCurve/Aruba AOS-S generations; VLAN writes remain blocked pending model-specific fixtures.",),
))

REGISTRY.register(_driver(
    "aruba-aos-cx", "HPE Aruba Networking", "AOS-CX", support_level="broad-read-field-validation",
    pager=("no page",),
    templates={
        "inventory": ("show version", "show system", "show inventory"),
        "backup": ("show running-config",),
        "vlan_inspect": ("show vlan {vlan}", "show running-config"),
        "vlan_locate": ("show vlan {vlan}", "show running-config"),
        "mac_lookup": ("show mac-address-table address {mac_colon}",),
        "arp_lookup": ("show arp | include {lookup}",),
        "core_lookup": ("show arp | include {lookup}", "show mac-address-table | include {lookup}"),
        "ping": ("ping {destination} repetitions {count}",),
        "neighbors": ("show lldp neighbor-info",),
        "fdb": ("show mac-address-table",),
        "vlan_membership": ("show vlan {vlan}", "show interface trunk"),
        "stp": ("show spanning-tree vlan {vlan}",),
        "lag": ("show lag",),
        "svi": ("show interface vlan {vlan}",),
        "vrf": ("show vrf",),
        "routes": ("show ip route {destination} vrf all", "show ipv6 route {destination} vrf all"),
        "arp_nd": ("show arp | include {destination}", "show ipv6 neighbors | include {destination}"),
        "interface_policy": ("show running-config interface {interface}", "show access-list"),
        "interface_health": ("show interface {interface}", "show interface {interface} physical"),
        "cable_status": ("diag cable-diagnostic show {interface}",),
        "cable_start": ("diag cable-diagnostic test {interface}",),
        "config_enter": ("configure terminal",),
        "config_exit": ("end",),
        "save": ("write memory",),
    },
    capabilities={**COMMON_READ_CAPABILITIES, "cdp": "unsupported", "cable_status": "supported", "cable_test": "manual-confirmation", "configuration": "unsupported", "vlan_write": "unsupported"},
    firmware_profiles=("aos-cx-10.x",),
    notes=("AOS-CX active cable tests may prompt interactively and remain maintenance-window operations.",),
))

REGISTRY.register(_driver(
    "ruckus-fastiron", "RUCKUS Networks", "FastIron", support_level="broad-read-field-validation",
    pager=("skip-page-display",),
    templates={
        "inventory": ("show version", "show chassis", "show module"),
        "backup": ("show running-config",),
        "vlan_inspect": ("show vlan {vlan}", "show running-config"),
        "vlan_locate": ("show vlan {vlan}", "show running-config"),
        "mac_lookup": ("show mac-address {mac_plain}",),
        "arp_lookup": ("show arp | include {lookup}",),
        "core_lookup": ("show arp | include {lookup}", "show mac-address | include {lookup}"),
        "ping": ("ping {destination} count {count} timeout {timeout}",),
        "neighbors": ("show lldp neighbors detail",),
        "fdb": ("show mac-address",),
        "vlan_membership": ("show vlan {vlan}", "show running-config"),
        "stp": ("show spanning-tree vlan {vlan}",),
        "lag": ("show lag",),
        "svi": ("show interfaces ve {vlan}",),
        "vrf": ("show vrf",),
        "routes": ("show ip route {destination}", "show ipv6 route {destination}"),
        "arp_nd": ("show arp | include {destination}", "show ipv6 neighbor | include {destination}"),
        "interface_policy": ("show running-config interface {interface}", "show access-list"),
        "interface_health": ("show interfaces {interface}",),
        "cable_status": ("show cable-diag tdr {interface}",),
        "cable_start": ("phy cable-diag tdr {interface}",),
        "config_enter": ("configure terminal",),
        "config_exit": ("end",),
        "save": ("write memory",),
    },
    capabilities={**COMMON_READ_CAPABILITIES, "cdp": "unsupported", "cable_status": "supported", "cable_test": "supported", "configuration": "unsupported", "vlan_write": "unsupported"},
    firmware_profiles=("fastiron-08.x", "fastiron-09.x", "fastiron-10.x"),
    notes=("Read support targets FastIron 08.0.95, 09.0.10, and 10.0.20 command families; writes remain blocked until fixtures are accepted.",),
))

for family, kind, os_name in (
    ("ruckus-smartzone", "controller", "SmartZone"),
    ("ruckus-ap", "access-point", "RUCKUS AP firmware"),
):
    REGISTRY.register(_driver(
        family, "RUCKUS Networks", os_name, support_level="inventory-only",
        pager=(), logout=(), templates={},
        capabilities={"inventory": "inventory-only", "configuration": "unsupported", "vlan_read": "unsupported", "mac_table": "unsupported", "lldp": "unsupported", "cable_test": "unsupported"},
        notes=("This family is ingested through controller/SNMP data and is not treated as a switch CLI target.",),
        device_kind=kind,
    ))

REGISTRY.register(_driver(
    "unknown", "Unknown", "Unknown", support_level="unclassified",
    pager=(), logout=(), templates={},
    capabilities={"inventory": "probe-only", "configuration": "unsupported", "vlan_read": "unsupported", "mac_table": "unsupported", "lldp": "unsupported", "cable_test": "unsupported"},
    notes=("Collect sysDescr, model, and version evidence before selecting a driver.",),
    device_kind="unknown",
))


def detect_device_family(**evidence: Any) -> DeviceDetection:
    return REGISTRY.detect(**evidence)


def driver_for(*, family: str = "", **evidence: Any) -> DeviceDriver:
    if family:
        return REGISTRY.get(family)
    return REGISTRY.get(REGISTRY.detect(**evidence).family)


def _stream_values(action: str, arguments: Sequence[str]) -> Tuple[str, Dict[str, Any]]:
    action_key = action.strip().lower().replace("-", "_")
    if action_key == "propagated":
        return "vlan_inspect", {"vlan": arguments[0] if arguments else ""}
    if action_key == "locate_vlan":
        if len(arguments) > 1 and arguments[1] == "--config-only":
            return "backup", {}
        return "vlan_locate", {"vlan": arguments[0] if arguments else ""}
    if action_key == "mac_lookup":
        return action_key, {"mac": arguments[0] if arguments else ""}
    if action_key == "core_lookup":
        return action_key, {"lookup": arguments[0] if arguments else ""}
    if action_key == "show":
        return action_key, {"command": arguments[0] if arguments else ""}
    if action_key == "config":
        return action_key, {"commands": list(arguments)}
    if action_key in {"cable_status", "cable_start", "interface_health"}:
        return action_key, {"interface": arguments[0] if arguments else ""}
    return action_key, {}


def _parse_cli_args(parser: argparse.ArgumentParser, argv: Optional[Sequence[str]]) -> argparse.Namespace:
    raw_arguments = list(sys.argv[1:] if argv is None else argv)
    stream_arguments: List[str] = []
    if "--" in raw_arguments:
        separator = raw_arguments.index("--")
        parser_arguments = raw_arguments[:separator]
        stream_arguments = raw_arguments[separator + 1:]
    else:
        parser_arguments = raw_arguments
    args = parser.parse_args(parser_arguments)
    args.arguments = [*args.arguments, *stream_arguments]
    return args


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="NetOps device-driver registry")
    parser.add_argument("operation", choices=("detect", "report", "stream"))
    parser.add_argument("--family", default="")
    parser.add_argument("--platform", default="")
    parser.add_argument("--model", default="")
    parser.add_argument("--sysdescr", default="")
    parser.add_argument("--hostname", default="")
    parser.add_argument("--action", default="")
    parser.add_argument("arguments", nargs="*")
    args = _parse_cli_args(parser, argv)
    detection = detect_device_family(
        platform=args.platform,
        model=args.model,
        sysdescr=args.sysdescr,
        hostname=args.hostname,
    )
    driver = driver_for(family=args.family or detection.family)
    if args.operation == "detect":
        print(json.dumps(detection.as_dict(), sort_keys=True))
        return 0
    if args.operation == "report":
        payload = driver.report()
        payload["detection"] = detection.as_dict()
        print(json.dumps(payload, sort_keys=True))
        return 0
    try:
        operation, values = _stream_values(args.action, args.arguments)
        for command in driver.command_plan(operation, **values):
            print(command)
    except (IndexError, KeyError, UnsupportedDeviceAction, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 5
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BrokenPipeError:
        # A short-lived SSH consumer can close stdin after producing its fixture
        # output.  Command generation itself succeeded, so do not turn SIGPIPE
        # into an operation failure or emit an interpreter flush warning.
        with open(os.devnull, "w", encoding="ascii") as sink:
            os.dup2(sink.fileno(), sys.stdout.fileno())
        raise SystemExit(0)
