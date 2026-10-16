#!/usr/bin/env python3
"""Netrune Python core.

This is the noun-first Netrune platform entrypoint. It keeps the existing shell
helpers available for network-touching operations, but owns command grammar,
SQLite state, relationship memory, jobs, API, and deterministic natural asks.
"""
from __future__ import annotations

import contextlib
import base64
import concurrent.futures
import difflib
import hashlib
import hmac
import io
import ipaddress
from importlib.metadata import PackageNotFoundError, version as distribution_version
import json
import os
import re
import shlex
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import termios
import threading
import textwrap
import tempfile
import time
import tty
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from rich import box
from rich.console import Console
from rich.style import Style
from rich.table import Table
from rich.text import Text

from netops_platform.ask import NaturalAskEngine
from netops_platform.device_cli import DeviceCommandsMixin
from netops_platform.devices import REGISTRY as DEVICE_DRIVERS
from netops_platform.devices import DeviceDetection, DeviceDriver, firmware_certification
from netops_platform.diagnose_cli import DiagnoseCommandsMixin
from netops_platform.identity import (
    ap_rows_match,
    cluster_rename_candidates,
    identity_continuity_candidates,
    identity_match_evidence,
    normalize_mac,
    reconcile_ap_rows,
    reconcile_device_rows,
)
from netops_platform.inventory_cli import InventoryCommandsMixin
from netops_platform.lookup_cli import LookupCommandsMixin
from netops_platform.mac_registry import IeeeMacRegistry, lookup_ieee_mac
from netops_platform.network import (
    clean_network_output,
    extract_ip_candidates,
    interface_matches,
    lookup_oui,
    normalize_interface,
    parse_arp_output,
    parse_mac_table_output,
    parse_cable_diagnostics_output,
    parse_cdp_neighbors_table,
    parse_trunk_summary,
    parse_lag_output,
    parse_route_output,
    parse_vrf_output,
    classify_uplink_ports,
    parse_interface_health_output,
    parse_iperf3_output,
    parse_neighbor_detail_output,
    parse_ping_output,
    parse_spanning_tree_output,
    parse_svi_output,
    parse_vlan_control_output,
)
from netops_platform.traffic import TrafficMonitor
from netops_platform.profiles import (
    NEUTRAL_PROFILE,
    ProfileLayout,
    ProfileStore,
    environment_value,
    flatten_profile,
    profile_environment,
    read_kv,
)
from netops_platform.contracts import PathRequestV1
from netops_platform.ingest import IngestManager, SecretResolver
from netops_platform.path_inspector import PathInspector
from netops_platform.plugins import PLUGIN_GROUPS, PluginManager
from netops_platform.support import create_support_bundle
from netops_platform.topology_cli import TopologyCommandsMixin
from netops_platform.vlan_cli import VlanCommandsMixin

def resolved_version() -> str:
    try:
        return Path(__file__).resolve().parents[1].joinpath("VERSION").read_text(encoding="ascii").strip()
    except OSError:
        try:
            try:
                return distribution_version("netrune")
            except PackageNotFoundError:
                return distribution_version("netops-platform")
        except PackageNotFoundError:
            return "0.0.0+unknown"


#: A file that only ever sits beside the helpers, used to recognise the
#: directory they were installed into.
_ROOT_MARKERS = ("netrune-connect", "netops-connect", "netops-lib.sh")


def installation_root() -> Path:
    """Where the shell helpers the collector shells out to actually live.

    Not simply the interpreter's directory. Inside a virtualenv `sys.executable`
    is a symlink, and resolving it lands on the system Python's bin -- so a
    wheel installed into a venv, which is how a poller is installed, would look
    for its helpers in /usr/bin and find nothing. The collector then reports
    every switch as unreachable, with no error that names the cause.

    The candidates are tried in order of how specific they are: a source tree
    first, then the venv the running interpreter belongs to, and only then the
    resolved interpreter directory.
    """
    return _first_root_holding_helpers(
        Path(__file__).resolve().parents[1], Path(sys.executable), Path(sys.prefix))


def _first_root_holding_helpers(source_root: Path, executable: Path, prefix: Path) -> Path:
    """The first candidate that actually contains the helpers.

    Ordered by how specific each is: a source tree, then the venv the running
    interpreter belongs to, then the interpreter's real directory. Resolving
    the executable is last precisely because it is the one that walks out of a
    venv and into /usr/bin.
    """
    fallback = executable.resolve().parent
    for candidate in (source_root, executable.parent, prefix / "bin", fallback):
        with contextlib.suppress(OSError):
            if any((candidate / marker).is_file() for marker in _ROOT_MARKERS):
                return candidate
    return fallback


def synchronize_environment_aliases() -> None:
    """Make canonical NETRUNE_* settings available to v8 compatibility code."""
    for key, value in tuple(os.environ.items()):
        if key.startswith("NETRUNE_"):
            os.environ["NETOPS_" + key[len("NETRUNE_"):]] = value
    for key, value in tuple(os.environ.items()):
        if key.startswith("NETOPS_"):
            os.environ.setdefault("NETRUNE_" + key[len("NETOPS_"):], value)


VERSION = resolved_version()
SCHEMA_VERSION = "13"
# Bump when a capability parser changes shape, so stored facts stay attributable
# to the parser that produced them.
CAPABILITY_PARSER_VERSION = "1"
CAPABILITY_EVIDENCE_HISTORY = 5
TIME_FORMAT = "ISO 8601 UTC"
CHRONOLOGY = "newest_first"
SUCCESS = 0
USAGE = 2
PARTIAL = 3
UNREACHABLE = 4
UNSUPPORTED = 5
VALIDATION = 6
CONFIRM_REQUIRED = 7
AUTH = 8
TIMEOUT = 9
INTERNAL = 10
#: Exact-match (stripped, uppercased) status words colored consistently
#: wherever they appear in a table cell, not just in a column literally
#: named "status" -- ONLINE reads the same whether it's under STATUS,
#: CURRENT_STATE, or PHASE.
STATUS_STYLES: Dict[str, str] = {
    "ONLINE": "green", "PASS": "green", "SUCCESS": "green", "OK": "green", "COMPLETE": "green",
    "OFFLINE": "red", "FAIL": "red", "FAILED": "red", "FAILURE": "red", "ERROR": "red",
    "CRITICAL": "red", "BLOCKED": "red", "UNREACHABLE": "red",
    "WARN": "yellow", "WARNING": "yellow", "ATTENTION": "yellow", "PARTIAL": "yellow",
    "UNSUPPORTED": "yellow", "DEGRADED": "yellow", "FLAPPING": "yellow", "CONFIRM_REQUIRED": "yellow",
}
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
SECRET_KEY_RE = re.compile(r"(password|passwd|secret|credential|community|token|key|snmpv3_.*pass|sshpass)", re.I)
MAC_RE = re.compile(r"(?i)(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}|[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}|[0-9a-f]{12}")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def now() -> int:
    return int(time.time())


def eprint(*args: Any) -> None:
    print(*args, file=sys.stderr)


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


def norm_status(value: Any) -> str:
    text = str(value or "UNKNOWN").strip().upper()
    if text in {"UP", "ACTIVE", "ALIVE", "REACHABLE"}:
        return "ONLINE"
    if text in {"DOWN", "INACTIVE", "DEAD", "UNREACHABLE"}:
        return "OFFLINE"
    if text in {"ONLINE", "OFFLINE", "UNKNOWN"}:
        return text
    return "UNKNOWN"


def norm_mac(value: Any) -> str:
    return normalize_mac(value)


def compact_name(name: Any) -> str:
    text = str(name or "").strip()
    if "." in text:
        text = text.split(".", 1)[0]
    return text


def fmt_time(value: Any) -> str:
    try:
        ts = int(value or 0)
    except (TypeError, ValueError):
        return ""
    if ts <= 0:
        return ""
    try:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))
    except (OverflowError, OSError, ValueError):
        return ""


def is_timestamp_field(name: Any) -> bool:
    key = str(name or "")
    return key in {"first_seen", "last_seen", "last_failed"} or key.endswith("_at")


def timestamp_row(row: Dict[str, Any]) -> Dict[str, Any]:
    """Add stable display timestamps while retaining epoch values for compatibility."""
    item = dict(row)
    for key in tuple(item):
        if not is_timestamp_field(key):
            continue
        rendered = fmt_time(item.get(key))
        if rendered:
            item[f"{key}_iso"] = rendered
    if item.get("created_at_iso"):
        item["recorded_at_iso"] = item["created_at_iso"]
    if item.get("last_seen_iso"):
        item["last_recorded_at_iso"] = item["last_seen_iso"]
    return item


def timestamp_rows(rows: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [timestamp_row(row) for row in rows]


def clean_limit(value: Any, default: int = 100, ceiling: int = 1000) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        n = default
    return max(1, min(n, ceiling))


def bounded_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    """Parse operator/environment integers without allowing zero-worker deadlocks."""
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(parsed, maximum))


def normalized_exit_code(value: Optional[int]) -> int:
    """Convert subprocess signal return codes to conventional shell exit codes."""
    if value is None:
        return INTERNAL
    return 128 + abs(value) if value < 0 else value


def json_dumps(data: Any) -> str:
    return json.dumps(data, indent=2, sort_keys=True)

def expand_abbreviated_target(value: str, prefix: str) -> str:
    """Complete an abbreviated address against the profile's prefix.

    The shell resolver has always done this, so an abbreviation there completes
    against the profile's prefix. Python did not, and treated the same text as a name fragment
    that could match anything containing those digits -- including a *former*
    address of a different device. Two resolvers disagreeing about what an
    operator typed is how a command lands on hardware nobody chose.
    """
    text = str(value or "").strip().lstrip(".")
    base = str(prefix or "").strip().strip(".")
    if not text or not base:
        return ""
    if not re.fullmatch(r"(\d{1,3}\.){0,2}\d{1,3}", text):
        return ""
    if not re.fullmatch(r"(\d{1,3}\.){0,2}\d{1,3}", base):
        return ""
    parts = base.split(".") + text.split(".")
    if len(parts) != 4:
        return ""
    candidate = ".".join(parts)
    return candidate if is_ipv4_literal(candidate) else ""


def normalize_target_literal(value: Any) -> str:
    """Normalize an optional profile-defined IPv4 abbreviation."""
    text = str(value or "").strip()
    if not text:
        return ""
    if IP_RE.fullmatch(text):
        with contextlib.suppress(ValueError):
            return str(ipaddress.ip_address(text))
        return text
    prefix = environment_value("NETRUNE_TARGET_ABBREVIATION_PREFIX", "NETOPS_TARGET_ABBREVIATION_PREFIX").strip().strip(".")
    if not prefix:
        return text
    try:
        prefix_parts = [int(part) for part in prefix.split(".")]
    except ValueError:
        return text
    if not 1 <= len(prefix_parts) <= 3 or any(part < 0 or part > 255 for part in prefix_parts):
        return text
    suffix_text = text.lstrip(".")
    suffix_parts = suffix_text.split(".") if suffix_text else []
    if not suffix_parts or len(prefix_parts) + len(suffix_parts) != 4:
        return text
    try:
        suffix = [int(part) for part in suffix_parts]
    except ValueError:
        return text
    if any(part < 0 or part > 255 for part in suffix):
        return text
    return ".".join(str(part) for part in [*prefix_parts, *suffix])


def is_ipv4_literal(value: Any) -> bool:
    try:
        return ipaddress.ip_address(str(value or "").strip()).version == 4
    except ValueError:
        return False


def is_all_keyword(value: Any) -> bool:
    return str(value or "").strip().lower() in {"all", "*", "any"}

def pattern_or_all(value: Any) -> str:
    text = str(value or "").strip()
    return "" if is_all_keyword(text) else text

def clean_display_name(value: Any) -> str:
    return str(value or "").strip().strip('"\'')


def valid_ssh_username(value: Any) -> bool:
    username = str(value or "")
    return bool(username) and len(username) <= 255 and not bool(re.search(r"\s", username))


# Secrets also appear inside free text: a device echoes a configuration line,
# an error quotes a command. Matching only on the key name misses all of it.
SECRET_VALUE_RE = re.compile(
    r"(?i)\b(password|passwd|secret|community|token|key|passphrase|credential|sshpass)\b"
    r"\s*(?:=|:|\s)\s*(?P<value>\S+)"
)
SECRET_ARG_RE = re.compile(r"(?i)(--(?:password|secret|token|community|key)[= ])(\S+)")


def redact_text(value: Any) -> str:
    """Mask secret-looking assignments inside free text."""
    text = str(value or "")
    if not text:
        return text
    text = SECRET_VALUE_RE.sub(lambda m: m.group(0).replace(m.group("value"), "***"), text)
    text = SECRET_ARG_RE.sub(lambda m: m.group(1) + "***", text)
    return text


def redact_for_api(value: Any) -> Any:
    if isinstance(value, dict):
        out: Dict[str, Any] = {}
        for key, item in value.items():
            out[key] = "configured" if SECRET_KEY_RE.search(str(key)) and item else redact_for_api(item)
        return out
    if isinstance(value, list):
        return [redact_for_api(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


@dataclass
class GlobalOptions:
    json: bool = False
    plain: bool = False
    no_color: bool = False
    dry_run: bool = False
    confirm: bool = False
    execute: bool = False
    limit: int = 100
    since: str = ""
    status: str = ""
    site: str = ""
    source: str = ""
    timeout: int = 0
    workers: int = 20
    depth: int = 0
    max_nodes: int = 64
    refresh_neighbors: bool = False
    first: bool = False
    all: bool = False
    interactive: bool = False
    profile: str = ""


def parse_global(argv: Sequence[str]) -> Tuple[GlobalOptions, List[str]]:
    opts = GlobalOptions()
    out: List[str] = []
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--json": opts.json = True; i += 1
        elif arg == "--plain": opts.plain = True; os.environ["NO_COLOR"] = "1"; i += 1
        elif arg == "--no-color": opts.no_color = True; os.environ["NO_COLOR"] = "1"; i += 1
        elif arg == "--dry-run": opts.dry_run = True; i += 1
        elif arg in {"--confirm", "--approve", "--yes"}: opts.confirm = True; i += 1
        elif arg in {"--execute", "--run-plan"}: opts.execute = True; i += 1
        elif arg == "--limit" and i + 1 < len(argv): opts.limit = clean_limit(argv[i + 1]); i += 2
        elif arg == "--since" and i + 1 < len(argv): opts.since = argv[i + 1]; i += 2
        elif arg == "--status" and i + 1 < len(argv): opts.status = norm_status(argv[i + 1]); i += 2
        elif arg == "--site" and i + 1 < len(argv): opts.site = argv[i + 1]; i += 2
        elif arg == "--source" and i + 1 < len(argv): opts.source = argv[i + 1]; i += 2
        elif arg == "--timeout" and i + 1 < len(argv): opts.timeout = clean_limit(argv[i + 1], 20, 3600); i += 2
        elif arg == "--workers" and i + 1 < len(argv): opts.workers = clean_limit(argv[i + 1], 20, 200); i += 2
        elif arg == "--depth" and i + 1 < len(argv):
            try: opts.depth = max(0, min(int(argv[i + 1]), 16))
            except (TypeError, ValueError): opts.depth = 0
            i += 2
        elif arg == "--max-nodes" and i + 1 < len(argv): opts.max_nodes = clean_limit(argv[i + 1], 64, 256); i += 2
        elif arg == "--refresh-neighbors": opts.refresh_neighbors = True; i += 1
        elif arg == "--first": opts.first = True; i += 1
        elif arg == "--all": opts.all = True; i += 1
        elif arg == "--interactive": opts.interactive = True; i += 1
        elif arg == "--profile" and i + 1 < len(argv):
            # ``diagnose speed`` has its own performance profile. Preserve that
            # option after the command path while keeping a leading --profile as
            # the one-shot Netrune state-profile selector.
            command_path = tuple(out)
            local_speed_profile = command_path[:2] == ("diagnose", "speed") or command_path[:3] == ("commands", "run", "diagnose-speed")
            if local_speed_profile:
                out.extend((arg, argv[i + 1]))
            else:
                opts.profile = argv[i + 1]
            i += 2
        else: out.append(arg); i += 1
    return opts, out


@dataclass
class Paths:
    install_dir: Path
    home: Path = field(default_factory=Path.home)
    profile: str = ""
    profile_layout: ProfileLayout = field(init=False)
    config_root: Path = field(init=False)
    state_dir: Path = field(init=False)
    data_dir: Path = field(init=False)
    config_dir: Path = field(init=False)
    cache_dir: Path = field(init=False)
    config_file: Path = field(init=False)
    env_file: Path = field(init=False)
    devices_file: Path = field(init=False)
    aps_file: Path = field(init=False)
    neighbors_file: Path = field(init=False)
    sqlite_db: Path = field(init=False)
    backup_dir: Path = field(init=False)
    ssh_known_hosts_file: Path = field(init=False)
    mac_registry_dir: Path = field(init=False)
    profile_file: Path = field(init=False)
    secrets_file: Path = field(init=False)

    def __post_init__(self) -> None:
        store = ProfileStore(self.home)
        layout = store.ensure(self.profile or ProfileLayout.resolve(home=self.home).name)
        self.profile_layout = layout
        self.profile = layout.name
        self.config_root = layout.config_root
        self.config_dir = layout.config_dir
        self.state_dir = layout.state_dir
        self.cache_dir = layout.cache_dir
        self.data_dir = layout.data_dir
        self.profile_file = self.config_dir / "profile.toml"
        self.config_file = self.config_dir / "netsnmp.conf"
        self.env_file = self.config_dir / ".env"
        self.devices_file = self.cache_dir / "devices.db"
        self.aps_file = self.cache_dir / "ap_devices.db"
        self.neighbors_file = self.cache_dir / "neighbor.db"
        self.sqlite_db = Path(environment_value("NETRUNE_SQLITE_DB", "NETOPS_SQLITE_DB", str(self.state_dir / "netrune.sqlite3")))
        self.backup_dir = Path(environment_value("NETRUNE_BACKUP_DIR", "NETOPS_BACKUP_DIR", str(self.data_dir / "backups")))
        self.ssh_known_hosts_file = Path(environment_value("NETRUNE_SSH_KNOWN_HOSTS_FILE", "NETOPS_SSH_KNOWN_HOSTS_FILE", str(self.config_dir / "known_hosts")))
        self.mac_registry_dir = Path(environment_value("NETRUNE_MAC_REGISTRY_DIR", "NETOPS_MAC_REGISTRY_DIR", str(self.cache_dir / "mac-registry")))
        self.secrets_file = Path(environment_value("NETRUNE_SECRETS_FILE", "NETOPS_SECRETS_FILE", str(self.data_dir / "secrets.gpg")))
        self.secrets_meta_file = Path(environment_value("NETRUNE_SECRETS_META_FILE", "NETOPS_SECRETS_META_FILE", str(self.state_dir / "secrets.meta")))
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.config_dir.mkdir(parents=True, exist_ok=True)

    def tool(self, name: str) -> str:
        local = self.install_dir / ("scripts/netrune" if name == "netrune" else name)
        if local.is_file():
            return str(local)
        installed = shutil.which(name)
        return installed or str(local)


class Config:
    def __init__(self, paths: Paths):
        self.paths = paths
        self.public = self._resolved_public(paths)
        # Legacy plaintext secrets are readable only during the compatibility
        # window. New configuration stores references, never values.
        self.secret = read_kv(paths.env_file)

    @staticmethod
    def _toml_values(path: Path) -> Dict[str, str]:
        if not path.is_file():
            return {}
        import tomllib
        with path.open("rb") as stream:
            return flatten_profile(tomllib.load(stream))

    def _resolved_public(self, paths: Paths) -> Dict[str, str]:
        import tomllib
        values = flatten_profile(tomllib.loads(NEUTRAL_PROFILE))
        values.update(self._toml_values(paths.config_root / "config.toml"))
        values.update(self._toml_values(paths.profile_file))
        values.update(read_kv(paths.config_file))
        for key in tuple(values):
            environment_key = "NETRUNE_" + key.upper()
            legacy_environment_key = "NETOPS_" + key.upper()
            if key == "strip_prefixes":
                environment_key = "NETRUNE_IDENTITY_STRIP_PREFIXES"
                legacy_environment_key = "NETOPS_IDENTITY_STRIP_PREFIXES"
            if environment_key in os.environ:
                values[key] = os.environ[environment_key]
            elif legacy_environment_key in os.environ:
                values[key] = os.environ[legacy_environment_key]
        return values

    def public_safe(self) -> Dict[str, str]:
        output: Dict[str, str] = {}
        for key, value in self.public.items():
            output[key] = "configured" if SECRET_KEY_RE.search(key) and key not in {"ssh_host_key_mode"} else value
        for key, value in self.secret.items():
            output[key] = "configured" if value else "missing"
        return output

SCHEMA = r"""
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
CREATE TABLE IF NOT EXISTS schema_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL,updated_at INTEGER NOT NULL);
INSERT OR IGNORE INTO schema_meta(key,value,updated_at) VALUES('schema_version','13',strftime('%s','now'));
CREATE TABLE IF NOT EXISTS devices(ip TEXT PRIMARY KEY,hostname TEXT,platform TEXT,model TEXT,serial TEXT,mac TEXT,source TEXT,last_seen INTEGER,status TEXT);
CREATE TABLE IF NOT EXISTS aps(ip TEXT PRIMARY KEY,name TEXT,platform TEXT,switch_ip TEXT,switch_name TEXT,switch_port TEXT,mac TEXT,last_seen INTEGER,status TEXT);
CREATE TABLE IF NOT EXISTS neighbors(local_ip TEXT,local_name TEXT,local_port TEXT,remote_name TEXT,remote_port TEXT,remote_ip TEXT,PRIMARY KEY(local_ip,local_port,remote_name,remote_port));
CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY,action TEXT NOT NULL,command TEXT NOT NULL,status TEXT NOT NULL,created_at INTEGER,started_at INTEGER,finished_at INTEGER,exit_code INTEGER,read_only INTEGER NOT NULL DEFAULT 1,writes_local INTEGER NOT NULL DEFAULT 0,request_json TEXT,result_json TEXT,summary TEXT,duration_ms INTEGER,actor TEXT,actor_uid INTEGER,session_id TEXT,reason TEXT,ticket TEXT,preview_hash TEXT,parent_job_id TEXT,workflow_step TEXT);
CREATE TABLE IF NOT EXISTS job_logs(id INTEGER PRIMARY KEY AUTOINCREMENT,job_id TEXT NOT NULL,created_at INTEGER NOT NULL,stream TEXT NOT NULL,line TEXT NOT NULL,event_type TEXT NOT NULL DEFAULT 'log',phase TEXT,progress_current INTEGER,progress_total INTEGER,payload_json TEXT);
CREATE TABLE IF NOT EXISTS command_history(id INTEGER PRIMARY KEY AUTOINCREMENT,created_at INTEGER NOT NULL,action TEXT NOT NULL,command TEXT NOT NULL,exit_code INTEGER,read_only INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS audit_events(id INTEGER PRIMARY KEY AUTOINCREMENT,created_at INTEGER NOT NULL,actor TEXT NOT NULL,actor_uid INTEGER,session_id TEXT,event_type TEXT NOT NULL,action TEXT,target TEXT,result TEXT,reason TEXT,ticket TEXT,preview_hash TEXT,job_id TEXT,detail_json TEXT);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL,updated_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS ask_aliases(phrase TEXT PRIMARY KEY COLLATE NOCASE,target TEXT NOT NULL,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS probe_results(id INTEGER PRIMARY KEY AUTOINCREMENT,target TEXT,mode TEXT,created_at INTEGER NOT NULL,packet_loss_pct REAL,min_ms REAL,avg_ms REAL,max_ms REAL,jitter_ms REAL,raw_json TEXT);
CREATE TABLE IF NOT EXISTS speed_tests(id INTEGER PRIMARY KEY AUTOINCREMENT,created_at INTEGER NOT NULL,interface TEXT,download_mbps REAL,upload_mbps REAL,idle_latency_ms REAL,loaded_down_ms REAL,loaded_up_ms REAL,packet_loss_pct REAL,reliability TEXT,raw_json TEXT);
CREATE TABLE IF NOT EXISTS interface_samples(id INTEGER PRIMARY KEY AUTOINCREMENT,created_at INTEGER NOT NULL,device_ip TEXT,interface_name TEXT,in_bps INTEGER,out_bps INTEGER,utilization_pct REAL,oper_status TEXT,raw_json TEXT);
CREATE TABLE IF NOT EXISTS filtering_checks(id INTEGER PRIMARY KEY AUTOINCREMENT,created_at INTEGER NOT NULL,target TEXT,result TEXT,raw_json TEXT);
CREATE TABLE IF NOT EXISTS diagnostic_runs(id INTEGER PRIMARY KEY AUTOINCREMENT,created_at INTEGER NOT NULL,kind TEXT NOT NULL,target TEXT,source TEXT,status TEXT,summary TEXT,raw_json TEXT);
CREATE TABLE IF NOT EXISTS backup_history(id INTEGER PRIMARY KEY AUTOINCREMENT,created_at INTEGER NOT NULL,device_ip TEXT NOT NULL,hostname TEXT,path TEXT,sha256 TEXT,changed INTEGER NOT NULL DEFAULT 1,size_bytes INTEGER,status TEXT NOT NULL,message TEXT);
CREATE TABLE IF NOT EXISTS health_state(entity_type TEXT NOT NULL,entity_id TEXT NOT NULL,name TEXT,platform TEXT,serial TEXT,status TEXT,first_seen INTEGER,last_seen INTEGER,last_failed INTEGER,outage_started_at INTEGER,flap_count INTEGER NOT NULL DEFAULT 0,switch_ip TEXT,switch_port TEXT,updated_at INTEGER NOT NULL,PRIMARY KEY(entity_type,entity_id));
CREATE TABLE IF NOT EXISTS health_events(id INTEGER PRIMARY KEY AUTOINCREMENT,created_at INTEGER NOT NULL,entity_type TEXT NOT NULL,entity_id TEXT NOT NULL,event_type TEXT NOT NULL,previous_value TEXT,current_value TEXT,detail TEXT);
CREATE TABLE IF NOT EXISTS topology_snapshot(local_ip TEXT,local_port TEXT,remote_name TEXT,remote_port TEXT,remote_ip TEXT,PRIMARY KEY(local_ip,local_port,remote_name,remote_port));
CREATE TABLE IF NOT EXISTS topology_events(id INTEGER PRIMARY KEY AUTOINCREMENT,created_at INTEGER NOT NULL,event_type TEXT NOT NULL,local_ip TEXT,local_port TEXT,remote_name TEXT,remote_port TEXT,remote_ip TEXT,detail TEXT);
CREATE TABLE IF NOT EXISTS ap_move_events(id INTEGER PRIMARY KEY AUTOINCREMENT,created_at INTEGER NOT NULL,ap_ip TEXT NOT NULL,ap_name TEXT,previous_switch_ip TEXT,previous_switch_port TEXT,current_switch_ip TEXT,current_switch_port TEXT);
CREATE TABLE IF NOT EXISTS inventory_identity_state(identity_kind TEXT NOT NULL,identity_value TEXT NOT NULL,entity_type TEXT NOT NULL,ip TEXT,mac TEXT,name TEXT,platform TEXT,model TEXT,serial TEXT,switch_ip TEXT,switch_name TEXT,switch_port TEXT,source TEXT,status TEXT,first_seen INTEGER,last_seen INTEGER,updated_at INTEGER NOT NULL,PRIMARY KEY(identity_kind,identity_value,entity_type));
CREATE TABLE IF NOT EXISTS inventory_history(id INTEGER PRIMARY KEY AUTOINCREMENT,created_at INTEGER NOT NULL,entity_type TEXT NOT NULL,identity_kind TEXT NOT NULL,identity_value TEXT NOT NULL,event_type TEXT NOT NULL,field_name TEXT,previous_value TEXT,current_value TEXT,ip TEXT,mac TEXT,name TEXT,switch_ip TEXT,switch_name TEXT,switch_port TEXT,platform TEXT,model TEXT,serial TEXT,source TEXT,status TEXT);
CREATE TABLE IF NOT EXISTS inventory_merges(merge_id TEXT PRIMARY KEY,entity_type TEXT NOT NULL,source_key TEXT NOT NULL,target_key TEXT NOT NULL,source_name TEXT,source_ip TEXT,target_name TEXT,target_ip TEXT,source_snapshot_json TEXT NOT NULL,target_snapshot_json TEXT NOT NULL,reason TEXT NOT NULL,actor TEXT NOT NULL,created_at INTEGER NOT NULL,last_applied_at INTEGER,suppressed_observations INTEGER NOT NULL DEFAULT 0,revoked_at INTEGER,revoked_by TEXT,revoke_reason TEXT);
CREATE TABLE IF NOT EXISTS relationships_current(rel_key TEXT PRIMARY KEY,rel_type TEXT NOT NULL,subject_kind TEXT NOT NULL,subject_id TEXT NOT NULL,object_kind TEXT,object_id TEXT,switch_ip TEXT,switch_name TEXT,switch_port TEXT,source TEXT,confidence INTEGER,status TEXT,first_seen INTEGER,last_seen INTEGER,updated_at INTEGER,attrs_json TEXT);
CREATE TABLE IF NOT EXISTS relationship_events(id INTEGER PRIMARY KEY AUTOINCREMENT,created_at INTEGER NOT NULL,event_type TEXT NOT NULL,rel_key TEXT NOT NULL,rel_type TEXT NOT NULL,subject_kind TEXT NOT NULL,subject_id TEXT NOT NULL,object_kind TEXT,object_id TEXT,previous_json TEXT,current_json TEXT,source TEXT,confidence INTEGER,detail TEXT);
CREATE TABLE IF NOT EXISTS core_lookup_cache(id INTEGER PRIMARY KEY AUTOINCREMENT,created_at INTEGER NOT NULL,target TEXT NOT NULL,exit_code INTEGER NOT NULL,output TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS scan_runs(id TEXT PRIMARY KEY,domain TEXT NOT NULL,mode TEXT,started_at INTEGER NOT NULL,finished_at INTEGER,status TEXT NOT NULL,complete INTEGER NOT NULL DEFAULT 0,source TEXT,detail TEXT);
CREATE TABLE IF NOT EXISTS ingest_channels(name TEXT PRIMARY KEY,kind TEXT NOT NULL,enabled INTEGER NOT NULL DEFAULT 1,manifest_path TEXT,config_json TEXT NOT NULL,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS ingest_runs(run_id TEXT PRIMARY KEY,channel TEXT NOT NULL,status TEXT NOT NULL,started_at INTEGER NOT NULL,finished_at INTEGER,received INTEGER NOT NULL DEFAULT 0,accepted INTEGER NOT NULL DEFAULT 0,duplicates INTEGER NOT NULL DEFAULT 0,rejected INTEGER NOT NULL DEFAULT 0,message TEXT,request_json TEXT,result_json TEXT);
CREATE TABLE IF NOT EXISTS observations(id INTEGER PRIMARY KEY AUTOINCREMENT,idempotency_key TEXT NOT NULL UNIQUE,entity_kind TEXT NOT NULL,stable_source_id TEXT NOT NULL,channel TEXT NOT NULL,observed_at INTEGER NOT NULL,received_at INTEGER NOT NULL,completeness TEXT NOT NULL,status TEXT,confidence INTEGER NOT NULL,provenance_json TEXT NOT NULL,facts_json TEXT NOT NULL,raw_evidence_hash TEXT NOT NULL,run_id TEXT);
CREATE TABLE IF NOT EXISTS observation_fields(observation_id INTEGER NOT NULL,field_name TEXT NOT NULL,value_json TEXT,source TEXT NOT NULL,confidence INTEGER NOT NULL,observed_at INTEGER NOT NULL,PRIMARY KEY(observation_id,field_name),FOREIGN KEY(observation_id) REFERENCES observations(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS observation_rejects(id INTEGER PRIMARY KEY AUTOINCREMENT,run_id TEXT NOT NULL,channel TEXT NOT NULL,received_at INTEGER NOT NULL,record_index INTEGER,error_code TEXT NOT NULL,message TEXT NOT NULL,raw_evidence_hash TEXT,redacted_record_json TEXT);
CREATE TABLE IF NOT EXISTS capability_evidence(id INTEGER PRIMARY KEY AUTOINCREMENT,device_id TEXT NOT NULL,capability TEXT NOT NULL,state TEXT NOT NULL,observed_at INTEGER NOT NULL,source TEXT NOT NULL,confidence INTEGER NOT NULL,facts_json TEXT NOT NULL,raw_evidence_hash TEXT NOT NULL,driver_family TEXT,parser_version TEXT,UNIQUE(device_id,capability,observed_at,raw_evidence_hash));
CREATE TABLE IF NOT EXISTS path_runs(run_id TEXT PRIMARY KEY,status TEXT NOT NULL,endpoint TEXT NOT NULL,vlan INTEGER NOT NULL,source TEXT,destination TEXT,mode TEXT NOT NULL,depth INTEGER NOT NULL,max_nodes INTEGER NOT NULL,confidence INTEGER NOT NULL,started_at INTEGER NOT NULL,finished_at INTEGER NOT NULL,summary TEXT,request_json TEXT NOT NULL,result_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS path_hops(run_id TEXT NOT NULL,sequence INTEGER NOT NULL,device_id TEXT NOT NULL,device_name TEXT,management_ip TEXT,ingress_interface TEXT,egress_interface TEXT,layer TEXT,vlan_state TEXT,forwarding_state TEXT,confidence INTEGER,evidence_observed_at INTEGER,evidence_json TEXT NOT NULL,PRIMARY KEY(run_id,sequence),FOREIGN KEY(run_id) REFERENCES path_runs(run_id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS path_findings(id INTEGER PRIMARY KEY AUTOINCREMENT,run_id TEXT NOT NULL,severity TEXT NOT NULL,code TEXT NOT NULL,message TEXT NOT NULL,device_id TEXT,interface TEXT,confidence INTEGER,evidence_observed_at INTEGER,evidence_json TEXT NOT NULL,FOREIGN KEY(run_id) REFERENCES path_runs(run_id) ON DELETE CASCADE);
CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status);
CREATE INDEX IF NOT EXISTS idx_aps_status ON aps(status);
CREATE INDEX IF NOT EXISTS idx_aps_switch ON aps(switch_ip,switch_name,switch_port);
CREATE INDEX IF NOT EXISTS idx_neighbors_local ON neighbors(local_ip,local_port);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
CREATE INDEX IF NOT EXISTS idx_job_logs_job ON job_logs(job_id,id);
CREATE INDEX IF NOT EXISTS idx_audit_events_created ON audit_events(created_at,id);
CREATE INDEX IF NOT EXISTS idx_audit_events_action ON audit_events(action,target,created_at);
CREATE INDEX IF NOT EXISTS idx_relationships_type ON relationships_current(rel_type,subject_id,object_id,status);
CREATE INDEX IF NOT EXISTS idx_relationship_events_key ON relationship_events(rel_key,created_at);
CREATE INDEX IF NOT EXISTS idx_relationship_events_type ON relationship_events(rel_type,created_at);
CREATE INDEX IF NOT EXISTS idx_topology_events_created ON topology_events(created_at);
CREATE INDEX IF NOT EXISTS idx_ap_move_events_created ON ap_move_events(created_at);
CREATE INDEX IF NOT EXISTS idx_backup_history_device ON backup_history(device_ip,created_at);
CREATE INDEX IF NOT EXISTS idx_health_state_status ON health_state(status);
CREATE INDEX IF NOT EXISTS idx_inventory_history_identity ON inventory_history(identity_kind,identity_value,entity_type,created_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_inventory_merges_active_source ON inventory_merges(entity_type,source_key) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_inventory_merges_target ON inventory_merges(entity_type,target_key,created_at);
CREATE INDEX IF NOT EXISTS idx_scan_runs_domain ON scan_runs(domain,started_at);
CREATE INDEX IF NOT EXISTS idx_diagnostic_runs_kind ON diagnostic_runs(kind,created_at);
CREATE INDEX IF NOT EXISTS idx_ingest_runs_channel ON ingest_runs(channel,started_at);
CREATE INDEX IF NOT EXISTS idx_observations_entity ON observations(entity_kind,stable_source_id,observed_at);
CREATE INDEX IF NOT EXISTS idx_observations_channel ON observations(channel,received_at);
CREATE INDEX IF NOT EXISTS idx_observation_rejects_run ON observation_rejects(run_id,id);
CREATE TABLE IF NOT EXISTS traffic_watch(
  watch_id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  device_ip TEXT,
  device_name TEXT,
  interface_name TEXT,
  target TEXT,
  label TEXT,
  interval_seconds INTEGER NOT NULL DEFAULT 60,
  enabled INTEGER NOT NULL DEFAULT 1,
  added_at INTEGER NOT NULL,
  added_by TEXT,
  notes TEXT,
  ifindex TEXT,
  ifname TEXT,
  display_name TEXT,
  subscribed_down_bps INTEGER,
  subscribed_up_bps INTEGER,
  faces_lan INTEGER NOT NULL DEFAULT 0,
  display_color TEXT);
CREATE TABLE IF NOT EXISTS traffic_counter_log(
  watch_id TEXT NOT NULL,
  counter TEXT NOT NULL,
  observed_at INTEGER NOT NULL,
  value INTEGER,
  collector TEXT NOT NULL DEFAULT 'local',
  PRIMARY KEY(collector, watch_id, counter, observed_at),
  FOREIGN KEY(watch_id) REFERENCES traffic_watch(watch_id) ON DELETE CASCADE) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS traffic_samples(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  watch_id TEXT NOT NULL,
  observed_at INTEGER NOT NULL,
  metric TEXT NOT NULL,
  value REAL,
  unit TEXT,
  status TEXT,
  collector TEXT NOT NULL DEFAULT 'local',
  raw_json TEXT,
  FOREIGN KEY(watch_id) REFERENCES traffic_watch(watch_id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS traffic_counters(
  watch_id TEXT NOT NULL,
  counter TEXT NOT NULL,
  observed_at INTEGER NOT NULL,
  value INTEGER NOT NULL,
  collector TEXT NOT NULL DEFAULT 'local',
  PRIMARY KEY(watch_id,counter,collector),
  FOREIGN KEY(watch_id) REFERENCES traffic_watch(watch_id) ON DELETE CASCADE);
CREATE INDEX IF NOT EXISTS idx_capability_evidence_device ON capability_evidence(device_id,capability,observed_at);
CREATE TABLE IF NOT EXISTS traffic_remotes(
  name TEXT PRIMARY KEY,
  host TEXT NOT NULL,
  ssh_user TEXT,
  ssh_port INTEGER,
  profile TEXT,
  collector_id TEXT,
  added_at INTEGER NOT NULL,
  added_by TEXT,
  last_pull_at INTEGER,
  last_sample_at INTEGER,
  notes TEXT);
-- A pull must be repeatable without duplicating what it already merged, and a
-- reading is identified by who took it, of what, and when.
CREATE UNIQUE INDEX IF NOT EXISTS idx_traffic_samples_identity
  ON traffic_samples(collector,watch_id,metric,observed_at);
CREATE INDEX IF NOT EXISTS idx_traffic_samples_series ON traffic_samples(watch_id,metric,observed_at);
CREATE INDEX IF NOT EXISTS idx_traffic_samples_time ON traffic_samples(observed_at);
CREATE INDEX IF NOT EXISTS idx_traffic_watch_enabled ON traffic_watch(enabled,kind);
CREATE INDEX IF NOT EXISTS idx_traffic_counter_log_time ON traffic_counter_log(observed_at);
CREATE INDEX IF NOT EXISTS idx_identity_state_lookup ON inventory_identity_state(entity_type,identity_kind,identity_value);
CREATE INDEX IF NOT EXISTS idx_identity_state_ip ON inventory_identity_state(ip);
CREATE INDEX IF NOT EXISTS idx_health_events_entity ON health_events(entity_type,entity_id,created_at);
CREATE INDEX IF NOT EXISTS idx_path_findings_run ON path_findings(run_id,severity);
CREATE INDEX IF NOT EXISTS idx_path_hops_run ON path_hops(run_id,sequence);
CREATE INDEX IF NOT EXISTS idx_path_runs_endpoint ON path_runs(endpoint,vlan,started_at);
CREATE INDEX IF NOT EXISTS idx_path_findings_run ON path_findings(run_id,severity);
"""

class State:
    def __init__(self, paths: Paths):
        self.inventory_dirty = False
        self.paths = paths
        self.init_db()

    @contextlib.contextmanager
    def connect(self):
        con = sqlite3.connect(str(self.paths.sqlite_db), timeout=30)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA busy_timeout=30000")
        con.execute("PRAGMA foreign_keys=ON")
        try:
            yield con
            con.commit()
        except Exception:
            con.rollback()
            raise
        finally:
            con.close()

    def init_db(self) -> None:
        with self.connect() as con:
            con.executescript(SCHEMA)
            self._repair_legacy_jobs_schema(con)
            self._add_missing_columns(con, "traffic_watch", {
                "ifindex": "TEXT", "ifname": "TEXT", "owner": "TEXT",
                "display_name": "TEXT", "subscribed_down_bps": "INTEGER",
                "subscribed_up_bps": "INTEGER", "faces_lan": "INTEGER",
                "display_color": "TEXT"})
            self._deduplicate_traffic_samples(con)
            con.execute(
                "INSERT OR REPLACE INTO schema_meta(key,value,updated_at) VALUES('schema_version',?,?)",
                (SCHEMA_VERSION, now()),
            )

    def _add_missing_columns(self, con: sqlite3.Connection, table: str, columns: Dict[str, str]) -> None:
        """Add columns a newer release introduced without discarding stored rows."""
        present = {str(row["name"]) for row in con.execute(f"PRAGMA table_info({table})")}
        for name, definition in columns.items():
            if name not in present:
                con.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")

    def _deduplicate_traffic_samples(self, con: sqlite3.Connection) -> None:
        """Collapse repeated readings so the identity index can be created.

        A store written before that index existed can hold two rows for the same
        collector, watch, metric, and second. Keeping the newest row is correct:
        a later write for the same instant is a correction of the earlier one.
        """
        try:
            con.execute(
                "DELETE FROM traffic_samples WHERE id NOT IN ("
                " SELECT MAX(id) FROM traffic_samples GROUP BY collector,watch_id,metric,observed_at)")
        except sqlite3.OperationalError:
            # The table does not exist yet on a first run; the schema creates it.
            pass

    def _repair_legacy_jobs_schema(self, con: sqlite3.Connection) -> None:
        """Bring pre-v7 job tables forward without discarding job or log history."""
        columns = {str(row["name"]) for row in con.execute("PRAGMA table_info(jobs)")}
        if "created_at" not in columns:
            con.execute("ALTER TABLE jobs ADD COLUMN created_at INTEGER")
        if "writes_local" not in columns:
            con.execute("ALTER TABLE jobs ADD COLUMN writes_local INTEGER NOT NULL DEFAULT 0")
        job_columns = {
            "request_json": "TEXT",
            "result_json": "TEXT",
            "summary": "TEXT",
            "duration_ms": "INTEGER",
            "actor": "TEXT",
            "actor_uid": "INTEGER",
            "session_id": "TEXT",
            "reason": "TEXT",
            "ticket": "TEXT",
            "preview_hash": "TEXT",
            "parent_job_id": "TEXT",
            "workflow_step": "TEXT",
        }
        for name, sql_type in job_columns.items():
            if name not in columns:
                con.execute(f"ALTER TABLE jobs ADD COLUMN {name} {sql_type}")
        log_columns = {str(row["name"]) for row in con.execute("PRAGMA table_info(job_logs)")}
        for name, definition in {
            "event_type": "TEXT NOT NULL DEFAULT 'log'",
            "phase": "TEXT",
            "progress_current": "INTEGER",
            "progress_total": "INTEGER",
            "payload_json": "TEXT",
        }.items():
            if name not in log_columns:
                con.execute(f"ALTER TABLE job_logs ADD COLUMN {name} {definition}")
        con.execute(
            "UPDATE jobs SET created_at=COALESCE(created_at,started_at,finished_at,?) WHERE created_at IS NULL",
            (now(),),
        )

    def migrate(self) -> Dict[str, Any]:
        self.init_db()
        mac_cleanup = self._sanitize_invalid_mac_identities()
        with self.connect() as con:
            con.execute(
                "INSERT OR REPLACE INTO schema_meta(key,value,updated_at) VALUES('schema_version',?,?)",
                (SCHEMA_VERSION, now()),
            )
        return {
            "ok": True,
            "schema_version": self.schema_version(),
            "db_path": str(self.paths.sqlite_db),
            "mac_identity_cleanup": mac_cleanup,
        }

    def _sanitize_invalid_mac_identities(self) -> Dict[str, Any]:
        """Remove parser placeholders and multicast values from device identity state."""
        counters = {
            "devices_cleared": 0,
            "aps_cleared": 0,
            "identity_state_deleted": 0,
            "identity_history_deleted": 0,
            "identity_fields_cleared": 0,
            "relationships_deleted": 0,
            "relationship_events_deleted": 0,
            "json_fields_sanitized": 0,
        }
        absent = {"", "n/a", "unknown", "none", "null"}

        def invalid(value: Any) -> bool:
            raw = str(value or "").strip()
            if raw.lower() in absent:
                return False
            digits = re.sub(r"[^0-9a-f]", "", raw.lower())
            return bool(digits) and not normalize_mac(raw)

        with self.connect() as con:
            invalid_values: set[str] = set()
            sources = (
                ("devices", "mac"),
                ("aps", "mac"),
                ("inventory_identity_state", "mac"),
                ("inventory_history", "mac"),
                ("inventory_identity_state", "identity_value"),
                ("inventory_history", "identity_value"),
                ("relationships_current", "subject_id"),
                ("relationship_events", "subject_id"),
            )
            for table, column in sources:
                where = " WHERE identity_kind='mac'" if column == "identity_value" else (" WHERE subject_kind='mac'" if column == "subject_id" else "")
                for row in con.execute(f"SELECT {column} FROM {table}{where}"):
                    if invalid(row[0]):
                        invalid_values.add(str(row[0]))

            forms: set[str] = set(invalid_values)
            for value in list(invalid_values):
                digits = re.sub(r"[^0-9a-f]", "", value.lower())
                if len(digits) == 12:
                    forms.update({
                        digits,
                        ":".join(digits[i:i + 2] for i in range(0, 12, 2)),
                        "-".join(digits[i:i + 2] for i in range(0, 12, 2)),
                        ".".join(digits[i:i + 4] for i in range(0, 12, 4)),
                    })

            def clean_text(value: Any) -> str:
                text = str(value or "")
                for form in sorted(forms, key=len, reverse=True):
                    text = re.sub(re.escape(form), "", text, flags=re.I)
                return text

            for table, key, counter in (("devices", "ip", "devices_cleared"), ("aps", "ip", "aps_cleared")):
                for row in con.execute(f"SELECT {key},mac FROM {table}").fetchall():
                    if invalid(row["mac"]):
                        con.execute(f"UPDATE {table} SET mac='' WHERE {key}=?", (row[key],))
                        counters[counter] += 1

            for row in con.execute("SELECT identity_kind,identity_value,entity_type FROM inventory_identity_state WHERE identity_kind='mac'").fetchall():
                if invalid(row["identity_value"]):
                    con.execute("DELETE FROM inventory_identity_state WHERE identity_kind=? AND identity_value=? AND entity_type=?", tuple(row))
                    counters["identity_state_deleted"] += 1
            for row in con.execute("SELECT id,identity_value FROM inventory_history WHERE identity_kind='mac'").fetchall():
                if invalid(row["identity_value"]):
                    con.execute("DELETE FROM inventory_history WHERE id=?", (row["id"],))
                    counters["identity_history_deleted"] += 1

            for row in con.execute("SELECT identity_kind,identity_value,entity_type,mac FROM inventory_identity_state").fetchall():
                if invalid(row["mac"]):
                    con.execute("UPDATE inventory_identity_state SET mac='' WHERE identity_kind=? AND identity_value=? AND entity_type=?", (row["identity_kind"], row["identity_value"], row["entity_type"]))
                    counters["identity_fields_cleared"] += 1
            for row in con.execute("SELECT id,mac,previous_value,current_value FROM inventory_history").fetchall():
                mac = "" if invalid(row["mac"]) else str(row["mac"] or "")
                previous = clean_text(row["previous_value"])
                current = clean_text(row["current_value"])
                if mac != str(row["mac"] or "") or previous != str(row["previous_value"] or "") or current != str(row["current_value"] or ""):
                    con.execute("UPDATE inventory_history SET mac=?,previous_value=?,current_value=? WHERE id=?", (mac, previous, current, row["id"]))
                    counters["identity_fields_cleared"] += 1

            for row in con.execute("SELECT rel_key,subject_id,attrs_json FROM relationships_current").fetchall():
                if row["subject_id"] and invalid(row["subject_id"]) and str(row["rel_key"]).startswith("identity_mac|"):
                    con.execute("DELETE FROM relationships_current WHERE rel_key=?", (row["rel_key"],))
                    counters["relationships_deleted"] += 1
                    continue
                attrs = clean_text(row["attrs_json"])
                if attrs != str(row["attrs_json"] or ""):
                    con.execute("UPDATE relationships_current SET attrs_json=? WHERE rel_key=?", (attrs, row["rel_key"]))
                    counters["json_fields_sanitized"] += 1
            for row in con.execute("SELECT id,rel_key,subject_id,previous_json,current_json FROM relationship_events").fetchall():
                if row["subject_id"] and invalid(row["subject_id"]) and str(row["rel_key"]).startswith("identity_mac|"):
                    con.execute("DELETE FROM relationship_events WHERE id=?", (row["id"],))
                    counters["relationship_events_deleted"] += 1
                    continue
                previous = clean_text(row["previous_json"])
                current = clean_text(row["current_json"])
                if previous != str(row["previous_json"] or "") or current != str(row["current_json"] or ""):
                    con.execute("UPDATE relationship_events SET previous_json=?,current_json=? WHERE id=?", (previous, current, row["id"]))
                    counters["json_fields_sanitized"] += 1

            changed = sum(counters.values())
            if changed:
                stamp = now()
                detail = {"invalid_values": sorted({re.sub(r"[^0-9a-f]", "", value.lower()) for value in invalid_values}), "counts": counters}
                con.execute(
                    "INSERT INTO scan_runs(id,domain,mode,started_at,finished_at,status,complete,source,detail) VALUES(?,?,?,?,?,?,?,?,?)",
                    ("migration-invalid-mac-" + uuid.uuid4().hex[:12], "migration", "invalid-mac-identity-cleanup", stamp, stamp, "completed", 1, "netops", json.dumps(detail, sort_keys=True)),
                )
                con.execute(
                    "INSERT OR REPLACE INTO settings(key,value,updated_at) VALUES(?,?,?)",
                    ("invalid_mac_identity_v1", json.dumps(detail, sort_keys=True), stamp),
                )
        return {"changed": sum(counters.values()), "counts": counters}

    def schema_version(self) -> str:
        row = self.one("SELECT value FROM schema_meta WHERE key='schema_version'")
        return str(row.get("value") if row else SCHEMA_VERSION)

    def integrity_check(self) -> Dict[str, Any]:
        with self.connect() as con:
            rows = [str(r[0]) for r in con.execute("PRAGMA integrity_check").fetchall()]
            quick = [str(r[0]) for r in con.execute("PRAGMA quick_check").fetchall()]
        ok = rows == ["ok"] and quick == ["ok"]
        return {"ok": ok, "integrity_check": rows, "quick_check": quick}

    def vacuum(self) -> Dict[str, Any]:
        with self.connect() as con:
            con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            con.execute("VACUUM")
            con.execute("PRAGMA optimize")
        return {"ok": True, "db_path": str(self.paths.sqlite_db), "bytes": self.paths.sqlite_db.stat().st_size if self.paths.sqlite_db.exists() else 0}

    def repair(self) -> Dict[str, Any]:
        migration = self.migrate()
        with self.connect() as con:
            con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            con.execute("ANALYZE")
            con.execute("PRAGMA optimize")
        reconciliation = self.sync_derived_state(origin="migration")
        payload = self.integrity_check()
        payload.update({"schema_version": self.schema_version(), "counts": self.counts(), "db_path": str(self.paths.sqlite_db), "reconciliation": reconciliation, "migration": migration})
        return payload

    def db_status_payload(self) -> Dict[str, Any]:
        wal = Path(str(self.paths.sqlite_db) + "-wal")
        shm = Path(str(self.paths.sqlite_db) + "-shm")
        return {
            "ok": True,
            "db_path": str(self.paths.sqlite_db),
            "cache_dir": str(self.paths.cache_dir),
            "schema_version": self.schema_version(),
            "expected_schema_version": SCHEMA_VERSION,
            # One-time migration markers were written and never read, so there
            # was no way to see which data migrations had already applied.
            "applied_migrations": [
                {"key": row["key"], "applied_at": row["updated_at"], "applied_at_iso": fmt_time(row["updated_at"])}
                for row in self.rows("SELECT key,updated_at FROM settings ORDER BY updated_at DESC LIMIT 20")
            ],
            "counts": self.counts(),
            "files": {
                "sqlite_bytes": self.paths.sqlite_db.stat().st_size if self.paths.sqlite_db.exists() else 0,
                "wal_bytes": wal.stat().st_size if wal.exists() else 0,
                "shm_bytes": shm.stat().st_size if shm.exists() else 0,
            },
        }

    def rows(self, sql: str, args: Sequence[Any] = ()) -> List[Dict[str, Any]]:
        with self.connect() as con:
            return [dict(r) for r in con.execute(sql, tuple(args)).fetchall()]

    def one(self, sql: str, args: Sequence[Any] = ()) -> Optional[Dict[str, Any]]:
        with self.connect() as con:
            row = con.execute(sql, tuple(args)).fetchone()
            return dict(row) if row else None

    # The shell helpers read inventory from flat pipe files, not SQLite, so a
    # device row changed here is invisible to them until it is exported. This
    # flag is the single choke point that records that an export is owed;
    # forgetting an explicit export call already shipped one wrong-driver bug.
    INVENTORY_TABLES_RE = re.compile(r"(?is)\b(?:INSERT(?:\s+OR\s+\w+)?\s+INTO|UPDATE|DELETE\s+FROM)\s+(devices|aps|neighbors)\b")

    def execute(self, sql: str, args: Sequence[Any] = ()) -> None:
        with self.connect() as con:
            con.execute(sql, tuple(args))
        if self.INVENTORY_TABLES_RE.search(sql):
            self.inventory_dirty = True

    def execute_many(self, sql: str, rows: Sequence[Sequence[Any]]) -> int:
        """Apply one statement over many rows and report how many it changed.

        One connection for the batch rather than one per row: a sync pulling a
        day of samples moves thousands of them, and the per-connection cost
        dominates everything else at that size. The count is what distinguishes
        rows newly merged from rows an earlier pull already had.
        """
        if not rows:
            return 0
        with self.connect() as con:
            cursor = con.executemany(sql, [tuple(row) for row in rows])
            changed = cursor.rowcount
        if self.INVENTORY_TABLES_RE.search(sql):
            self.inventory_dirty = True
        return max(0, int(changed if changed is not None else 0))

    def flush_inventory_exports(self) -> bool:
        """Write the flat files if inventory changed since the last export."""
        if not getattr(self, "inventory_dirty", False):
            return False
        self.inventory_dirty = False
        with contextlib.suppress(Exception):
            self.export_flat_files()
            return True
        return False

    def record_audit_event(
        self,
        event_type: str,
        action: str,
        *,
        actor: str = "local",
        actor_uid: Optional[int] = None,
        session_id: str = "",
        target: str = "",
        result: str = "",
        reason: str = "",
        ticket: str = "",
        preview_hash: str = "",
        job_id: str = "",
        detail: Optional[Dict[str, Any]] = None,
    ) -> int:
        with self.connect() as con:
            cur = con.execute(
                "INSERT INTO audit_events(created_at,actor,actor_uid,session_id,event_type,action,target,result,reason,ticket,preview_hash,job_id,detail_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    now(), actor or "local", actor_uid, session_id, event_type, action,
                    target, result, reason, ticket, preview_hash, job_id,
                    json.dumps(redact_for_api(detail or {}), sort_keys=True, default=str),
                ),
            )
            return int(cur.lastrowid or 0)

    RETENTION_DEFAULTS = {
        # Operational history: useful recently, noise forever.
        "topology_events": 90,
        "ap_move_events": 90,
        "probe_results": 30,
        "job_logs": 14,
        "core_lookup_cache": 7,
        "path_runs": 90,
        # Traffic history is the one series people look back through: a link
        # that saturates every month-end needs more than a month to show it.
        # It is also small -- a few hundred bytes per sample -- so a generous
        # window costs little. Override with `netrune config set
        # traffic_retention_days`.
        "traffic_samples": 180,
    # Only long enough to cover an outage, not to be a history. Raw counters at
    # polling resolution are the bulkiest thing here, and their purpose is to
    # let a collector that was cut off replay what the other end missed.
    "traffic_counter_log": 7,
    # The rest of operational/diagnostic history. Each of these grew without
    # bound on a long-running install until now: nothing pruned them, and
    # nothing invoked prune_history() on its own. Field-level and lifecycle
    # history keep the longest, since they are what an operator reaches for
    # months later to explain why something is the way it is; per-run and
    # per-check logs are shorter, since a run from a year ago answers nothing
    # a run from last quarter does not.
    "command_history": 90,
    "backup_history": 365,
    "speed_tests": 90,
    "interface_samples": 30,
    "filtering_checks": 30,
    "diagnostic_runs": 90,
    "health_events": 180,
    "inventory_history": 365,
    "relationship_events": 180,
    "scan_runs": 90,
    "ingest_runs": 90,
    # Rejected ingest records are a debugging aid for the channel that
    # produced them, not evidence -- unlike the observations table itself,
    # which (unpruned, alongside observation_fields and inventory_merges) is
    # the append-only provenance trail ADR 0002 and architecture-v8.md
    # describe; erasing it on a timer would contradict what it is for.
    "observation_rejects": 30,
    }

    def retention_days(self, table: str, configured: Optional[Mapping[str, Any]] = None) -> int:
        """Retention for one table, letting an operator widen or narrow it."""
        default = int(self.RETENTION_DEFAULTS.get(table, 0) or 0)
        settings = configured if configured is not None else {}
        raw = settings.get(f"{table}_retention_days") or settings.get("traffic_retention_days" if table.startswith("traffic") else "")
        try:
            value = int(raw)
        except (TypeError, ValueError):
            return default
        # A day is the floor: anything less would delete data the collector is
        # still writing. Ten years is well past any operational question.
        return max(1, min(value, 3650))

    #: Where a device's derived state lives. Evidence and audit are absent on
    #: purpose: forgetting a device corrects the inventory, and is not a way to
    #: erase what was observed or who did what.
    DEVICE_STATE_TABLES = (
        ("devices", "ip"),
        ("health_state", "entity_id"),
        ("neighbors", "local_ip"),
        ("capability_evidence", "device_id"),
        ("topology_snapshot", "local_ip"),
    )

    def device_footprint(self, addresses: Sequence[str]) -> Dict[str, int]:
        """How many rows each table holds for these addresses."""
        found: Dict[str, int] = {}
        targets = [str(value) for value in addresses if str(value or "").strip()]
        if not targets:
            return found
        placeholders = ",".join("?" * len(targets))
        with self.connect() as con:
            for table, column in self.DEVICE_STATE_TABLES:
                try:
                    count = con.execute(
                        f"SELECT COUNT(*) FROM {table} WHERE {column} IN ({placeholders})",
                        tuple(targets)).fetchone()[0]
                except sqlite3.OperationalError:
                    continue
                if count:
                    found[table] = int(count)
            try:
                identity = con.execute(
                    f"SELECT COUNT(*) FROM inventory_identity_state"
                    f" WHERE entity_type='device' AND ip IN ({placeholders})",
                    tuple(targets)).fetchone()[0]
            except sqlite3.OperationalError:
                identity = 0
            if identity:
                found["inventory_identity_state"] = int(identity)
        return found

    def forget_device(self, addresses: Sequence[str], forget_identity: bool = False) -> Dict[str, int]:
        """Remove a device's derived state so a scan can adopt it afresh.

        A device whose name was recorded wrong stays wrong: every later sighting
        reconciles against the stored identity and inherits it. Removing the
        rows lets the next scan record what the device reports now.

        `forget_identity` drops the naming history too. Keeping it is right when
        a device merely changed address, and wrong when the name itself was the
        mistake, so it is the caller's choice rather than a default.
        """
        removed: Dict[str, int] = {}
        targets = [str(value) for value in addresses if str(value or "").strip()]
        if not targets:
            return removed
        placeholders = ",".join("?" * len(targets))
        with self.connect() as con:
            for table, column in self.DEVICE_STATE_TABLES:
                try:
                    cursor = con.execute(
                        f"DELETE FROM {table} WHERE {column} IN ({placeholders})", tuple(targets))
                except sqlite3.OperationalError:
                    continue
                if cursor.rowcount > 0:
                    removed[table] = int(cursor.rowcount)
            if forget_identity:
                try:
                    cursor = con.execute(
                        f"DELETE FROM inventory_identity_state"
                        f" WHERE entity_type='device' AND ip IN ({placeholders})", tuple(targets))
                    if cursor.rowcount > 0:
                        removed["inventory_identity_state"] = int(cursor.rowcount)
                except sqlite3.OperationalError:
                    pass
        # The shell helpers read the flat file, so a device forgotten only in
        # SQLite would still resolve there.
        self.inventory_dirty = True
        return removed

    def get_marker(self, key: str) -> str:
        """A small piece of state a command needs to remember between runs."""
        row = self.one("SELECT value FROM schema_meta WHERE key=?", (f"marker:{key}",))
        return str(row["value"]) if row else ""

    def set_marker(self, key: str, value: str) -> None:
        self.execute(
            "INSERT OR REPLACE INTO schema_meta(key,value,updated_at) VALUES(?,?,?)",
            (f"marker:{key}", str(value), now()))

    def prune_history(self, overrides: Optional[Mapping[str, int]] = None) -> Dict[str, int]:
        """Delete operational history past its retention window.

        `audit_events` is deliberately absent: a privileged-operation record
        that expires is not an audit trail. Everything else here is diagnostic
        and grows without bound if left alone.
        """
        policy = dict(self.RETENTION_DEFAULTS)
        # Configured windows before explicit overrides: a caller passing a value
        # means this run, a setting means every run.
        configured = getattr(self, "retention_settings", None) or {}
        for table in list(policy):
            policy[table] = self.retention_days(table, configured)
        policy.update({key: int(value) for key, value in (overrides or {}).items()})
        removed: Dict[str, int] = {}
        cutoff_now = now()
        with self.connect() as con:
            for table, days in policy.items():
                if days <= 0:
                    continue
                cutoff = cutoff_now - days * 86400
                column = {"path_runs": "started_at", "traffic_samples": "observed_at",
                          "traffic_counter_log": "observed_at", "scan_runs": "started_at",
                          "ingest_runs": "started_at",
                          "observation_rejects": "received_at"}.get(table, "created_at")
                try:
                    cursor = con.execute(f"DELETE FROM {table} WHERE {column} < ?", (cutoff,))
                except sqlite3.OperationalError:
                    continue
                if cursor.rowcount and cursor.rowcount > 0:
                    removed[table] = cursor.rowcount
            # Path children follow their run rather than carrying their own age.
            for child in ("path_hops", "path_findings"):
                with contextlib.suppress(sqlite3.OperationalError):
                    cursor = con.execute(
                        f"DELETE FROM {child} WHERE run_id NOT IN (SELECT run_id FROM path_runs)"
                    )
                    if cursor.rowcount and cursor.rowcount > 0:
                        removed[child] = cursor.rowcount
        return removed

    def record_capability_evidence(
        self,
        device_id: str,
        capability: str,
        state: str,
        facts: Optional[Dict[str, Any]] = None,
        *,
        raw: str = "",
        source: str = "live-inspection",
        confidence: int = 90,
        driver_family: str = "",
        parser_version: str = CAPABILITY_PARSER_VERSION,
        observed_at: Optional[int] = None,
    ) -> int:
        """Persist one semantic driver observation for path inspection.

        The raw hash keys the row so re-reading unchanged device output within
        the same second is idempotent rather than a constraint violation.
        """
        device_id = str(device_id or "").strip()
        capability = str(capability or "").strip()
        if not device_id or not capability:
            return 0
        payload = json.dumps(facts or {}, sort_keys=True, default=str)
        digest = hashlib.sha256((raw or payload).encode("utf-8", "replace")).hexdigest()[:32]
        with self.connect() as con:
            cur = con.execute(
                "INSERT OR REPLACE INTO capability_evidence"
                "(device_id,capability,state,observed_at,source,confidence,facts_json,raw_evidence_hash,driver_family,parser_version)"
                " VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    device_id, capability, str(state or "unknown"), int(observed_at or now()),
                    source, max(0, min(100, int(confidence))), payload, digest,
                    driver_family, parser_version,
                ),
            )
            con.execute(
                "DELETE FROM capability_evidence WHERE device_id=? AND capability=? AND id NOT IN "
                "(SELECT id FROM capability_evidence WHERE device_id=? AND capability=? ORDER BY observed_at DESC,id DESC LIMIT ?)",
                (device_id, capability, device_id, capability, CAPABILITY_EVIDENCE_HISTORY),
            )
            return int(cur.lastrowid or 0)

    def _as_int(self, value: Any, default: int = 0) -> int:
        try: return int(value)
        except (TypeError, ValueError): return default

    def _read_pipe(self, path: Path, fields: int) -> List[List[str]]:
        rows: List[List[str]] = []
        if not path.exists(): return rows
        for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if not raw.strip(): continue
            parts = raw.rstrip("\n").split("|")
            if len(parts) >= fields: rows.append(parts[:fields])
        return rows

    def _valid_current_ip(self, value: Any) -> bool:
        text = str(value or "").strip()
        if not text or text.startswith("wlc:"):
            return False
        try:
            ipaddress.ip_address(text)
            return text != "0.0.0.0"
        except ValueError:
            return False

    def _stable_ap_name(self, value: Any) -> str:
        name = compact_name(value).strip().lower()
        if name in {"", "n/a", "unknown", "cisco-ap", "ruckus-ap"}:
            return ""
        return name

    def _ap_row_key(self, row: List[str]) -> str:
        ip = row[0].strip() if len(row) > 0 else ""
        name = self._stable_ap_name(row[1] if len(row) > 1 else "")
        mac = norm_mac(row[6] if len(row) > 6 else "")
        # Keep distinct current observations by address. Canonical AP identity is
        # reconciled later, where aliases can be retained instead of discarded.
        if self._valid_current_ip(ip):
            return f"ip:{ip}"
        if mac:
            return f"mac:{mac}"
        if name:
            return f"name:{name}"
        return "row:" + "|".join(row[:7]).lower()

    def _ap_row_score(self, row: List[str]) -> Tuple[int, int, int, int, int, int]:
        status = norm_status(row[8] if len(row) > 8 else "")
        ip = row[0] if len(row) > 0 else ""
        switch_ip = row[3] if len(row) > 3 else ""
        switch_name = row[4] if len(row) > 4 else ""
        switch_port = row[5] if len(row) > 5 else ""
        mac = norm_mac(row[6] if len(row) > 6 else "")
        last_seen = self._as_int(row[7] if len(row) > 7 else 0)
        attached = bool(switch_ip and switch_ip != "N/A" and switch_port and switch_port not in {"N/A", "wireless", "not-joined"})
        return (
            1 if status == "ONLINE" else 0,
            1 if self._valid_current_ip(ip) else 0,
            1 if attached else 0,
            1 if switch_name and switch_name != "N/A" else 0,
            1 if mac else 0,
            last_seen,
        )

    @staticmethod
    def _ap_row_attached(row: List[str]) -> bool:
        switch_ip = row[3] if len(row) > 3 else ""
        switch_name = row[4] if len(row) > 4 else ""
        switch_port = str(row[5] if len(row) > 5 else "").strip().lower()
        return bool(
            (switch_ip and switch_ip != "N/A") or (switch_name and switch_name != "N/A")
        ) and switch_port not in {"", "n/a", "wireless", "not-joined", "not joined", "unjoined", "nonjoined"}

    def _dedupe_ap_pipe_rows(self, rows: List[List[str]]) -> List[List[str]]:
        best: Dict[str, List[str]] = {}
        scores: Dict[str, Tuple[int, int, int, int, int, int]] = {}
        attachments: Dict[str, List[str]] = {}
        order: List[str] = []
        for raw in rows:
            row = list(raw[:9])
            while len(row) < 9:
                row.append("")
            key = self._ap_row_key(row)
            score = self._ap_row_score(row)
            if key not in best:
                order.append(key)
                best[key] = row
                scores[key] = score
            elif score >= scores[key]:
                best[key] = row
                scores[key] = score
            # Remember the newest switch-learned attachment separately, so the
            # row that wins on identity cannot discard a real port for the
            # controller's "wireless" placeholder.
            if self._ap_row_attached(row):
                current = attachments.get(key)
                if not current or self._as_int(row[7]) >= self._as_int(current[7]):
                    attachments[key] = row
        for key, attached in attachments.items():
            if key in best and not self._ap_row_attached(best[key]):
                best[key][3], best[key][4], best[key][5] = attached[3], attached[4], attached[5]
        return [best[key] for key in order]

    def _write_pipe(self, path: Path, rows: List[Dict[str, Any]], keys: List[str]) -> None:
        tmp = path.with_suffix(path.suffix + ".tmp")
        with tmp.open("w", encoding="utf-8") as fh:
            for row in rows:
                fh.write("|".join(str(row.get(k) if row.get(k) is not None else "") for k in keys) + "\n")
        tmp.replace(path)

    def import_flat_files(self) -> Dict[str, Any]:
        self.paths.devices_file.touch(exist_ok=True)
        self.paths.aps_file.touch(exist_ok=True)
        self.paths.neighbors_file.touch(exist_ok=True)
        devices = self._read_pipe(self.paths.devices_file, 9)
        aps_raw = self._read_pipe(self.paths.aps_file, 9)
        aps = self._dedupe_ap_pipe_rows(aps_raw)
        neighbors = self._read_pipe(self.paths.neighbors_file, 6)
        ts = now()
        with self.connect() as con:
            con.execute("DELETE FROM devices"); con.execute("DELETE FROM aps"); con.execute("DELETE FROM neighbors")
            for p in devices:
                con.execute("INSERT OR REPLACE INTO devices(ip,hostname,platform,model,serial,mac,source,last_seen,status) VALUES(?,?,?,?,?,?,?,?,?)", (p[0], p[1], p[2], p[3], p[4], p[5] if norm_mac(p[5]) else "", p[6], self._as_int(p[7], ts), norm_status(p[8])))
            for p in aps:
                con.execute("INSERT OR REPLACE INTO aps(ip,name,platform,switch_ip,switch_name,switch_port,mac,last_seen,status) VALUES(?,?,?,?,?,?,?,?,?)", (p[0], p[1], p[2], p[3], p[4], p[5], p[6] if norm_mac(p[6]) else "", self._as_int(p[7], ts), norm_status(p[8])))
            for p in neighbors:
                con.execute("INSERT OR REPLACE INTO neighbors(local_ip,local_name,local_port,remote_name,remote_port,remote_ip) VALUES(?,?,?,?,?,?)", tuple(p[:6]))
        reconciliation = self.sync_derived_state()
        if int(reconciliation.get("manual_merges", {}).get("suppressed") or 0) or int(reconciliation.get("manual_ap_merges", {}).get("suppressed") or 0):
            self.export_flat_files()
        return {"devices": len(devices), "aps": len(aps), "neighbors": len(neighbors), "aps_raw": len(aps_raw), "aps_deduped": max(0, len(aps_raw) - len(aps)), "reconciliation": reconciliation}

    def export_flat_files(self) -> Dict[str, int]:
        devices = self.rows("SELECT ip,hostname,platform,model,serial,mac,source,last_seen,status FROM devices ORDER BY ip")
        aps = self.rows("SELECT ip,name,platform,switch_ip,switch_name,switch_port,mac,last_seen,status FROM aps ORDER BY ip")
        neighbors = self.rows("SELECT local_ip,local_name,local_port,remote_name,remote_port,remote_ip FROM neighbors ORDER BY local_ip,local_port,remote_name")
        self._write_pipe(self.paths.devices_file, devices, ["ip","hostname","platform","model","serial","mac","source","last_seen","status"])
        self._write_pipe(self.paths.aps_file, aps, ["ip","name","platform","switch_ip","switch_name","switch_port","mac","last_seen","status"])
        self._write_pipe(self.paths.neighbors_file, neighbors, ["local_ip","local_name","local_port","remote_name","remote_port","remote_ip"])
        return {"devices": len(devices), "aps": len(aps), "neighbors": len(neighbors)}

    def counts(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        queries = {
            "devices":"SELECT COUNT(*) FROM devices", "neighbors":"SELECT COUNT(*) FROM neighbors",
            "offline_devices":"SELECT COUNT(*) FROM devices WHERE status='OFFLINE'",
            "relationships":"SELECT COUNT(*) FROM relationships_current WHERE status!='disappeared'", "relationship_events":"SELECT COUNT(*) FROM relationship_events",
            "running_jobs":"SELECT COUNT(*) FROM jobs WHERE status IN ('queued','running')", "partial_jobs":"SELECT COUNT(*) FROM jobs WHERE status='partial'", "failed_jobs":"SELECT COUNT(*) FROM jobs WHERE status='failed'", "backups":"SELECT COUNT(*) FROM backup_history",
            "diagnostic_runs":"SELECT COUNT(*) FROM diagnostic_runs", "audit_events":"SELECT COUNT(*) FROM audit_events",
            "manual_merges":"SELECT COUNT(*) FROM inventory_merges WHERE revoked_at IS NULL",
        }
        with self.connect() as con:
            for name, sql in queries.items():
                out[name] = int(con.execute(sql).fetchone()[0])
            raw_aps = [dict(row) for row in con.execute("SELECT * FROM aps")]
        canonical_aps = reconcile_ap_rows(raw_aps)
        out["aps"] = len(canonical_aps)
        out["offline_aps"] = sum(1 for row in canonical_aps if norm_status(row.get("status")) == "OFFLINE")
        out["ap_observations"] = len(raw_aps)
        out["ap_alias_records"] = max(0, len(raw_aps) - len(canonical_aps))
        return out

    def sync_derived_state(self, origin: str = "operational") -> Dict[str, Any]:
        event_tables = ("inventory_history", "health_events", "topology_events", "ap_move_events", "relationship_events")
        with self.connect() as con:
            highwater = {
                table: int(con.execute(f"SELECT COALESCE(MAX(id),0) FROM {table}").fetchone()[0])
                for table in event_tables
            }
            ts = now()
            merge_application = self._apply_manual_merges(con, ts)
            ap_merge_application = self._apply_manual_ap_merges(con, ts)
            inventory_rows = self._current_inventory_rows(con)
            self._sync_identity_history(con, ts, inventory_rows)
            self._sync_health(con, ts, inventory_rows)
            self._sync_topology(con, ts)
            self._sync_relationships(con, ts, inventory_rows)
            suppressed: Dict[str, int] = {}
            if origin == "migration":
                for table, last_id in highwater.items():
                    count = int(con.execute(f"SELECT COUNT(*) FROM {table} WHERE id>?", (last_id,)).fetchone()[0])
                    if count:
                        con.execute(f"DELETE FROM {table} WHERE id>?", (last_id,))
                    suppressed[table] = count
                run_id = "migration-" + uuid.uuid4().hex[:16]
                con.execute(
                    "INSERT INTO scan_runs(id,domain,mode,started_at,finished_at,status,complete,source,detail) VALUES(?,?,?,?,?,?,?,?,?)",
                    (run_id, "migration", "derived-state-reconciliation", ts, now(), "completed", 1, "netops", json.dumps({"suppressed_structural_events": suppressed}, sort_keys=True)),
                )
            return {"origin": origin, "timestamp": ts, "manual_merges": merge_application, "manual_ap_merges": ap_merge_application, "suppressed_structural_events": suppressed}

    def _current_inventory_rows(self, con: sqlite3.Connection) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        raw_devices = [dict(row) for row in con.execute("SELECT ip,hostname,hostname AS name,mac,platform,model,serial,NULL AS switch_ip,NULL AS switch_name,NULL AS switch_port,source,status,last_seen FROM devices WHERE COALESCE(ip,'')!=''")]
        devices = reconcile_device_rows(raw_devices)
        self._overlay_manual_device_merges(con, devices)
        for item in devices:
            item["entity_type"] = "device"
            rows.append(item)
        raw_aps = [dict(row) for row in con.execute("SELECT * FROM aps WHERE COALESCE(ip,'')!='' OR COALESCE(name,'')!='' OR COALESCE(mac,'')!=''")]
        aps = reconcile_ap_rows(raw_aps)
        for item in aps:
            item.update({
                "entity_type": "ap",
                "model": item.get("model") or "",
                "serial": item.get("serial") or "",
                "source": item.get("source") or "AP",
            })
        self._overlay_manual_ap_merges(con, aps)
        rows.extend(aps)
        return rows

    @staticmethod
    def _device_snapshot(row: Dict[str, Any]) -> Dict[str, Any]:
        try:
            last_seen = int(row.get("last_seen") or 0)
        except (TypeError, ValueError):
            last_seen = 0
        return {
            "ip": str(row.get("ip") or "").strip(),
            "hostname": str(row.get("hostname") or row.get("name") or "").strip(),
            "name": str(row.get("name") or row.get("hostname") or "").strip(),
            "platform": str(row.get("platform") or "").strip(),
            "model": str(row.get("model") or "").strip(),
            "serial": str(row.get("serial") or "").strip(),
            "mac": norm_mac(row.get("mac")),
            "source": str(row.get("source") or "").strip(),
            "last_seen": last_seen,
            "status": norm_status(row.get("status")),
        }

    @staticmethod
    def _ap_snapshot(row: Dict[str, Any]) -> Dict[str, Any]:
        """Same key shape as `_device_snapshot` so the generic merge machinery
        never has to branch on entity_type. The `aps` table has no model,
        serial, or source column, so those stay empty rather than missing.
        """
        try:
            last_seen = int(row.get("last_seen") or 0)
        except (TypeError, ValueError):
            last_seen = 0
        return {
            "ip": str(row.get("ip") or "").strip(),
            "hostname": str(row.get("name") or row.get("hostname") or "").strip(),
            "name": str(row.get("name") or row.get("hostname") or "").strip(),
            "platform": str(row.get("platform") or "").strip(),
            "model": "",
            "serial": "",
            "mac": norm_mac(row.get("mac")),
            "source": "",
            "switch_ip": str(row.get("switch_ip") or "").strip(),
            "switch_name": str(row.get("switch_name") or "").strip(),
            "switch_port": str(row.get("switch_port") or "").strip(),
            "last_seen": last_seen,
            "status": norm_status(row.get("status")),
        }

    @staticmethod
    def _merge_key(row: Dict[str, Any], entity_type: str = "device") -> str:
        """Stable merge identity for a device or AP row.

        A separate scheme from `canonical_id` (used by `reconcile_*_rows`
        for grouping observations) -- this one only has to be stable enough
        to recognize the *same* merge endpoint across calls, not to group a
        whole batch of raw observations.
        """
        mac = norm_mac(row.get("mac"))
        if mac:
            return "mac:" + mac
        if entity_type == "ap":
            from netops_platform.identity import ap_name_evidence
            signature = str(ap_name_evidence(row.get("name") or row.get("hostname")).get("signature") or "")
            if signature:
                return "sig:" + signature.lower()
        else:
            serial = re.sub(r"[^A-Z0-9]", "", str(row.get("serial") or "").upper())
            if serial not in {"", "NA", "NONE", "NULL", "UNKNOWN", "NOTAVAILABLE"}:
                return "serial:" + serial.lower()
        ip = str(row.get("ip") or "").strip()
        if is_ipv4_literal(ip):
            return "ip:" + ip
        name = compact_name(row.get("hostname") or row.get("name")).lower()
        return "name:" + name if name else ""

    @classmethod
    def _device_merge_key(cls, row: Dict[str, Any]) -> str:
        return cls._merge_key(row, "device")

    @staticmethod
    def _merge_snapshot(row: Dict[str, Any], field: str) -> Dict[str, Any]:
        try:
            payload = json.loads(str(row.get(field) or "{}"))
        except (TypeError, json.JSONDecodeError):
            payload = {}
        return payload if isinstance(payload, dict) else {}

    @classmethod
    def _matches_snapshot(cls, row: Dict[str, Any], snapshot: Dict[str, Any], entity_type: str = "device") -> bool:
        row_key = cls._merge_key(row, entity_type)
        snapshot_key = cls._merge_key(snapshot, entity_type)
        if row_key and snapshot_key and row_key == snapshot_key:
            return True
        assessment = identity_match_evidence(row, snapshot, "ap" if entity_type == "ap" else "switch")
        return bool(assessment.get("same_device"))

    @classmethod
    def _device_matches_snapshot(cls, row: Dict[str, Any], snapshot: Dict[str, Any]) -> bool:
        return cls._matches_snapshot(row, snapshot, "device")

    @staticmethod
    def _active_merges(con: sqlite3.Connection, entity_type: str = "device") -> List[Dict[str, Any]]:
        return [
            dict(row)
            for row in con.execute(
                "SELECT * FROM inventory_merges WHERE entity_type=? AND revoked_at IS NULL ORDER BY created_at,merge_id",
                (entity_type,),
            )
        ]

    @classmethod
    def _active_device_merges(cls, con: sqlite3.Connection) -> List[Dict[str, Any]]:
        return cls._active_merges(con, "device")

    @staticmethod
    def _device_history_index(history: Sequence[Dict[str, Any]]) -> Dict[str, Dict[str, List[int]]]:
        indexes: Dict[str, Dict[str, List[int]]] = {"ip": {}, "mac": {}, "serial": {}}
        for position, row in enumerate(history):
            values = {
                "ip": str(row.get("ip") or "").strip(),
                "mac": norm_mac(row.get("mac")),
                "serial": re.sub(r"[^A-Z0-9]", "", str(row.get("serial") or "").upper()),
            }
            if values["serial"] in {"", "NA", "NONE", "NULL", "UNKNOWN", "NOTAVAILABLE"}:
                values["serial"] = ""
            for kind, value in values.items():
                if value:
                    indexes[kind].setdefault(value, []).append(position)
        return indexes

    @staticmethod
    def _matching_device_history(
        current: Dict[str, Any],
        history: Sequence[Dict[str, Any]],
        indexes: Dict[str, Dict[str, List[int]]],
    ) -> List[Dict[str, Any]]:
        addresses = {str(value or "").strip() for value in current.get("addresses") or [current.get("ip")] if value}
        macs = {norm_mac(value) for value in current.get("macs") or [current.get("mac")] if norm_mac(value)}
        serials = {
            serial for serial in (
                re.sub(r"[^A-Z0-9]", "", str(value or "").upper())
                for value in current.get("serials") or [current.get("serial")]
            )
            if serial not in {"", "NA", "NONE", "NULL", "UNKNOWN", "NOTAVAILABLE"}
        }
        candidates: Dict[int, bool] = {}
        for value in macs:
            for position in indexes["mac"].get(value, []):
                candidates[position] = True
        for value in serials:
            for position in indexes["serial"].get(value, []):
                candidates[position] = True
        for value in addresses:
            for position in indexes["ip"].get(value, []):
                candidates.setdefault(position, False)
        matched: List[Dict[str, Any]] = []
        for position, strong in candidates.items():
            historical = history[position]
            if strong or identity_match_evidence(current, historical, "switch")["same_device"]:
                matched.append(historical)
        return matched

    def _apply_manual_merges(self, con: sqlite3.Connection, ts: int) -> Dict[str, Any]:
        merges = self._active_device_merges(con)
        if not merges:
            return {"active": 0, "suppressed": 0, "merge_ids": []}
        devices = [dict(row) for row in con.execute("SELECT * FROM devices")]
        devices_by_key: Dict[str, List[Dict[str, Any]]] = {}
        devices_by_ip: Dict[str, List[Dict[str, Any]]] = {}
        devices_by_name: Dict[str, List[Dict[str, Any]]] = {}
        for device in devices:
            devices_by_key.setdefault(self._device_merge_key(device), []).append(device)
            devices_by_ip.setdefault(str(device.get("ip") or ""), []).append(device)
            devices_by_name.setdefault(compact_name(device.get("hostname")).lower(), []).append(device)
        removed_ips: set[str] = set()
        applied: list[str] = []
        for merge in merges:
            source = self._merge_snapshot(merge, "source_snapshot_json")
            target = self._merge_snapshot(merge, "target_snapshot_json")
            source_key = str(merge.get("source_key") or "")
            target_key = str(merge.get("target_key") or "")
            candidates: Dict[str, Dict[str, Any]] = {}
            source_name = compact_name(source.get("hostname") or source.get("name")).lower()
            for device in [
                *devices_by_key.get(source_key, []),
                *devices_by_ip.get(str(source.get("ip") or ""), []),
                *devices_by_name.get(source_name, []),
            ]:
                candidates[str(device.get("ip") or id(device))] = device
            for device in candidates.values():
                ip = str(device.get("ip") or "")
                if not ip or ip in removed_ips:
                    continue
                key = self._device_merge_key(device)
                if key == target_key:
                    continue
                if key == source_key:
                    matched = True
                elif ip == str(target.get("ip") or "") and ip != str(source.get("ip") or ""):
                    matched = False
                elif ip == str(source.get("ip") or "") and ip != str(target.get("ip") or ""):
                    matched = self._device_matches_snapshot(device, source)
                else:
                    matched = self._device_matches_snapshot(device, source) and not self._device_matches_snapshot(device, target)
                if not matched:
                    continue
                con.execute("DELETE FROM devices WHERE ip=?", (ip,))
                con.execute(
                    "UPDATE inventory_merges SET last_applied_at=?,suppressed_observations=suppressed_observations+1 WHERE merge_id=?",
                    (ts, merge["merge_id"]),
                )
                removed_ips.add(ip)
                applied.append(str(merge["merge_id"]))
        return {"active": len(merges), "suppressed": len(removed_ips), "merge_ids": sorted(set(applied))}

    def _overlay_manual_device_merges(self, con: sqlite3.Connection, rows: List[Dict[str, Any]]) -> None:
        merges = self._active_device_merges(con)
        if not merges or not rows:
            return
        by_source = {str(merge.get("source_key") or ""): merge for merge in merges}
        rows_by_key = {
            str(row.get("canonical_id") or self._device_merge_key(row)): row
            for row in rows
            if row.get("canonical_id") or self._device_merge_key(row)
        }
        rows_by_ip = {
            str(address): row
            for row in rows
            for address in row.get("addresses") or ([row.get("ip")] if row.get("ip") else [])
            if address
        }
        rows_by_name = {
            compact_name(name).lower(): row
            for row in rows
            for name in row.get("aliases") or ([row.get("hostname") or row.get("name")] if row.get("hostname") or row.get("name") else [])
            if name
        }

        def final_target(merge: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
            key = str(merge.get("target_key") or "")
            snapshot = self._merge_snapshot(merge, "target_snapshot_json")
            visited = {str(merge.get("source_key") or "")}
            while key in by_source and key not in visited:
                visited.add(key)
                next_merge = by_source[key]
                key = str(next_merge.get("target_key") or "")
                snapshot = self._merge_snapshot(next_merge, "target_snapshot_json")
            return key, snapshot

        for merge in merges:
            target_key, target_snapshot = final_target(merge)
            target = rows_by_key.get(target_key) or rows_by_ip.get(str(target_snapshot.get("ip") or "")) or rows_by_name.get(compact_name(target_snapshot.get("hostname") or target_snapshot.get("name")).lower())
            if target is None:
                target = next((row for row in rows if self._device_matches_snapshot(row, target_snapshot)), None)
            if target is None:
                continue
            source = self._merge_snapshot(merge, "source_snapshot_json")
            aliases = set(target.get("aliases") or [])
            source_name = str(source.get("hostname") or source.get("name") or "").strip()
            if source_name:
                aliases.add(source_name)
            target["aliases"] = sorted(value for value in aliases if value)
            target["alias_names"] = ", ".join(target["aliases"])
            historical_addresses = set(target.get("historical_addresses") or [])
            if source.get("ip"):
                historical_addresses.add(str(source["ip"]))
            target["historical_addresses"] = sorted(historical_addresses)
            historical_macs = set(target.get("historical_macs") or [])
            if norm_mac(source.get("mac")):
                historical_macs.add(norm_mac(source.get("mac")))
            target["historical_macs"] = sorted(historical_macs)
            details = list(target.get("manual_merges") or [])
            details.append({
                "merge_id": merge["merge_id"],
                "source_key": merge["source_key"],
                "source_name": merge.get("source_name") or source_name,
                "source_ip": merge.get("source_ip") or source.get("ip") or "",
                "reason": merge.get("reason") or "",
                "created_at": merge.get("created_at"),
            })
            target["manual_merges"] = details
            target["manual_merge_count"] = len(details)

    def _apply_manual_ap_merges(self, con: sqlite3.Connection, ts: int) -> Dict[str, Any]:
        """AP counterpart of `_apply_manual_merges`. A real second function, not a
        parametrized one: it deletes from `aps` rather than `devices`, which
        doesn't generalize cleanly without an ugly table-name substitution."""
        merges = self._active_merges(con, "ap")
        if not merges:
            return {"active": 0, "suppressed": 0, "merge_ids": []}
        aps = [dict(row) for row in con.execute("SELECT * FROM aps")]
        aps_by_key: Dict[str, List[Dict[str, Any]]] = {}
        aps_by_ip: Dict[str, List[Dict[str, Any]]] = {}
        aps_by_name: Dict[str, List[Dict[str, Any]]] = {}
        for ap in aps:
            aps_by_key.setdefault(self._merge_key(ap, "ap"), []).append(ap)
            aps_by_ip.setdefault(str(ap.get("ip") or ""), []).append(ap)
            aps_by_name.setdefault(compact_name(ap.get("name")).lower(), []).append(ap)
        removed_ips: set[str] = set()
        applied: list[str] = []
        for merge in merges:
            source = self._merge_snapshot(merge, "source_snapshot_json")
            target = self._merge_snapshot(merge, "target_snapshot_json")
            source_key = str(merge.get("source_key") or "")
            target_key = str(merge.get("target_key") or "")
            candidates: Dict[str, Dict[str, Any]] = {}
            source_name = compact_name(source.get("hostname") or source.get("name")).lower()
            for ap in [
                *aps_by_key.get(source_key, []),
                *aps_by_ip.get(str(source.get("ip") or ""), []),
                *aps_by_name.get(source_name, []),
            ]:
                candidates[str(ap.get("ip") or id(ap))] = ap
            for ap in candidates.values():
                ip = str(ap.get("ip") or "")
                if not ip or ip in removed_ips:
                    continue
                key = self._merge_key(ap, "ap")
                if key == target_key:
                    continue
                if key == source_key:
                    matched = True
                elif ip == str(target.get("ip") or "") and ip != str(source.get("ip") or ""):
                    matched = False
                elif ip == str(source.get("ip") or "") and ip != str(target.get("ip") or ""):
                    matched = self._matches_snapshot(ap, source, "ap")
                else:
                    matched = self._matches_snapshot(ap, source, "ap") and not self._matches_snapshot(ap, target, "ap")
                if not matched:
                    continue
                con.execute("DELETE FROM aps WHERE ip=?", (ip,))
                con.execute(
                    "UPDATE inventory_merges SET last_applied_at=?,suppressed_observations=suppressed_observations+1 WHERE merge_id=?",
                    (ts, merge["merge_id"]),
                )
                removed_ips.add(ip)
                applied.append(str(merge["merge_id"]))
        return {"active": len(merges), "suppressed": len(removed_ips), "merge_ids": sorted(set(applied))}

    def _overlay_manual_ap_merges(self, con: sqlite3.Connection, rows: List[Dict[str, Any]]) -> None:
        """AP counterpart of `_overlay_manual_device_merges`, reading `aps`-table merges."""
        merges = self._active_merges(con, "ap")
        if not merges or not rows:
            return
        by_source = {str(merge.get("source_key") or ""): merge for merge in merges}
        rows_by_key = {
            str(row.get("canonical_id") or self._merge_key(row, "ap")): row
            for row in rows
            if row.get("canonical_id") or self._merge_key(row, "ap")
        }
        rows_by_ip = {
            str(address): row
            for row in rows
            for address in row.get("addresses") or ([row.get("ip")] if row.get("ip") else [])
            if address
        }
        rows_by_name = {
            compact_name(name).lower(): row
            for row in rows
            for name in row.get("aliases") or ([row.get("name")] if row.get("name") else [])
            if name
        }

        def final_target(merge: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
            key = str(merge.get("target_key") or "")
            snapshot = self._merge_snapshot(merge, "target_snapshot_json")
            visited = {str(merge.get("source_key") or "")}
            while key in by_source and key not in visited:
                visited.add(key)
                next_merge = by_source[key]
                key = str(next_merge.get("target_key") or "")
                snapshot = self._merge_snapshot(next_merge, "target_snapshot_json")
            return key, snapshot

        for merge in merges:
            target_key, target_snapshot = final_target(merge)
            target = rows_by_key.get(target_key) or rows_by_ip.get(str(target_snapshot.get("ip") or "")) or rows_by_name.get(compact_name(target_snapshot.get("hostname") or target_snapshot.get("name")).lower())
            if target is None:
                target = next((row for row in rows if self._matches_snapshot(row, target_snapshot, "ap")), None)
            if target is None:
                continue
            source = self._merge_snapshot(merge, "source_snapshot_json")
            aliases = set(target.get("aliases") or [])
            source_name = str(source.get("hostname") or source.get("name") or "").strip()
            if source_name:
                aliases.add(source_name)
            target["aliases"] = sorted(value for value in aliases if value)
            target["alias_names"] = ", ".join(target["aliases"])
            historical_addresses = set(target.get("historical_addresses") or [])
            if source.get("ip"):
                historical_addresses.add(str(source["ip"]))
            target["historical_addresses"] = sorted(historical_addresses)
            historical_macs = set(target.get("historical_macs") or [])
            if norm_mac(source.get("mac")):
                historical_macs.add(norm_mac(source.get("mac")))
            target["historical_macs"] = sorted(historical_macs)
            details = list(target.get("manual_merges") or [])
            details.append({
                "merge_id": merge["merge_id"],
                "source_key": merge["source_key"],
                "source_name": merge.get("source_name") or source_name,
                "source_ip": merge.get("source_ip") or source.get("ip") or "",
                "reason": merge.get("reason") or "",
                "created_at": merge.get("created_at"),
            })
            target["manual_merges"] = details
            target["manual_merge_count"] = len(details)

    def list_device_merges(self, include_revoked: bool = False) -> List[Dict[str, Any]]:
        where = "" if include_revoked else " WHERE revoked_at IS NULL"
        return self.rows(
            "SELECT merge_id,entity_type,source_key,target_key,source_name,source_ip,target_name,target_ip,reason,actor,created_at,last_applied_at,suppressed_observations,revoked_at,revoked_by,revoke_reason "
            f"FROM inventory_merges{where} ORDER BY created_at DESC,merge_id DESC"
        )

    def list_ap_merges(self, include_revoked: bool = False) -> List[Dict[str, Any]]:
        where = "" if include_revoked else " AND revoked_at IS NULL"
        return self.rows(
            "SELECT merge_id,entity_type,source_key,target_key,source_name,source_ip,target_name,target_ip,reason,actor,created_at,last_applied_at,suppressed_observations,revoked_at,revoked_by,revoke_reason "
            f"FROM inventory_merges WHERE entity_type='ap'{where} ORDER BY created_at DESC,merge_id DESC"
        )

    def create_manual_merge(self, entity_type: str, source_row: Dict[str, Any], target_row: Dict[str, Any], reason: str, actor: str) -> Dict[str, Any]:
        snapshot = self._ap_snapshot if entity_type == "ap" else self._device_snapshot
        source = snapshot(source_row)
        target = snapshot(target_row)
        source_key = self._merge_key(source, entity_type)
        target_key = self._merge_key(target, entity_type)
        if not source_key or not target_key:
            raise ValueError(f"both {entity_type}s require a stable MAC, serial, IP, or name identity")
        if source_key == target_key or source.get("ip") == target.get("ip"):
            raise ValueError(f"source and target resolve to the same active {entity_type}")
        reason = str(reason or "").strip()
        if not reason or len(reason) > 500 or any(value in reason for value in "\r\n\x00"):
            raise ValueError("a one-line merge reason of 1-500 characters is required")
        actor = str(actor or "local")[:128]
        merge_id = "mrg-" + uuid.uuid4().hex[:20]
        ts = now()
        source_json = json.dumps(source, sort_keys=True, separators=(",", ":"))
        target_json = json.dumps(target, sort_keys=True, separators=(",", ":"))
        with self.connect() as con:
            active = self._active_merges(con, entity_type)
            edges = {str(row["source_key"]): str(row["target_key"]) for row in active}
            if source_key in edges:
                raise ValueError(f"source {entity_type} already has an active manual merge: {source_key}")
            cursor = target_key
            visited: set[str] = set()
            while cursor in edges and cursor not in visited:
                if cursor == source_key:
                    raise ValueError("manual merge would create an identity cycle")
                visited.add(cursor)
                cursor = edges[cursor]
            if cursor == source_key:
                raise ValueError("manual merge would create an identity cycle")
            con.execute(
                "INSERT INTO inventory_merges(merge_id,entity_type,source_key,target_key,source_name,source_ip,target_name,target_ip,source_snapshot_json,target_snapshot_json,reason,actor,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (merge_id, entity_type, source_key, target_key, source["hostname"], source["ip"], target["hostname"], target["ip"], source_json, target_json, reason, actor, ts),
            )
            identity_values = [("ip", source["ip"]), ("mac", source["mac"]), ("name", source["hostname"])]
            for kind, value in ((kind, str(value or "").strip()) for kind, value in identity_values):
                if not value:
                    continue
                if kind == "mac":
                    value = norm_mac(value)
                elif kind == "name":
                    value = value.lower()
                if not value:
                    continue
                con.execute(
                    "INSERT INTO inventory_history(created_at,entity_type,identity_kind,identity_value,event_type,previous_value,current_value,ip,mac,name,platform,model,serial,source,status) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (ts, entity_type, kind, value, "manually_merged", source_json, json.dumps({"merge_id": merge_id, "target": target}, sort_keys=True, separators=(",", ":")), source["ip"], source["mac"], source["hostname"], source["platform"], source["model"], source["serial"], source["source"], "HISTORICAL"),
                )
                existing = con.execute(
                    "SELECT first_seen FROM inventory_identity_state WHERE identity_kind=? AND identity_value=? AND entity_type=?",
                    (kind, value, entity_type),
                ).fetchone()
                first_seen = int(existing[0]) if existing and existing[0] else int(source.get("last_seen") or ts)
                con.execute(
                    "INSERT OR REPLACE INTO inventory_identity_state(identity_kind,identity_value,entity_type,ip,mac,name,platform,model,serial,switch_ip,switch_name,switch_port,source,status,first_seen,last_seen,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (kind, value, entity_type, source["ip"], source["mac"], source["hostname"], source["platform"], source["model"], source["serial"], source.get("switch_ip") or "", source.get("switch_name") or "", source.get("switch_port") or "", source["source"], "HISTORICAL", first_seen, int(source.get("last_seen") or ts), ts),
                )
        return {
            "merge_id": merge_id,
            "entity_type": entity_type,
            "source_key": source_key,
            "target_key": target_key,
            "source_name": source["hostname"],
            "source_ip": source["ip"],
            "target_name": target["hostname"],
            "target_ip": target["ip"],
            "reason": reason,
            "actor": actor,
            "created_at": ts,
        }

    def create_device_merge(self, source_row: Dict[str, Any], target_row: Dict[str, Any], reason: str, actor: str) -> Dict[str, Any]:
        return self.create_manual_merge("device", source_row, target_row, reason, actor)

    def revoke_manual_merge(self, entity_type: str, merge_id: str, reason: str, actor: str) -> Dict[str, Any]:
        merge_id = str(merge_id or "").strip()
        reason = str(reason or "").strip()
        if not merge_id:
            raise ValueError("merge id is required")
        if not reason or len(reason) > 500 or any(value in reason for value in "\r\n\x00"):
            raise ValueError("a one-line revocation reason of 1-500 characters is required")
        table = "aps" if entity_type == "ap" else "devices"
        ts = now()
        with self.connect() as con:
            stored = con.execute(
                "SELECT * FROM inventory_merges WHERE merge_id=? AND entity_type=? AND revoked_at IS NULL",
                (merge_id, entity_type),
            ).fetchone()
            if not stored:
                raise ValueError(f"active manual merge not found: {merge_id}")
            merge = dict(stored)
            source = self._merge_snapshot(merge, "source_snapshot_json")
            source_ip = str(source.get("ip") or "")
            if not is_ipv4_literal(source_ip):
                raise ValueError("historical source has no restorable IP address")
            existing = con.execute(f"SELECT * FROM {table} WHERE ip=?", (source_ip,)).fetchone()
            if existing and not self._matches_snapshot(dict(existing), source, entity_type):
                raise ValueError(f"source IP is now owned by a different active {entity_type}: {source_ip}")
            if not existing:
                if entity_type == "ap":
                    con.execute(
                        "INSERT INTO aps(ip,name,platform,switch_ip,switch_name,switch_port,mac,last_seen,status) VALUES(?,?,?,?,?,?,?,?,?)",
                        (source["ip"], source["hostname"], source["platform"], source.get("switch_ip") or "", source.get("switch_name") or "", source.get("switch_port") or "", source["mac"], int(source.get("last_seen") or ts), source["status"]),
                    )
                else:
                    con.execute(
                        "INSERT INTO devices(ip,hostname,platform,model,serial,mac,source,last_seen,status) VALUES(?,?,?,?,?,?,?,?,?)",
                        (source["ip"], source["hostname"], source["platform"], source["model"], source["serial"], source["mac"], source["source"], int(source.get("last_seen") or ts), source["status"]),
                    )
            con.execute(
                "UPDATE inventory_merges SET revoked_at=?,revoked_by=?,revoke_reason=? WHERE merge_id=?",
                (ts, str(actor or "local")[:128], reason, merge_id),
            )
            con.execute(
                "INSERT INTO inventory_history(created_at,entity_type,identity_kind,identity_value,event_type,previous_value,current_value,ip,mac,name,platform,model,serial,source,status) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (ts, entity_type, "merge", merge_id, "manual_merge_revoked", merge["target_snapshot_json"], merge["source_snapshot_json"], source["ip"], source["mac"], source["hostname"], source["platform"], source["model"], source["serial"], source["source"], source["status"]),
            )
        return {
            key: value for key, value in {
                **merge,
                "revoked_at": ts,
                "revoked_by": str(actor or "local")[:128],
                "revoke_reason": reason,
            }.items()
            if key not in {"source_snapshot_json", "target_snapshot_json"}
        }

    def revoke_device_merge(self, merge_id: str, reason: str, actor: str) -> Dict[str, Any]:
        return self.revoke_manual_merge("device", merge_id, reason, actor)

    def _identity_keys(self, row: Dict[str, Any]) -> List[Tuple[str, str]]:
        keys: List[Tuple[str, str]] = []
        seen: set[Tuple[str, str]] = set()

        def add(kind: str, value: Any) -> None:
            text_value = str(value or "").strip()
            if kind == "mac":
                text_value = norm_mac(text_value)
            elif kind == "name":
                text_value = text_value.lower()
            if text_value and (kind, text_value) not in seen:
                seen.add((kind, text_value))
                keys.append((kind, text_value))

        for value in [row.get("ip"), *(row.get("addresses") or [])]:
            add("ip", value)
        for value in [row.get("mac"), *(row.get("macs") or [])]:
            add("mac", value)
        for value in [row.get("name"), *(row.get("aliases") or [])]:
            add("name", value)
        return keys

    def _sync_identity_history(self, con: sqlite3.Connection, ts: int, inventory_rows: Optional[Sequence[Dict[str, Any]]] = None) -> None:
        for row in inventory_rows if inventory_rows is not None else self._current_inventory_rows(con):
            entity_type = row["entity_type"]
            clean = {"ip": row.get("ip") or "", "mac": row.get("mac") or "", "name": row.get("name") or "", "platform": row.get("platform") or "", "model": row.get("model") or "", "serial": row.get("serial") or "", "switch_ip": row.get("switch_ip") or "", "switch_name": row.get("switch_name") or "", "switch_port": row.get("switch_port") or "", "source": row.get("source") or "", "status": norm_status(row.get("status"))}
            for kind, value in self._identity_keys(row):
                existing = con.execute("SELECT * FROM inventory_identity_state WHERE identity_kind=? AND identity_value=? AND entity_type=?", (kind, value, entity_type)).fetchone()
                first_seen = self._as_int(row.get("last_seen"), ts)
                if not existing:
                    con.execute("INSERT INTO inventory_history(created_at,entity_type,identity_kind,identity_value,event_type,field_name,previous_value,current_value,ip,mac,name,switch_ip,switch_name,switch_port,platform,model,serial,source,status) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (ts, entity_type, kind, value, "first_seen", None, None, json.dumps(clean, separators=(",",":")), clean["ip"], clean["mac"], clean["name"], clean["switch_ip"], clean["switch_name"], clean["switch_port"], clean["platform"], clean["model"], clean["serial"], clean["source"], clean["status"]))
                else:
                    ex = dict(existing); first_seen = ex.get("first_seen") or first_seen
                    for field_name in ["ip","mac","name","platform","model","serial","switch_ip","switch_name","switch_port","source","status"]:
                        prev = str(ex.get(field_name) or ""); curr = str(clean.get(field_name) or "")
                        if prev != curr:
                            con.execute("INSERT INTO inventory_history(created_at,entity_type,identity_kind,identity_value,event_type,field_name,previous_value,current_value,ip,mac,name,switch_ip,switch_name,switch_port,platform,model,serial,source,status) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (ts, entity_type, kind, value, "field_changed", field_name, prev, curr, clean["ip"], clean["mac"], clean["name"], clean["switch_ip"], clean["switch_name"], clean["switch_port"], clean["platform"], clean["model"], clean["serial"], clean["source"], clean["status"]))
                con.execute("INSERT OR REPLACE INTO inventory_identity_state(identity_kind,identity_value,entity_type,ip,mac,name,platform,model,serial,switch_ip,switch_name,switch_port,source,status,first_seen,last_seen,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (kind, value, entity_type, clean["ip"], clean["mac"], clean["name"], clean["platform"], clean["model"], clean["serial"], clean["switch_ip"], clean["switch_name"], clean["switch_port"], clean["source"], clean["status"], first_seen, self._as_int(row.get("last_seen"), ts), ts))

    def _sync_health(self, con: sqlite3.Connection, ts: int, inventory_rows: Optional[Sequence[Dict[str, Any]]] = None) -> None:
        con.execute("DELETE FROM health_state WHERE COALESCE(entity_id,'')=''")
        con.execute("DELETE FROM health_events WHERE COALESCE(entity_id,'')=''")
        current_keys: set[Tuple[str, str]] = set()
        for row in inventory_rows if inventory_rows is not None else self._current_inventory_rows(con):
            entity_type = row["entity_type"]
            entity_id = row.get("canonical_id") or norm_mac(row.get("mac")) or row.get("ip") or row.get("name")
            if not entity_id:
                continue
            current_keys.add((entity_type, str(entity_id)))
            status = norm_status(row.get("status"))
            existing = con.execute("SELECT * FROM health_state WHERE entity_type=? AND entity_id=?", (entity_type, entity_id)).fetchone()
            first_seen = self._as_int(row.get("last_seen"), ts)
            last_seen = first_seen if status == "ONLINE" else None
            last_failed = first_seen if status == "OFFLINE" else None
            outage_started_at = ts if status == "OFFLINE" else None
            flap_count = 0
            if existing:
                ex = dict(existing)
                first_seen = ex.get("first_seen") or first_seen
                flap_count = int(ex.get("flap_count") or 0)
                outage_started_at = ex.get("outage_started_at")
                if ex.get("status") != status:
                    flap_count += 1
                    con.execute(
                        "INSERT INTO health_events(created_at,entity_type,entity_id,event_type,previous_value,current_value,detail) VALUES(?,?,?,?,?,?,?)",
                        (ts, entity_type, entity_id, "status_changed", ex.get("status"), status, row.get("name") or ""),
                    )
                if status == "OFFLINE" and not outage_started_at:
                    outage_started_at = ts
                if status == "ONLINE" and outage_started_at:
                    outage_started_at = None
                last_seen = self._as_int(row.get("last_seen"), ts) if status == "ONLINE" else ex.get("last_seen")
                last_failed = self._as_int(row.get("last_seen"), ts) if status == "OFFLINE" else ex.get("last_failed")
            else:
                con.execute(
                    "INSERT INTO health_events(created_at,entity_type,entity_id,event_type,previous_value,current_value,detail) VALUES(?,?,?,?,?,?,?)",
                    (ts, entity_type, entity_id, "first_seen", None, status, row.get("name") or ""),
                )
            con.execute(
                "INSERT OR REPLACE INTO health_state(entity_type,entity_id,name,platform,serial,status,first_seen,last_seen,last_failed,outage_started_at,flap_count,switch_ip,switch_port,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (entity_type, entity_id, row.get("name"), row.get("platform"), row.get("serial"), status, first_seen, last_seen, last_failed, outage_started_at, flap_count, row.get("switch_ip"), row.get("switch_port"), ts),
            )
        for stale in con.execute("SELECT entity_type,entity_id FROM health_state").fetchall():
            key = (str(stale["entity_type"]), str(stale["entity_id"]))
            if key not in current_keys:
                con.execute("DELETE FROM health_state WHERE entity_type=? AND entity_id=?", key)

    def _sync_topology(self, con: sqlite3.Connection, ts: int) -> None:
        current = {tuple(r) for r in con.execute("SELECT local_ip,local_port,remote_name,remote_port,remote_ip FROM neighbors")}
        previous = {tuple(r) for r in con.execute("SELECT local_ip,local_port,remote_name,remote_port,remote_ip FROM topology_snapshot")}
        for item in sorted(current - previous): con.execute("INSERT INTO topology_events(created_at,event_type,local_ip,local_port,remote_name,remote_port,remote_ip,detail) VALUES(?,?,?,?,?,?,?,?)", (ts, "link_added", *item, "new neighbor link"))
        for item in sorted(previous - current): con.execute("INSERT INTO topology_events(created_at,event_type,local_ip,local_port,remote_name,remote_port,remote_ip,detail) VALUES(?,?,?,?,?,?,?,?)", (ts, "link_removed", *item, "missing from latest neighbor discovery"))
        con.execute("DELETE FROM topology_snapshot"); con.executemany("INSERT OR REPLACE INTO topology_snapshot(local_ip,local_port,remote_name,remote_port,remote_ip) VALUES(?,?,?,?,?)", list(current))

    def _continuity_config(self) -> Dict[str, int]:
        public = Config(self.paths).public

        def intval(key: str, default: int) -> int:
            try:
                return int(public.get(key) or default)
            except (TypeError, ValueError):
                return default

        return {
            "window_days": max(1, intval("continuity_window_days", 14)),
            "confidence_floor": max(0, min(100, intval("continuity_confidence_floor", 55))),
            "cluster_min_members": max(2, intval("continuity_cluster_min_members", 3)),
            "attention_ttl_days": max(1, intval("continuity_attention_ttl_days", 30)),
        }

    def _continuity_pool_row(self, raw: Dict[str, Any], entity_type: str) -> Dict[str, Any]:
        return {
            "name": raw.get("name") or "",
            "ip": raw.get("ip") or "",
            "mac": raw.get("mac") or "",
            "model": raw.get("model") or "",
            "platform": raw.get("platform") or "",
            "switch_ip": raw.get("switch_ip") or "",
            "switch_name": raw.get("switch_name") or "",
            "switch_port": raw.get("switch_port") or "",
            "first_seen": raw.get("first_seen"),
            "last_seen": raw.get("last_seen"),
            "canonical_id": self._merge_key(raw, entity_type),
        }

    def _continuity_first_seen(self, con: sqlite3.Connection, row: Dict[str, Any], entity_type: str) -> Optional[int]:
        """The earliest `first_seen` on record for any of this row's own
        identity values, most-specific first. Used to tell a genuinely
        freshly-appeared entity from a long-standing one that merely wasn't
        re-derived with a new timestamp this exact tick.
        """
        candidates = [
            ("mac", normalize_mac(row.get("mac"))),
            ("ip", str(row.get("ip") or "").strip()),
            ("name", str(row.get("name") or row.get("hostname") or "").strip().lower()),
        ]
        for kind, value in candidates:
            if not value:
                continue
            found = con.execute(
                "SELECT first_seen FROM inventory_identity_state WHERE identity_kind=? AND identity_value=? AND entity_type=?",
                (kind, value, entity_type),
            ).fetchone()
            if found and found[0] is not None:
                return int(found[0])
        return None

    def _continuity_candidate_rels(self, con: sqlite3.Connection, canonical_rows: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Propose that a newly-appeared device/AP continues one that just
        disappeared, using signals beyond plain identity (attachment, a
        location+role match across naming conventions, or timing on top of
        one of those -- never timing alone). Never auto-applied: this only
        writes a candidate relationship for an operator to confirm through
        `inventory merge`/`ap merge`.
        """
        config = self._continuity_config()
        cutoff = now() - config["window_days"] * 86400
        current_ids = {
            (str(row.get("entity_type") or ""), str(row.get("canonical_id") or "").lower())
            for row in canonical_rows if row.get("canonical_id")
        }
        # A pair an operator already confirmed through `inventory merge`/
        # `ap merge` is resolved, not pending -- it should stop being
        # re-proposed even though the old side is still (and will remain)
        # absent from `current_ids`.
        merged_pairs = {
            (entity_type, str(merge.get("source_key") or "").lower(), str(merge.get("target_key") or "").lower())
            for entity_type in ("device", "ap")
            for merge in self._active_merges(con, entity_type)
        }

        old_pools: Dict[str, List[Dict[str, Any]]] = {"device": [], "ap": []}
        seen_old: set = set()
        for raw in con.execute("SELECT * FROM inventory_identity_state WHERE last_seen>=?", (cutoff,)):
            r = dict(raw)
            entity_type = r.get("entity_type")
            if entity_type not in old_pools:
                continue
            pool_row = self._continuity_pool_row(r, entity_type)
            key = (entity_type, pool_row["canonical_id"].lower())
            if not pool_row["canonical_id"] or key in current_ids or key in seen_old:
                continue
            seen_old.add(key)
            old_pools[entity_type].append(pool_row)

        new_pools: Dict[str, List[Dict[str, Any]]] = {"device": [], "ap": []}
        for row in canonical_rows:
            entity_type = row.get("entity_type")
            if entity_type not in new_pools or not row.get("canonical_id"):
                continue
            first_seen = self._continuity_first_seen(con, row, entity_type)
            if first_seen is None or first_seen < cutoff:
                continue
            pool_row = self._continuity_pool_row(row, entity_type)
            pool_row["first_seen"] = first_seen
            pool_row["canonical_id"] = str(row.get("canonical_id")).lower()
            new_pools[entity_type].append(pool_row)

        rels: List[Dict[str, Any]] = []
        for entity_type in ("device", "ap"):
            old_pool = old_pools[entity_type]
            new_pool = new_pools[entity_type]
            if not old_pool or not new_pool:
                continue
            kind = "ap" if entity_type == "ap" else "switch"
            # No confidence floor here: a floor is applied where this is
            # surfaced (`attention_payload`), not where it's persisted, so a
            # weak isolated pair and a weak pair that is one of several
            # sharing a site-rename pattern can be told apart at display
            # time. `identity_continuity_candidates` already only returns
            # structurally-grounded pairs (never timing alone).
            for candidate in identity_continuity_candidates(old_pool, new_pool, kind, window_days=config["window_days"]):
                old, new = candidate["old"], candidate["new"]
                if (entity_type, old["canonical_id"].lower(), new["canonical_id"].lower()) in merged_pairs:
                    continue
                rel_key = f"identity_swap_candidate|{entity_type}|{old['canonical_id']}|{new['canonical_id']}"
                rels.append({
                    "rel_key": rel_key,
                    "rel_type": "identity_swap_candidate",
                    "subject_kind": entity_type,
                    "subject_id": old["canonical_id"],
                    "object_kind": entity_type,
                    "object_id": new["canonical_id"],
                    "source": "identity_continuity",
                    "confidence": candidate["confidence"],
                    "status": "active",
                    "attrs": {"entity_type": entity_type, "old": old, "new": new, "signals": candidate["signals"]},
                })
        # Re-affirm still-unresolved candidates from an earlier tick so they
        # are not spuriously retracted just because this tick's fresh search
        # did not happen to regenerate them (e.g. the "new" side is no longer
        # inside the first-seen window but is still the only plausible match).
        fresh_keys = {rel["rel_key"] for rel in rels}
        for raw in con.execute("SELECT * FROM relationships_current WHERE rel_type='identity_swap_candidate' AND status!='disappeared'"):
            existing = dict(raw)
            if existing["rel_key"] in fresh_keys:
                continue
            try:
                attrs = json.loads(existing.get("attrs_json") or "{}")
            except (TypeError, json.JSONDecodeError):
                continue
            entity_type = str(attrs.get("entity_type") or "")
            old_id = str((attrs.get("old") or {}).get("canonical_id") or "").lower()
            new_id = str((attrs.get("new") or {}).get("canonical_id") or "").lower()
            if (entity_type, old_id) in current_ids or (entity_type, new_id) not in current_ids:
                continue  # old reappeared, or the new side itself vanished -- let it lapse
            if (entity_type, old_id, new_id) in merged_pairs:
                continue  # already resolved via a confirmed manual merge
            rels.append({
                "rel_key": existing["rel_key"],
                "rel_type": "identity_swap_candidate",
                "subject_kind": existing["subject_kind"],
                "subject_id": existing["subject_id"],
                "object_kind": existing["object_kind"],
                "object_id": existing["object_id"],
                "source": existing.get("source") or "identity_continuity",
                "confidence": existing.get("confidence"),
                "status": "active",
                "attrs": attrs,
            })
        return rels

    def _relationship_desired(self, con: sqlite3.Connection, inventory_rows: Optional[Sequence[Dict[str, Any]]] = None) -> Dict[str, Dict[str, Any]]:
        desired: Dict[str, Dict[str, Any]] = {}
        def add(rel: Dict[str, Any]) -> None:
            rel.setdefault("status", "active"); rel.setdefault("confidence", 70); rel.setdefault("attrs", {})
            rel["attrs_json"] = json.dumps(rel.pop("attrs"), sort_keys=True, separators=(",",":")); desired[rel["rel_key"]] = rel
        device_identity_history = [
            dict(row) for row in con.execute(
                "SELECT identity_kind,identity_value,ip,mac,name,model,serial "
                "FROM inventory_identity_state WHERE entity_type='device'"
            )
        ]
        device_history_index = self._device_history_index(device_identity_history)
        canonical_rows = list(inventory_rows) if inventory_rows is not None else self._current_inventory_rows(con)
        for r in (row for row in canonical_rows if row.get("entity_type") == "device"):
            ip = r.get("ip") or ""; name = r.get("hostname") or r.get("name") or ip
            device_id = r.get("canonical_id") or name or ip
            addresses = set(r.get("addresses") or ([ip] if ip else []))
            macs = {
                norm_mac(value)
                for value in (r.get("macs") or ([r.get("mac")] if r.get("mac") else []))
                if norm_mac(value)
            }
            serials = {
                re.sub(r"[^A-Z0-9]", "", str(value or "").upper())
                for value in (r.get("serials") or ([r.get("serial")] if r.get("serial") else []))
                if re.sub(r"[^A-Z0-9]", "", str(value or "").upper())
                not in {"", "NA", "NONE", "NULL", "UNKNOWN", "NOTAVAILABLE"}
            }
            aliases = set(r.get("aliases") or ([name] if name else []))
            current_identity = {
                "ip": ip,
                "mac": next(iter(macs), ""),
                "serial": next(iter(serials), ""),
                "hostname": name,
                "model": r.get("model") or "",
                "addresses": sorted(addresses),
                "macs": sorted(macs),
                "serials": sorted(serials),
            }
            for historical in self._matching_device_history(current_identity, device_identity_history, device_history_index):
                aliases.add(str(historical.get("name") or "").strip())
                if historical.get("identity_kind") == "name":
                    aliases.add(str(historical.get("identity_value") or "").strip())
            aliases = {alias for alias in aliases if alias}
            common_attrs = {
                "canonical_id": device_id,
                "ip": ip,
                "name": name,
                "mac": r.get("mac"),
                "platform": r.get("platform"),
                "status": r.get("status"),
                "aliases": sorted(aliases),
                "addresses": r.get("addresses") or [],
                "identity_confidence": r.get("identity_confidence"),
            }
            for address in r.get("addresses") or ([ip] if ip else []):
                add({"rel_key":f"identity_ip|device|{address}","rel_type":"identity_ip","subject_kind":"ip","subject_id":address,"object_kind":"device","object_id":name,"source":r.get("source") or "inventory","confidence":95,"attrs":common_attrs})
            for mac in r.get("macs") or ([norm_mac(r.get("mac"))] if norm_mac(r.get("mac")) else []):
                add({"rel_key":f"identity_mac|device|{mac}","rel_type":"identity_mac","subject_kind":"mac","subject_id":mac,"object_kind":"device","object_id":name,"source":r.get("source") or "inventory","confidence":99,"attrs":common_attrs})
            for alias in sorted(aliases):
                alias_key = compact_name(alias).lower()
                if alias_key:
                    add({"rel_key":f"device_alias|device|{device_id}|{alias_key}","rel_type":"device_alias","subject_kind":"alias","subject_id":alias_key,"object_kind":"device","object_id":device_id,"source":r.get("source") or "inventory","confidence":int(r.get("identity_confidence") or 75),"attrs":common_attrs})
        for merge in self._active_device_merges(con):
            add({
                "rel_key": f"manual_identity_merge|{merge['merge_id']}",
                "rel_type": "manual_identity_merge",
                "subject_kind": "historical_device",
                "subject_id": merge["source_key"],
                "object_kind": "device",
                "object_id": merge["target_key"],
                "source": "operator",
                "confidence": 100,
                "attrs": {
                    "merge_id": merge["merge_id"],
                    "source_name": merge.get("source_name") or "",
                    "source_ip": merge.get("source_ip") or "",
                    "target_name": merge.get("target_name") or "",
                    "target_ip": merge.get("target_ip") or "",
                    "reason": merge.get("reason") or "",
                    "actor": merge.get("actor") or "",
                    "created_at": merge.get("created_at"),
                },
            })
        for r in (row for row in canonical_rows if row.get("entity_type") == "ap"):
            ip = r.get("ip") or ""
            name = r.get("name") or ip
            ap_id = r.get("canonical_id") or norm_mac(r.get("mac")) or self._stable_ap_name(name) or ip or name
            if not ap_id:
                continue
            aliases = r.get("aliases") or ([name] if name else [])
            addresses = r.get("addresses") or ([ip] if ip else [])
            macs = r.get("macs") or ([norm_mac(r.get("mac"))] if norm_mac(r.get("mac")) else [])
            common_attrs = {
                "canonical_id": ap_id,
                "ap_ip": ip,
                "ap_name": name,
                "ap_mac": r.get("mac"),
                "aliases": aliases,
                "addresses": addresses,
                "status": r.get("status"),
                "identity_confidence": r.get("identity_confidence"),
            }
            for address in addresses:
                if address:
                    add({"rel_key":f"identity_ip|ap|{address}","rel_type":"identity_ip","subject_kind":"ip","subject_id":address,"object_kind":"ap","object_id":name,"source":"ap_inventory","confidence":95,"attrs":common_attrs})
            for mac in macs:
                if mac:
                    add({"rel_key":f"identity_mac|ap|{mac}","rel_type":"identity_mac","subject_kind":"mac","subject_id":mac,"object_kind":"ap","object_id":name,"source":"ap_inventory","confidence":99,"attrs":common_attrs})
            for alias in aliases:
                alias_key = self._stable_ap_name(alias)
                if alias_key:
                    add({"rel_key":f"identity_alias|ap|{ap_id}|{alias_key}","rel_type":"identity_alias","subject_kind":"alias","subject_id":alias_key,"object_kind":"ap","object_id":ap_id,"source":"ap_inventory","confidence":int(r.get("identity_confidence") or 80),"attrs":common_attrs})
            sw_id = r.get("switch_ip") or compact_name(r.get("switch_name"))
            if sw_id:
                add({"rel_key":f"ap_attachment|{ap_id}","rel_type":"ap_attachment","subject_kind":"ap","subject_id":ap_id,"object_kind":"switch","object_id":sw_id,"switch_ip":r.get("switch_ip"),"switch_name":r.get("switch_name"),"switch_port":r.get("switch_port"),"source":"controller","confidence":95 if r.get("switch_ip") else 84,"attrs":common_attrs})
                if r.get("switch_port"):
                    add({"rel_key":f"port_occupancy|{sw_id}|{r.get('switch_port')}|{ap_id}","rel_type":"port_occupancy","subject_kind":"switch_port","subject_id":f"{sw_id}:{r.get('switch_port')}","object_kind":"ap","object_id":ap_id,"switch_ip":r.get("switch_ip"),"switch_name":r.get("switch_name"),"switch_port":r.get("switch_port"),"source":"controller","confidence":92,"attrs":common_attrs})
        for row in con.execute("SELECT * FROM neighbors"):
            r = dict(row); local = r.get("local_ip") or compact_name(r.get("local_name")); remote = r.get("remote_ip") or r.get("remote_name") or "unknown"
            if not local: continue
            add({"rel_key":f"neighbor_link|{local}|{r.get('local_port')}|{remote}|{r.get('remote_port')}","rel_type":"neighbor_link","subject_kind":"switch","subject_id":local,"object_kind":"neighbor","object_id":remote,"switch_ip":r.get("local_ip"),"switch_name":r.get("local_name"),"switch_port":r.get("local_port"),"source":"topology","confidence":88,"attrs":{"remote_name":r.get("remote_name"),"remote_port":r.get("remote_port"),"remote_ip":r.get("remote_ip")}})
            if r.get("local_port"): add({"rel_key":f"port_occupancy|{local}|{r.get('local_port')}|{remote}","rel_type":"port_occupancy","subject_kind":"switch_port","subject_id":f"{local}:{r.get('local_port')}","object_kind":"neighbor","object_id":remote,"switch_ip":r.get("local_ip"),"switch_name":r.get("local_name"),"switch_port":r.get("local_port"),"source":"topology","confidence":82,"attrs":{"remote_name":r.get("remote_name"),"remote_port":r.get("remote_port"),"remote_ip":r.get("remote_ip")}})
        for rel in self._continuity_candidate_rels(con, canonical_rows):
            add(rel)
        return desired

    def _rel_json(self, rel: Dict[str, Any]) -> str:
        payload = {k: rel.get(k) for k in ["rel_type","subject_kind","subject_id","object_kind","object_id","switch_ip","switch_name","switch_port","source","confidence","status"]}
        with contextlib.suppress(Exception): payload["attrs"] = json.loads(rel.get("attrs_json") or "{}")
        return json.dumps(payload, sort_keys=True, separators=(",",":"))

    def _rel_tuple(self, rel: Dict[str, Any], first_seen: int, last_seen: int, updated_at: int) -> Tuple[Any, ...]:
        return (rel.get("rel_key"),rel.get("rel_type"),rel.get("subject_kind"),rel.get("subject_id"),rel.get("object_kind"),rel.get("object_id"),rel.get("switch_ip"),rel.get("switch_name"),rel.get("switch_port"),rel.get("source"),int(rel.get("confidence") or 0),rel.get("status"),first_seen,last_seen,updated_at,rel.get("attrs_json"))

    def _insert_rel_event(self, con: sqlite3.Connection, ts: int, event_type: str, rel: Dict[str, Any], prev: Optional[str], curr: Optional[str], detail: str) -> None:
        con.execute("INSERT INTO relationship_events(created_at,event_type,rel_key,rel_type,subject_kind,subject_id,object_kind,object_id,previous_json,current_json,source,confidence,detail) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", (ts,event_type,rel.get("rel_key"),rel.get("rel_type"),rel.get("subject_kind"),rel.get("subject_id"),rel.get("object_kind"),rel.get("object_id"),prev,curr,rel.get("source"),int(rel.get("confidence") or 0),detail))

    def _sync_relationships(self, con: sqlite3.Connection, ts: int, inventory_rows: Optional[Sequence[Dict[str, Any]]] = None) -> None:
        desired = self._relationship_desired(con, inventory_rows); existing = {r["rel_key"]: dict(r) for r in con.execute("SELECT * FROM relationships_current")}; managed = {"identity_ip","identity_mac","identity_alias","device_alias","manual_identity_merge","ap_attachment","neighbor_link","port_occupancy","identity_swap_candidate"}
        for key, rel in desired.items():
            ex = existing.get(key); curr = self._rel_json(rel)
            if not ex:
                con.execute("INSERT INTO relationships_current(rel_key,rel_type,subject_kind,subject_id,object_kind,object_id,switch_ip,switch_name,switch_port,source,confidence,status,first_seen,last_seen,updated_at,attrs_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", self._rel_tuple(rel, ts, ts, ts)); self._insert_rel_event(con, ts, "first_seen", rel, None, curr, "relationship first seen"); continue
            prev = self._rel_json(ex); changed = any(str(ex.get(f) or "") != str(rel.get(f) or "") for f in ["object_kind","object_id","switch_ip","switch_name","switch_port","source","confidence","status","attrs_json"])
            if changed:
                etype = "reappeared" if ex.get("status") == "disappeared" and rel.get("status") != "disappeared" else "changed"
                con.execute("UPDATE relationships_current SET object_kind=?,object_id=?,switch_ip=?,switch_name=?,switch_port=?,source=?,confidence=?,status=?,last_seen=?,updated_at=?,attrs_json=? WHERE rel_key=?", (rel.get("object_kind"),rel.get("object_id"),rel.get("switch_ip"),rel.get("switch_name"),rel.get("switch_port"),rel.get("source"),int(rel.get("confidence") or 0),rel.get("status"),ts,ts,rel.get("attrs_json"),key)); self._insert_rel_event(con, ts, etype, rel, prev, curr, "relationship changed")
                if rel.get("rel_type") == "ap_attachment":
                    p = json.loads(prev or "{}"); c = json.loads(curr or "{}")
                    if p.get("switch_ip") != c.get("switch_ip") or p.get("switch_port") != c.get("switch_port"):
                        attrs = json.loads(rel.get("attrs_json") or "{}"); con.execute("INSERT INTO ap_move_events(created_at,ap_ip,ap_name,previous_switch_ip,previous_switch_port,current_switch_ip,current_switch_port) VALUES(?,?,?,?,?,?,?)", (ts, attrs.get("ap_ip") or rel.get("subject_id"), attrs.get("ap_name"), p.get("switch_ip"), p.get("switch_port"), c.get("switch_ip"), c.get("switch_port")))
            else:
                con.execute("UPDATE relationships_current SET last_seen=?,updated_at=? WHERE rel_key=?", (ts, ts, key))
        for key, ex in existing.items():
            if key in desired or ex.get("rel_type") not in managed or ex.get("status") == "disappeared": continue
            rel = dict(ex); rel["status"] = "disappeared"; con.execute("UPDATE relationships_current SET status=?,updated_at=? WHERE rel_key=?", ("disappeared", ts, key)); self._insert_rel_event(con, ts, "disappeared", rel, self._rel_json(ex), self._rel_json(rel), "relationship absent from latest canonical state")

    def record_device_bridge_mac(self, device_id: str, mac: Any) -> bool:
        """Fill in a switch MAC from the bridge address it states for itself.

        Only ever fills a blank. An address already in inventory was observed
        through another path and stays authoritative, so spanning tree can add
        identity evidence but never overwrite it.
        """
        clean = norm_mac(mac)
        device_id = str(device_id or "").strip()
        if not clean or not device_id:
            return False
        with self.connect() as con:
            row = con.execute(
                "SELECT ip,mac FROM devices WHERE ip=? OR lower(hostname)=lower(?) LIMIT 1",
                (device_id, device_id),
            ).fetchone()
            if not row or norm_mac(row["mac"]):
                return False
            con.execute("UPDATE devices SET mac=? WHERE ip=?", (clean, row["ip"]))
            return True

    def record_stp_links(self, links: Sequence[Dict[str, Any]], ts: Optional[int] = None) -> Dict[str, int]:
        """Persist spanning-tree derived switch links as first-class relationships.

        These are kept out of the `neighbors` table on purpose. That table is
        the LLDP/CDP record and drives link-added/removed events; mixing in a
        second protocol's view would make those events lie about what changed.
        """
        ts = int(ts or now())
        added = updated = 0
        with self.connect() as con:
            for link in links:
                local = str(link.get("local_id") or "").strip()
                remote = str(link.get("remote_id") or "").strip()
                port = str(link.get("local_port") or "").strip()
                if not local or not remote or local == remote:
                    continue
                rel = {
                    "rel_key": f"stp_link|{local}|{port}|{remote}",
                    "rel_type": "stp_link",
                    "subject_kind": "switch",
                    "subject_id": local,
                    "object_kind": "switch",
                    "object_id": remote,
                    "switch_ip": link.get("local_ip") or "",
                    "switch_name": link.get("local_name") or "",
                    "switch_port": port,
                    "source": "spanning-tree",
                    "confidence": int(link.get("confidence") or 82),
                    "status": "active",
                    "attrs_json": json.dumps({
                        "role": link.get("role") or "",
                        "state": link.get("state") or "",
                        "designated_bridge": link.get("designated_bridge") or "",
                        "remote_name": link.get("remote_name") or "",
                        "remote_ip": link.get("remote_ip") or "",
                        # Spanning tree names the bridge on the far end of the
                        # segment, never which of its ports terminates the link.
                        "remote_port": "",
                        "corroborates_lldp": bool(link.get("corroborates_lldp")),
                    }, sort_keys=True, separators=(",", ":")),
                }
                existing = con.execute("SELECT * FROM relationships_current WHERE rel_key=?", (rel["rel_key"],)).fetchone()
                if not existing:
                    con.execute(
                        "INSERT INTO relationships_current(rel_key,rel_type,subject_kind,subject_id,object_kind,object_id,switch_ip,switch_name,switch_port,source,confidence,status,first_seen,last_seen,updated_at,attrs_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        self._rel_tuple(rel, ts, ts, ts),
                    )
                    self._insert_rel_event(con, ts, "first_seen", rel, None, self._rel_json(rel), "spanning-tree link observed")
                    added += 1
                else:
                    con.execute(
                        "UPDATE relationships_current SET object_id=?,switch_ip=?,switch_name=?,confidence=?,status='active',last_seen=?,updated_at=?,attrs_json=? WHERE rel_key=?",
                        (remote, rel["switch_ip"], rel["switch_name"], rel["confidence"], ts, ts, rel["attrs_json"], rel["rel_key"]),
                    )
                    updated += 1
        return {"added": added, "updated": updated}

    def record_core_lookup(self, target: str, output: str, exit_code: int) -> None:
        ts = now()
        with self.connect() as con:
            con.execute("INSERT INTO core_lookup_cache(created_at,target,exit_code,output) VALUES(?,?,?,?)", (ts,target,exit_code,redact_text(output[-8000:])))
            for kind, values in {"ip": sorted(set(IP_RE.findall(output))), "mac": sorted(set(norm_mac(m) for m in MAC_RE.findall(output) if norm_mac(m)))}.items():
                for value in values:
                    rel = {"rel_key":f"core_lookup|{kind}|{value}","rel_type":"core_lookup","subject_kind":kind,"subject_id":value,"object_kind":"lookup","object_id":target,"source":"core_lookup","confidence":70,"status":"observed","attrs_json":json.dumps({"target":target,"excerpt":output[:600]}, sort_keys=True)}
                    ex = con.execute("SELECT * FROM relationships_current WHERE rel_key=?", (rel["rel_key"],)).fetchone()
                    if not ex:
                        con.execute("INSERT INTO relationships_current(rel_key,rel_type,subject_kind,subject_id,object_kind,object_id,switch_ip,switch_name,switch_port,source,confidence,status,first_seen,last_seen,updated_at,attrs_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", self._rel_tuple(rel, ts, ts, ts)); self._insert_rel_event(con, ts, "first_seen", rel, None, self._rel_json(rel), "core lookup observation")
                    else:
                        con.execute("UPDATE relationships_current SET last_seen=?,updated_at=?,attrs_json=? WHERE rel_key=?", (ts,ts,rel["attrs_json"],rel["rel_key"]))

    def record_probe_result(self, target: str, mode: str, payload: Dict[str, Any]) -> None:
        with self.connect() as con:
            con.execute(
                "INSERT INTO probe_results(target,mode,created_at,packet_loss_pct,min_ms,avg_ms,max_ms,jitter_ms,raw_json) VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    target,
                    mode,
                    int(payload.get("observed_at") or now()),
                    payload.get("packet_loss_pct"),
                    payload.get("min_ms"),
                    payload.get("avg_ms"),
                    payload.get("max_ms"),
                    payload.get("jitter_ms"),
                    json.dumps(payload, sort_keys=True, default=str),
                ),
            )

    def record_speed_result(self, payload: Dict[str, Any]) -> int:
        created_at = int(payload.get("observed_at") or now())
        path = payload.get("path") or {}
        download = payload.get("download_mbps") or {}
        upload = payload.get("upload_mbps") or {}
        latency = payload.get("latency_ms") or {}
        reliability = payload.get("reliability") or {}
        with self.connect() as con:
            cur = con.execute(
                "INSERT INTO speed_tests(created_at,interface,download_mbps,upload_mbps,idle_latency_ms,loaded_down_ms,loaded_up_ms,packet_loss_pct,reliability,raw_json) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    created_at,
                    path.get("interface") or payload.get("interface"),
                    download.get("sustained") if isinstance(download, dict) else download,
                    upload.get("sustained") if isinstance(upload, dict) else upload,
                    latency.get("idle") if isinstance(latency, dict) else None,
                    latency.get("loaded_download") if isinstance(latency, dict) else None,
                    latency.get("loaded_upload") if isinstance(latency, dict) else None,
                    payload.get("packet_loss_pct"),
                    reliability.get("rating") if isinstance(reliability, dict) else reliability,
                    json.dumps(payload, sort_keys=True, default=str),
                ),
            )
            return int(cur.lastrowid or 0)

    def record_diagnostic_run(
        self,
        kind: str,
        target: str,
        source: str,
        status: str,
        summary: str,
        payload: Dict[str, Any],
    ) -> int:
        created_at = int(payload.get("observed_at") or now())
        with self.connect() as con:
            cur = con.execute(
                "INSERT INTO diagnostic_runs(created_at,kind,target,source,status,summary,raw_json) VALUES(?,?,?,?,?,?,?)",
                (created_at, kind, target, source, status, summary, json.dumps(payload, sort_keys=True, default=str)),
            )
            return int(cur.lastrowid or 0)

    def record_interface_result(self, payload: Dict[str, Any]) -> int:
        current = payload.get("current") or payload
        created_at = int(payload.get("observed_at") or now())
        with self.connect() as con:
            cur = con.execute(
                "INSERT INTO interface_samples(created_at,device_ip,interface_name,in_bps,out_bps,utilization_pct,oper_status,raw_json) VALUES(?,?,?,?,?,?,?,?)",
                (
                    created_at,
                    payload.get("device_ip") or payload.get("target"),
                    payload.get("interface") or current.get("interface"),
                    current.get("input_bps"),
                    current.get("output_bps"),
                    payload.get("utilization_pct"),
                    current.get("oper_status"),
                    json.dumps(payload, sort_keys=True, default=str),
                ),
            )
            return int(cur.lastrowid or 0)

    def record_mac_observation(
        self,
        mac: str,
        switch_ip: str,
        switch_name: str,
        switch_port: str,
        vlan: str = "",
        entry_type: str = "",
        source: str = "mac_table",
    ) -> Dict[str, Any]:
        clean = norm_mac(mac)
        if not clean or not switch_ip or not switch_port:
            return {"ok": False, "error": "valid MAC, switch IP, and switch port are required"}
        dotted = f"{clean[:4]}.{clean[4:8]}.{clean[8:]}"
        ts = now()
        attrs = {
            "mac": dotted,
            "switch_ip": switch_ip,
            "switch_name": switch_name,
            "switch_port": switch_port,
            "vlan": str(vlan or ""),
            "entry_type": str(entry_type or ""),
        }
        rel = {
            "rel_key": f"mac_location|{clean}",
            "rel_type": "mac_location",
            "subject_kind": "mac",
            "subject_id": clean,
            "object_kind": "switch_port",
            "object_id": f"{switch_ip}:{switch_port}",
            "switch_ip": switch_ip,
            "switch_name": switch_name,
            "switch_port": switch_port,
            "source": source,
            "confidence": 92 if str(entry_type or "").upper() in {"DYNAMIC", "LEARNED"} else 82,
            "status": "observed",
            "attrs_json": json.dumps(attrs, sort_keys=True),
        }
        event_type = "observed"
        with self.connect() as con:
            existing_row = con.execute("SELECT * FROM relationships_current WHERE rel_key=?", (rel["rel_key"],)).fetchone()
            if not existing_row:
                con.execute(
                    "INSERT INTO relationships_current(rel_key,rel_type,subject_kind,subject_id,object_kind,object_id,switch_ip,switch_name,switch_port,source,confidence,status,first_seen,last_seen,updated_at,attrs_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    self._rel_tuple(rel, ts, ts, ts),
                )
                self._insert_rel_event(con, ts, "first_seen", rel, None, self._rel_json(rel), "MAC learned in switch forwarding table")
                event_type = "first_seen"
            else:
                existing = dict(existing_row)
                moved = existing.get("object_id") != rel["object_id"] or existing.get("switch_port") != switch_port
                changed = moved or existing.get("attrs_json") != rel["attrs_json"]
                con.execute(
                    "UPDATE relationships_current SET object_kind=?,object_id=?,switch_ip=?,switch_name=?,switch_port=?,source=?,confidence=?,status=?,last_seen=?,updated_at=?,attrs_json=? WHERE rel_key=?",
                    (
                        rel["object_kind"], rel["object_id"], switch_ip, switch_name, switch_port, source,
                        rel["confidence"], rel["status"], ts, ts, rel["attrs_json"], rel["rel_key"],
                    ),
                )
                if changed:
                    event_type = "moved" if moved else "changed"
                    self._insert_rel_event(
                        con,
                        ts,
                        event_type,
                        rel,
                        self._rel_json(existing),
                        self._rel_json(rel),
                        "MAC forwarding-table location changed" if moved else "MAC forwarding-table evidence changed",
                    )
        return {"ok": True, "event_type": event_type, "observed_at": ts, **attrs}

@dataclass
class CommandSpec:
    id: str
    label: str
    command: List[str]
    description: str
    read_only: bool = True
    writes_local: bool = False
    args: List[str] = field(default_factory=list)
    domain: str = "general"
    risk_level: str = "safe"
    preview_supported: bool = True
    run_supported: bool = True
    output_type: str = "log"
    arg_schema: List[Dict[str, Any]] = field(default_factory=list)
    state_effects: List[str] = field(default_factory=list)
    safety_class: str = "read-only"
    timeout_seconds: int = 0
    cancellable: bool = True
    examples: List[str] = field(default_factory=list)

    def inferred_arg_schema(self) -> List[Dict[str, Any]]:
        if self.arg_schema:
            return self.arg_schema
        schemas: List[Dict[str, Any]] = []
        for arg in self.args:
            kind = "text"
            required = arg not in {
                "count", "runs", "profile", "chart", "once", "depth", "max_nodes", "refresh_neighbors", "core", "scope",
                "ca_file", "port", "seconds", "parallel", "direction", "bind", "sample_seconds", "expected_speed", "wait", "online",
                "source", "destination", "mode", "explain", "group",
            }
            label = arg.replace("_", " ").replace("-", " ").title()
            item: Dict[str, Any] = {"name": arg, "label": label, "type": kind, "required": required}
            if arg in {"count", "runs", "depth", "max_nodes", "port", "seconds", "parallel", "sample_seconds", "expected_speed", "wait"}:
                item["type"] = "number"
                item["min"] = 0 if arg == "sample_seconds" else 1
                if arg == "depth": item["max"] = 16
                if arg == "max_nodes": item["max"] = 256
                if arg == "port": item["max"] = 65535
                if arg in {"seconds", "sample_seconds"}: item["max"] = 300 if arg == "seconds" else 60
                if arg == "parallel": item["max"] = 16
            elif arg == "chart":
                item["type"] = "select"
                item["options"] = ["classic", "histogram"]
            elif arg == "profile":
                item["type"] = "select"
                item["options"] = ["balanced", "quick", "thorough"]
            elif arg == "vlan_mode":
                item["type"] = "select"
                item["options"] = ["access", "trunk"]
            elif arg == "vlan":
                item["type"] = "number"
                item["min"] = 1
                item["max"] = 4094
            elif arg == "direction":
                item["type"] = "select"
                item["options"] = ["both", "upload", "download"]
            elif arg == "mode":
                item["type"] = "select"
                item["options"] = ["hybrid", "cached", "live"]
            elif arg in {"once", "refresh_neighbors", "online", "explain"}:
                item["type"] = "boolean"
            elif arg in {"target", "device"}:
                item["placeholder"] = "hostname, IP, or site token"
            elif arg in {"command", "commands"}:
                item["placeholder"] = "show version" if arg == "command" else "configuration commands"
            schemas.append(item)
        return schemas

    def effective_state_effects(self) -> List[str]:
        if self.state_effects:
            return self.state_effects
        effects: List[str] = []
        if self.writes_local:
            effects.append("local-state")
        if self.domain in {"inventory", "ap", "topology", "memory", "health", "lookup", "diagnose", "diagnostics", "backup", "workflow"} and self.writes_local:
            effects.append("sqlite")
        if self.risk_level == "config":
            effects.append("device-config")
        return effects

    def effective_safety_class(self) -> str:
        if self.risk_level == "config" or not self.read_only:
            return "config-write"
        if self.safety_class and self.safety_class != "read-only":
            return self.safety_class
        if self.writes_local:
            return "network-read/local-write"
        if self.output_type == "terminal":
            return "interactive-read"
        return self.safety_class or "read-only"

    def as_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "command": shlex.join(self.command),
            "description": self.description,
            "read_only": self.read_only,
            "writes_local": self.writes_local,
            "args": self.args,
            "domain": self.domain,
            "risk_level": self.risk_level,
            "preview_supported": self.preview_supported,
            "run_supported": self.run_supported,
            "output_type": self.output_type,
            "arg_schema": self.inferred_arg_schema(),
            "state_effects": self.effective_state_effects(),
            "safety_class": self.effective_safety_class(),
            "timeout_seconds": self.timeout_seconds,
            "cancellable": self.cancellable,
            "examples": self.examples,
        }


#: How wide an index line may be before it stops being a list and becomes
#: prose. A reader scanning twenty actions wants to find one, not read them.
GIST_WIDTH = 92


def action_gist(doc: Mapping[str, Any]) -> str:
    """One line for the index, from the paragraph on the action's own page.

    An action's `about` is written for `netrune help <noun> <action>`, where a
    paragraph is what a person came for. In a list of twenty actions the same
    paragraph is a wall, and the one action they are looking for is hidden
    inside it. A `gist` is used where one is written; otherwise the first
    sentence stands in, which is where a well-written `about` puts the point.
    """
    gist = str(doc.get("gist") or "").strip()
    if gist:
        return gist
    about = " ".join(str(doc.get("about") or "").split())
    if not about:
        return ""
    # First sentence, without splitting on the full stop inside "e.g." or a
    # version number.
    match = re.search(r"(?<![A-Z0-9])\.(?:\s|$)", about)
    first = about[: match.start() + 1] if match else about
    if len(first) > GIST_WIDTH:
        first = first[:GIST_WIDTH].rsplit(" ", 1)[0] + "..."
    return first


def _take_flag(rest: List[str], name: str) -> Tuple[List[str], Optional[str]]:
    """Pull `--name value` out of an argument list, leaving the rest."""
    if name not in rest:
        return rest, None
    position = rest.index(name)
    if position + 1 >= len(rest):
        return rest[:position], ""
    return rest[:position] + rest[position + 2:], rest[position + 1]


HELP_TOPICS: Dict[str, Dict[str, Any]] = {
    "inventory": {
        "summary": "Switch/router inventory, flat-file migration, details, and bulk activity checks.",
        "usage": "netrune inventory <action> [arguments] [global flags]",
        "actions": {
            "scan": {"usage": "netrune inventory scan [target|CIDR|range]", "about": "Refresh switch/router inventory. Imports refreshed flat cache data into SQLite when the scan completes.", "args": [{"name":"target", "text":"Optional hostname, IP, CIDR, range, or site token to scan."}], "examples": ["netrune inventory scan", "netrune inventory scan 203.0.113.0/24", "netrune inventory scan ZONE10 --dry-run"]},
            "list": {"usage": "netrune inventory list [pattern] [--status ONLINE|OFFLINE] [--site SITE]", "about": "Search devices and APs from canonical SQLite inventory.", "args": [{"name":"pattern", "text":"Optional text matched against IP, hostname, platform, AP name, or switch name."}], "examples": ["netrune inventory list ZONE10", "netrune inventory list --status OFFLINE", "netrune inventory list 192.0.2 --json"]},
            "details": {"usage": "netrune inventory details <target>", "about": "Show deeper information for one device or AP. Plain output delegates to the legacy details view; JSON uses canonical state.", "args": [{"name":"target", "text":"Hostname, AP name, IP, or partial match."}], "examples": ["netrune inventory details sq34", "netrune inventory details 198.51.100.92 --json"]},
            "activity": {"usage": "netrune inventory activity --file devices.txt", "about": "Ping a list of switches/APs and print offline records first, then online records.", "args": [{"name":"--file", "text":"Text file with one hostname or IP per line. Blank lines and # comments are ignored."}, {"name":"targets", "text":"You can also provide targets directly after the action."}], "examples": ["netrune inventory activity --file ./devices.txt", "netrune inventory activity sq34 sq35 ap-sq10"]},
            "forget": {"usage": "netrune inventory forget <target> [--with-names] [--confirm]", "about": "Drop a device's inventory and derived state so the next scan adopts it afresh. A name recorded wrong is inherited by every later sighting; this is the way out. Backups, audit events, and traffic history are untouched. --with-names also drops the recorded naming history so an old name is not re-derived.", "args": [{"name":"target","text":"Device to forget. Every address it has answered on is forgotten together."}], "examples": ["netrune inventory forget SITE-A-SW01", "netrune inventory forget SITE-A-SW01 --with-names --confirm"]},
            "merge": {"usage": "netrune inventory merge <old-device> <current-device> --reason TEXT [--dry-run|--confirm]", "about": "Retire an old device into the current device's chronological identity. The old record leaves active inventory but remains searchable historical memory.", "args": [{"name":"old-device", "text":"Exact hostname or IP of the active record to retire."}, {"name":"current-device", "text":"Exact hostname or IP of the active record that remains current."}, {"name":"--reason", "text":"Required one-line audit reason."}], "examples": ["netrune inventory merge SITE-A-OLD-SW01 SITE-A-ACCESS-01 --reason 'approved hardware replacement' --dry-run", "netrune inventory merge 192.0.2.11 192.0.2.21 --reason 'verified replacement' --confirm"]},
            "merges": {"usage": "netrune inventory merges [--all]", "about": "List active manual identity merges newest first; --all includes revoked merges.", "examples": ["netrune inventory merges", "netrune inventory merges --all --json"]},
            "unmerge": {"usage": "netrune inventory unmerge <merge-id> --reason TEXT --confirm", "about": "Revoke a manual merge and restore its source snapshot when the old IP has not been reassigned.", "args": [{"name":"merge-id", "text":"Identifier from inventory merges."}, {"name":"--reason", "text":"Required one-line revocation reason."}], "examples": ["netrune inventory unmerge mrg-example --reason 'association was incorrect' --confirm"]},
            "import-flat": {"usage": "netrune inventory import-flat", "about": "Import devices.db, ap_devices.db, and neighbor.db into SQLite.", "examples": ["netrune inventory import-flat", "netrune inventory import-flat --json"]},
            "export-flat": {"usage": "netrune inventory export-flat", "about": "Export SQLite inventory back to the legacy pipe-delimited files.", "examples": ["netrune inventory export-flat"]},
        },
    },
    "ap": {
        "summary": "Wireless AP inventory, AP-on-switch lookup, AP move history, unjoined WLC records, and AP timelines.",
        "usage": "netrune ap <action> [arguments] [global flags]",
        "actions": {
            "scan": {"usage": "netrune ap scan", "about": "Refresh AP inventory from wireless/controller sources.", "examples": ["netrune ap scan"]},
            "list": {"usage": "netrune ap list [pattern] [--status ONLINE|OFFLINE]", "about": "Search AP inventory.", "args": [{"name":"pattern", "text":"Optional AP name, IP, platform, switch, or port pattern."}], "examples": ["netrune ap list ZONE10", "netrune ap list --status OFFLINE"]},
            "unjoined": {"usage": "netrune ap unjoined [pattern] [--limit N]", "about": "Show Cisco WLC APs seen in join statistics but not currently joined.", "args": [{"name":"pattern", "text":"Optional AP name/MAC/site filter."}], "examples": ["netrune ap unjoined", "netrune ap unjoined SITE-A --json"]},
            "show": {"usage": "netrune ap show [pattern]", "about": "Alias of ap list for quick lookup.", "examples": ["netrune ap show SITEA"]},
            "on-switch": {"usage": "netrune ap on-switch <switch>", "about": "Show APs currently attached to a switch, using controller and memory state.", "args": [{"name":"switch", "text":"Switch hostname, short name, site token, or IP."}], "examples": ["netrune ap on-switch ZONE10", "netrune ap on-switch SITEAZONE34SW01"]},
            "moves": {"usage": "netrune ap moves [--limit N]", "about": "Show recorded AP switch/port movement events.", "examples": ["netrune ap moves", "netrune ap moves --limit 50"]},
            "timeline": {"usage": "netrune ap timeline [target]", "about": "Show AP attachment timeline events.", "args": [{"name":"target", "text":"Optional AP name/IP/MAC or relationship search term."}], "examples": ["netrune ap timeline", "netrune ap timeline AP-ZONE10-01"]},
            "merge": {"usage": "netrune ap merge <old-ap> <current-ap> --reason TEXT [--dry-run|--confirm]", "about": "Retire an old AP into the current AP's chronological identity. The old record leaves active inventory but remains searchable historical memory.", "args": [{"name":"old-ap", "text":"Exact name or IP of the active record to retire."}, {"name":"current-ap", "text":"Exact name or IP of the active record that remains current."}, {"name":"--reason", "text":"Required one-line audit reason."}], "examples": ["netrune ap merge SITE-A-AP12 NEWCISCO-AP-01 --reason 'vendor replacement' --dry-run", "netrune ap merge SITE-A-AP12 NEWCISCO-AP-01 --reason 'verified replacement' --confirm"]},
            "merges": {"usage": "netrune ap merges [--all]", "about": "List active manual AP merges newest first; --all includes revoked merges.", "examples": ["netrune ap merges", "netrune ap merges --all --json"]},
            "unmerge": {"usage": "netrune ap unmerge <merge-id> --reason TEXT --confirm", "about": "Revoke a manual AP merge and restore its source snapshot when the old IP has not been reassigned.", "args": [{"name":"merge-id", "text":"Identifier from ap merges."}, {"name":"--reason", "text":"Required one-line revocation reason."}], "examples": ["netrune ap unmerge mrg-example --reason 'association was incorrect' --confirm"]},
        },
    },
    "topology": {
        "summary": "LLDP/CDP neighbor scans, topology display, topology changes, and link timelines.",
        "usage": "netrune topology <action> [arguments] [global flags]",
        "actions": {
            "scan": {"usage": "netrune topology scan", "about": "Refresh LLDP/CDP neighbor data.", "examples": ["netrune topology scan"]},
            "stp": {"usage": "netrune topology stp [target] [--jobs N] [--failed] [--dry-run]", "about": "Read spanning tree from switches and derive switch links from designated-bridge addresses. Finds links where LLDP is not enabled, including redundant links spanning tree is blocking, and records each switch's own bridge MAC as identity evidence.", "args": [{"name":"target", "text":"Optional switch hostname or IP; all switches by default."}], "options": [{"name":"--jobs N", "text":"Switches to read at a time, 1 to 32 (default 8)."}, {"name":"--failed", "text":"Re-read only the switches whose last spanning-tree read did not parse."}], "examples": ["netrune topology stp", "netrune topology stp --failed", "netrune topology stp --jobs 16"]},
            "links": {"usage": "netrune topology links [--limit N]", "about": "List spanning-tree derived switch links with their source confidence.", "examples": ["netrune topology links --json"]},
            "show": {"usage": "netrune topology show [target]", "about": "Show topology links. With a target in plain mode, opens the legacy topology view for that target.", "args": [{"name":"target", "text":"Optional switch/site/IP."}], "examples": ["netrune topology show", "netrune topology show ZONE10"]},
            "changes": {"usage": "netrune topology changes [--limit N]", "about": "Show topology change events.", "examples": ["netrune topology changes"]},
            "timeline": {"usage": "netrune topology timeline [target]", "about": "Show neighbor relationship timeline.", "examples": ["netrune topology timeline ZONE10"]},
        },
    },
    "memory": {
        "summary": "Relationship memory: AP attachments, IP/MAC ownership, switch ports, topology, and source confidence.",
        "usage": "netrune memory <action> [arguments] [global flags]",
        "actions": {
            "refresh": {"usage": "netrune memory refresh", "about": "Recompute relationship memory from inventory, APs, topology, and lookup observations.", "examples": ["netrune memory refresh"]},
            "switch": {"usage": "netrune memory switch <switch>", "about": "Show APs, neighbors, current relationships, and timeline for a switch/site.", "args": [{"name":"switch", "text":"Switch hostname, short name, IP, or site token."}], "examples": ["netrune memory switch ZONE10", "netrune memory switch SITEAZONE34SW01 --json"]},
            "device": {"usage": "netrune memory device <name|ip>", "about": "Show relationships involving a device or AP.", "examples": ["netrune memory device 198.51.100.92"]},
            "ip": {"usage": "netrune memory ip <ip>", "about": "Show historical ownership and relationship events for an IP address.", "examples": ["netrune memory ip 198.51.100.92"]},
            "mac": {"usage": "netrune memory mac <mac>", "about": "Show identity and movement history for a MAC address.", "examples": ["netrune memory mac 0200.0000.0025"]},
            "port": {"usage": "netrune memory port <switch> <port>", "about": "Show current and historical occupancy for one switch port.", "args": [{"name":"switch", "text":"Switch name/IP/site token."}, {"name":"port", "text":"Interface name, for example Gi1/0/7."}], "examples": ["netrune memory port ZONE34 Gi1/0/7"]},
            "timeline": {"usage": "netrune memory timeline [target]", "about": "Search the full relationship event timeline.", "examples": ["netrune memory timeline 192.0.2", "netrune memory timeline --limit 200"]},
            "explain": {"usage": "netrune memory explain [target]", "about": "Summarize relationship sources and average confidence.", "examples": ["netrune memory explain ZONE10"]},
            "export": {"usage": "netrune memory export [--json]", "about": "Export current relationships.", "examples": ["netrune memory export --json"]},
            "prune": {"usage": "netrune memory prune", "about": "Reserved for future pruning. Relationship history is retained forever by default.", "examples": ["netrune memory prune"]},
        },
    },
    "health": {
        "summary": "Reachability, stale state, offline lists, attention queue, and health timeline.",
        "usage": "netrune health <action> [arguments] [global flags]",
        "actions": {
            "check": {"usage": "netrune health check [target]", "about": "Run fast reachability checks and refresh health state.", "examples": ["netrune health check", "netrune health check ZONE10"]},
            "status": {"usage": "netrune health status [--limit N]", "about": "Show current health state for devices and APs.", "examples": ["netrune health status"]},
            "offline": {"usage": "netrune health offline [--limit N]", "about": "List current offline devices/APs.", "examples": ["netrune health offline"]},
            "attention": {"usage": "netrune health attention [--limit N]", "about": "Show items needing operator review: offline, flapping, topology changes, AP moves, backup issues.", "examples": ["netrune health attention"]},
            "timeline": {"usage": "netrune health timeline [--limit N]", "about": "Show health events over time.", "examples": ["netrune health timeline"]},
        },
    },
    "backup": {
        "summary": "Online-only, changed-only config backups plus backup history and diffs.",
        "usage": "netrune backup <action> [arguments] [global flags]",
        "actions": {
            "run": {"usage": "netrune backup run <target|--all> [--redact-secrets] [--skip-recent] [--force]", "about": "Back up online devices only, skip unchanged configs, and print a per-device report. --all (or a literal all/*/any target) backs up every online device and, like --skip-recent on any target, skips devices that already have a saved/unchanged backup from today without connecting to them; --force runs every matched device regardless.", "args": [{"name":"target", "text":"Hostname, IP, site token, or pattern supported by netrune-control -- or --all for every device."}], "examples": ["netrune backup run ZONE34", "netrune backup run 198.51.100.92 --redact-secrets", "netrune backup run --all", "netrune backup run --all --force"]},
            "history": {"usage": "netrune backup history <target>", "about": "Show backup history for one target.", "examples": ["netrune backup history ZONE34"]},
            "diff": {"usage": "netrune backup diff <target>", "about": "Diff the latest backup against the previous backup.", "examples": ["netrune backup diff ZONE34"]},
            "verify": {"usage": "netrune backup verify [--limit N]", "about": "Show backup metadata recorded in SQLite.", "examples": ["netrune backup verify"]},
        },
    },
    "device": {
        "summary": "SSH, read-only show commands, config previews/confirmed changes, and inventory enrichment.",
        "usage": "netrune device <action> [arguments] [global flags]",
        "actions": {
            "ssh": {"usage": "netrune device ssh [-l|--legacy] <target>", "about": "Open an interactive SSH session using netrune-connect. If SSH negotiation reports legacy algorithms, retry with -l/--legacy.", "examples": ["netrune device ssh ZONE34", "netrune device ssh -l ZONE34", "netrune device ssh 198.51.100.92"]},
            "show": {"usage": "netrune device show <target> <show-command>", "about": "Run a read-only show command through netrune-control.", "args": [{"name":"target", "text":"Hostname, IP, or inventory match."}, {"name":"show-command", "text":"Command text after the target, for example show interface status."}], "examples": ["netrune device show ZONE34 show version", "netrune device show 198.51.100.92 show interface status"]},
            "config": {"usage": "netrune device config <target[,target...]> <commands...> --dry-run|--confirm | netrune device config --file devices.txt [--target T] <commands...> [--commands-file F] [--skip-offline] [--skip-unverified] [--cisco] [--aruba] [--ruckus] --dry-run|--confirm", "about": "Run configuration commands on one or many devices (comma list, --target, --file) through the guarded backup/apply/verify lifecycle. Requires --dry-run or --confirm.", "args": [{"name":"--file", "text":"Text file with one hostname or IP per line. Blank lines and # comments are ignored."}, {"name":"--target", "text":"Add a device (or comma list); repeatable, combinable with --file."}, {"name":"--commands-file", "text":"Read the config commands from a file, one per line, instead of the command line."}, {"name":"--skip-offline", "text":"Ping every device before starting and skip (and report) the ones that don't reply."}, {"name":"--skip-unverified", "text":"Skip targets that don't resolve or fail the write gate instead of refusing the whole batch."}, {"name":"--cisco/--aruba/--ruckus", "text":"Only let devices of that vendor through (combine for several); the rest are listed as filtered, not run."}], "examples": ["netrune device config ZONE34 'interface Gi1/0/7' 'description AP' --dry-run", "netrune device config SW1,SW2,SW3 'ntp server 198.51.100.5' --skip-offline --dry-run", "netrune device config --file ./devices.txt --commands-file ./snmp.txt --skip-offline --confirm", "netrune device config --file ./site-a.txt --cisco 'ip ssh version 2' --dry-run"]},
            "inventory": {"usage": "netrune device inventory [target|--view]", "about": "View or enrich device inventory through netrune-control.", "examples": ["netrune device inventory --view", "netrune device inventory ZONE34"]},
            "support": {"usage": "netrune device support [target]", "about": "Show registered Cisco, Aruba, and Ruckus driver capabilities, or classify one inventory target.", "examples": ["netrune device support", "netrune device support ZONE34 --json"]},
            "identity": {"usage": "netrune device identity <first> <second>", "about": "Explain name, IP, MAC, serial, model, and attachment evidence used to assess two switch records.", "examples": ["netrune device identity SITE-A-PLNT-PLN-SW01 SITEAPLNTPLANSW01"]},
            "trust-status": {"usage": "netrune device trust status [target]", "about": "Inspect the private managed known-hosts store without touching the network.", "examples": ["netrune device trust status", "netrune device trust status ZONE34 --json"]},
            "trust-scan": {"usage": "netrune device trust scan <target>", "about": "Retrieve current SSH host keys and print SHA-256 fingerprints without trusting them.", "examples": ["netrune device trust scan ZONE34"]},
            "trust-enroll": {"usage": "netrune device trust enroll <target> --fingerprint SHA256:... --confirm", "about": "Store only host keys whose out-of-band verified fingerprints match the scan.", "examples": ["netrune device trust enroll ZONE34 --fingerprint SHA256:abc... --confirm"]},
            "trust-forget": {"usage": "netrune device trust forget <target> --confirm", "about": "Remove a target from the managed trust store after explicit confirmation.", "examples": ["netrune device trust forget ZONE34 --confirm"]},
        },
    },
    "vault": {
        "summary": "Local SSH-password vault lifecycle with terminal sudo authentication and no graphical pinentry.",
        "usage": "netrune vault <status|set|migrate|unlock|lock>",
        "actions": {
            "status": {"usage": "netrune vault status [--json]", "about": "Show vault security plus password-recorded time, expected three-day expiry window, session state, and current lifecycle state without prompting.", "examples": ["netrune vault status", "netrune vault status --json"]},
            "set": {"usage": "netrune vault set [--legacy-vault]", "about": "Save a new SSH password. The default sudo-gated mode asks for terminal sudo authentication and never stores the sudo password.", "options": [{"name":"--legacy-vault", "text":"Use a terminal-passphrase GPG vault when sudo-backed storage is unavailable."}], "examples": ["netrune vault set"]},
            "migrate": {"usage": "netrune vault migrate", "about": "Decrypt the existing legacy vault once in the terminal, then atomically replace it with the sudo-gated GPG format.", "examples": ["netrune vault migrate"]},
            "unlock": {"usage": "netrune vault unlock [--ttl MINUTES]", "about": "Authenticate once and hold the vault open for a bounded window, so a batch of commands does not re-prompt per process. The key is held in a memory-backed file readable only by you and is erased when the window ends. Without --ttl the configured vault_session_ttl_minutes is used (default 15, maximum 480).", "options": [{"name":"--ttl MINUTES", "text":"How long to hold the vault open, 1 to 480 minutes."}], "examples": ["netrune vault unlock", "netrune vault unlock --ttl 60"]},
            "lock": {"usage": "netrune vault lock", "about": "End an open vault session immediately and erase the cached key. The next command authenticates again.", "examples": ["netrune vault lock"]},
        },
    },
    "vlan": {
        "summary": "Read-only VLAN lookup/propagation plus guarded VLAN changes.",
        "usage": "netrune vlan <action> [arguments] [global flags]",
        "actions": {
            "locate": {"usage": "netrune vlan locate <target[,target...]> <vlan[,vlan|range...]> [--depth N] [--max-nodes N]", "about": "Find one or many VLANs from one or many roots. Depth zero inspects roots; positive depth traverses LLDP/CDP-confirmed switch links breadth-first.", "examples": ["netrune vlan locate ZONE34 120", "netrune vlan locate SW1,SW2 10,20-22 --depth 2", "netrune vlan locate --target SW1 --target SW2 --vlan 10,20 --depth 5"]},
            "propagation": {"usage": "netrune vlan propagation <target[,target...]> <vlan[,vlan|range...]> [--depth N] [--max-nodes N]", "about": "Build a root-by-VLAN propagation matrix, traversing every reachable switch layer within the depth/node bounds.", "examples": ["netrune vlan propagation ZONE34 120", "netrune vlan propagation site-a-core 131 --depth 5", "netrune vlan propagation SW1,SW2 10,20 --depth 3"]},
            "set": {"usage": "netrune vlan set <target> <interface> [--access N|--trunk LIST] --dry-run|--confirm | netrune vlan set --file changes.txt [--skip-unverified] --dry-run|--confirm", "about": "Guarded VLAN change wrapper. Requires --dry-run or --confirm. --file runs a batch, one independent '<target> <interface> --access|--trunk <vlan> [--native N] [--replace]' change per line; --skip-unverified excludes lines that don't resolve or aren't approved instead of aborting the whole batch.", "examples": ["netrune vlan set ZONE34 Gi1/0/7 --access 120 --dry-run", "netrune vlan set --file changes.txt --confirm"]},
        },
    },
    "lookup": {
        "summary": "Core and MAC lookups. Results are cached into relationship memory.",
        "usage": "netrune lookup <action> [arguments] [global flags]",
        "actions": {
            "core": {"usage": "netrune lookup core <ip|mac>", "about": "Run core lookup and cache observations into memory.", "examples": ["netrune lookup core 198.51.100.92", "netrune lookup core 0200.0000.0025"]},
            "mac": {"usage": "netrune lookup mac <inspect|locate|profile|history|vendor|online|registry> ...", "about": "Inspect local evidence, search forwarding tables, profile an edge port, show movement history, or query cached authoritative IEEE MA-L/MA-M/MA-S assignments.", "examples": ["netrune lookup mac online 00:00:5e:00:53:01", "netrune lookup mac inspect 0200.0000.0025", "netrune lookup mac locate 0200.0000.0025 ZONE34", "netrune lookup mac registry refresh"]},
            "mac-online": {"usage": "netrune lookup mac online <mac> [--refresh|--offline]", "about": "Resolve the longest matching IEEE MA-L, MA-M, or MA-S assignment with organization details, cache time, and source provenance.", "examples": ["netrune lookup mac online 00:00:5e:00:53:01", "netrune lookup mac online 00:00:5e:00:53:01 --refresh"]},
            "mac-registry": {"usage": "netrune lookup mac registry <status|refresh>", "about": "Inspect or refresh the private cache of all three IEEE public MAC assignment registries.", "examples": ["netrune lookup mac registry status", "netrune lookup mac registry refresh"]},
            "mac-all": {"usage": "netrune lookup mac all <mac> [--jobs N]", "about": "Search every online switch's forwarding table for a MAC and report where it is attached. Each switch along the path lists the MAC, so hits on known uplink ports are shown separately as transit and the remaining hit is the access port the device is on. Run 'netrune topology stp' first so uplinks are known, and ping the address first so the switches have learned it.", "options": [{"name":"--jobs N", "text":"Switches to query at a time, 1 to 32 (default 8)."}], "examples": ["netrune lookup mac all 0200.0000.0025", "netrune lookup mac all f814.ddc7.e4a0 --jobs 16"]},
            "mac-inspect": {"usage": "netrune lookup mac inspect <mac>", "about": "Correlate cached identity, L2 location, IP, vendor, inventory, and movement evidence without touching devices.", "examples": ["netrune lookup mac inspect 0200.0000.0025"]},
            "mac-locate": {"usage": "netrune lookup mac locate <mac> [--site SITE] [--limit N]", "about": "Search switch forwarding tables directly, independent of whether the endpoint has an IP address.", "examples": ["netrune lookup mac locate 0200.0000.0025", "netrune lookup mac locate 0200.0000.0025 --site ZONE34"]},
            "mac-profile": {"usage": "netrune lookup mac profile <mac> [--site SITE]", "about": "Locate a MAC, then gather best-effort interface, LLDP/CDP, PoE, device-tracking, OUI, and core ARP evidence at likely edge ports.", "examples": ["netrune lookup mac profile 0200.0000.0025"]},
            "mac-history": {"usage": "netrune lookup mac history <mac>", "about": "Show newest-first MAC location and identity events.", "examples": ["netrune lookup mac history 0200.0000.0025"]},
            "mac-vendor": {"usage": "netrune lookup mac vendor <mac>", "about": "Resolve the locally installed OUI prefix. This identifies an organization, not an exact model.", "examples": ["netrune lookup mac vendor 00:00:5e:00:53:01"]},
        },
    },
    "diagnose": {
        "summary": "Local/core latency, verified Internet speed, controlled throughput, port health, and guarded copper cable diagnostics.",
        "usage": "netrune diagnose <action> [arguments] [global flags]",
        "actions": {
            "latency": {"usage": "netrune diagnose latency <target> [--count N]", "about": "Run a continuous latency probe by default. Add --count N for a finite run; JSON output is finite and defaults to 5 samples.", "examples": ["netrune diagnose latency 1.1.1.1", "netrune diagnose latency ZONE34 --count 10"]},
            "core-ping": {"usage": "netrune diagnose core-ping <target> [--core SWITCH] [--count N]", "about": "Point-of-truth ICMP probe issued by the configured core switch, with parsed loss and min/average/max latency stored in diagnostics history.", "examples": ["netrune diagnose core-ping 192.0.2.50 --count 5", "netrune diagnose core-ping ZONE34 --core CORE01"]},
            "speed": {"usage": "netrune diagnose speed [--profile quick|balanced|thorough] [--runs N] [--ca-file PEM]", "about": "Measure this Netrune host's routed Internet path with verified TLS, loaded latency, jitter, loss, and profile-specific confidence/runtime tradeoffs.", "examples": ["netrune diagnose speed", "netrune diagnose speed --profile quick", "netrune diagnose speed --profile thorough --runs 5"]},
            "throughput": {"usage": "netrune diagnose throughput <iperf3-server> [--direction both|upload|download] [--port 5201] [--seconds 10] [--parallel 1]", "about": "Measure TCP receiver goodput between this client and a controlled iperf3 server. Run it on the endpoint attached to a switch port for endpoint-to-core results.", "examples": ["netrune diagnose throughput 203.0.113.20", "netrune diagnose throughput core --direction both --parallel 2"]},
            "port-health": {"usage": "netrune diagnose port-health <device> on <interface> [--sample-seconds 5] [--expected-speed 1000]", "about": "Read link negotiation and switch counters twice, then distinguish cumulative history from errors increasing during the sample.", "examples": ["netrune diagnose port-health ZONE34 on Gi1/0/7", "netrune diagnose port-health 203.0.113.39 on Gi1/0/12 --sample-seconds 10"]},
            "cable": {"usage": "netrune diagnose cable <device> on <interface> [--test --dry-run|--confirm] [--wait N]", "about": "Read the previous copper TDR result by default. Starting a new potentially disruptive TDR requires an explicit preview or confirmation.", "examples": ["netrune diagnose cable ZONE34 on Gi1/0/7", "netrune diagnose cable ZONE34 on Gi1/0/7 --test --dry-run"]},
            "doctor": {"usage": "netrune diagnose doctor [--online]", "about": "Audit local dependencies, route, WSL limitations, secure speed backend, core settings, and optional iperf/cable tooling.", "examples": ["netrune diagnose doctor", "netrune diagnose doctor --online"]},
            "filtering": {"usage": "netrune diagnose filtering [domain]", "about": "Check DNS, 443/tcp, TLS issuer, and filtering/MITM indicators.", "examples": ["netrune diagnose filtering google.com"]},
            "interface": {"usage": "netrune diagnose interface <device> on <interface> [--chart classic|histogram]", "about": "Launch interface monitoring. Histogram mode mirrors the gateprober rate chart style.", "examples": ["netrune diagnose interface ZONE34 on Gi1/0/7", "netrune diagnose interface ZONE34 on Gi1/0/7 --chart histogram"]},
        },
    },
    "workflow": {
        "summary": "Safe multi-step operator workflows.",
        "usage": "netrune workflow <name> [arguments] [global flags]",
        "actions": {
            "morning-check": {"usage": "netrune workflow morning-check", "about": "Import cache, check reachability, refresh LLDP/CDP topology, refresh memory, review topology changes, check filtering, and build the attention queue.", "examples": ["netrune workflow morning-check --dry-run"]},
            "refresh-inventory": {"usage": "netrune workflow refresh-inventory", "about": "Health check, AP scan, topology scan, memory refresh, and attention summary.", "examples": ["netrune workflow refresh-inventory"]},
            "backup-online": {"usage": "netrune workflow backup-online [target]", "about": "Run changed-only backups for online devices.", "examples": ["netrune workflow backup-online ZONE10"]},
            "site-health": {"usage": "netrune workflow site-health <target>", "about": "Latency and filtering checks for a target/site.", "examples": ["netrune workflow site-health google.com"]},
            "ap-audit": {"usage": "netrune workflow ap-audit", "about": "Refresh AP data, recompute memory, show AP moves and attention.", "examples": ["netrune workflow ap-audit"]},
        },
    },
    "commands": {
        "summary": "Canonical command registry used by the CLI, previews, and workflows.",
        "usage": "netrune commands <action> [arguments] [global flags]",
        "actions": {
            "list": {"usage": "netrune commands list", "about": "List registered command IDs and risk metadata.", "examples": ["netrune commands list"]},
            "show": {"usage": "netrune commands show <id>", "about": "Show registry metadata for one command ID.", "examples": ["netrune commands show backup-run --json"]},
            "run": {"usage": "netrune commands run <id> [args] [--preview]", "about": "Run or preview a registry command. Required args depend on the command ID.", "examples": ["netrune commands run backup-run ZONE34 --preview", "netrune commands run diagnose-latency --target 1.1.1.1 --count 10"]},
        },
    },
    "db": {
        "summary": "SQLite lifecycle and flat-file compatibility shortcuts.",
        "usage": "netrune db <action> [arguments] [global flags]",
        "actions": {
            "migrate": {"usage": "netrune db migrate", "about": "Create or update the SQLite schema.", "examples": ["netrune db migrate"]},
            "status": {"usage": "netrune db status [--json]", "about": "Show SQLite path and table counts.", "examples": ["netrune db status --json"]},
            "import-flat": {"usage": "netrune db import-flat", "about": "Alias for inventory import-flat.", "examples": ["netrune db import-flat"]},
            "export-flat": {"usage": "netrune db export-flat", "about": "Alias for inventory export-flat.", "examples": ["netrune db export-flat"]},
    "path": {"usage": "netrune db path", "about": "Print the SQLite database path.", "examples": ["netrune db path"]},
            "integrity": {"usage": "netrune db integrity [--json]", "about": "Run SQLite integrity and quick checks without changing data.", "examples": ["netrune db integrity", "netrune db integrity --json"]},
            "repair": {"usage": "netrune db repair", "about": "Run schema migration, derived-state sync, WAL checkpoint, ANALYZE, optimize, and integrity checks.", "examples": ["netrune db repair"]},
            "history": {"usage": "netrune db history [--limit N]", "about": "Show recorded command executions newest first, with exit code and whether the command was read-only.", "examples": ["netrune db history"]},
            "prune": {"usage": "netrune db prune", "about": "Delete operational history past its retention window. Audit events are never pruned.", "examples": ["netrune db prune", "netrune db prune --json"]},
            "vacuum": {"usage": "netrune db vacuum", "about": "Checkpoint WAL and compact the SQLite database.", "examples": ["netrune db vacuum"]},
        },
    },
    "ask": {
        "summary": "Deterministic state retrieval and registry-backed command planning from natural language.",
        "usage": 'netrune ask ["question"] [global flags]',
        "actions": {
            "chat": {"usage": "netrune ask", "about": "Open a continuous retrieval/command-planning prompt with result, target, and plan context.", "examples": ["netrune ask"]},
            "question": {"usage": 'netrune ask "question" [--execute [--confirm]]', "about": "Answer from current state or return a validated command plan. Planning never executes; --execute is a separate boundary, and active operations also require --confirm.", "examples": ['netrune ask "How many APs are on the building9 switch at ZONE10?"', 'netrune ask "Run a fast health check for ZONE34"', 'netrune ask --execute --confirm "Run a fast health check for ZONE34"']},
            "patterns": {"usage": "netrune ask patterns", "about": "List supported retrieval and command-center families with example wording.", "examples": ["netrune ask patterns", "netrune ask patterns --json"]},
            "aliases": {"usage": "netrune ask aliases", "about": "List deterministic profile-specific phrase aliases.", "examples": ["netrune ask aliases"]},
            "alias": {"usage": "netrune ask alias set '<phrase>' '<target>' | remove '<phrase>'", "about": "Add or remove a durable local phrase alias. Natural alias plans are local-write actions and require explicit execution confirmation.", "examples": ["netrune ask alias set 'engineering office' 'engg ofc'", "netrune ask alias remove 'engineering office'"]},
        },
    },
}

HELP_TOPICS.update({
    "init": {
        "summary": "Initialize an isolated profile and check host capabilities.",
        "usage": "netrune init [--profile NAME] [--migrate-legacy]",
        "actions": {
            "run": {"usage": "netrune init [--profile NAME] [--migrate-legacy]", "about": "Create neutral XDG profile state and report required and optional system tools.", "examples": ["netrune init", "netrune init --profile lab", "netrune init --migrate-legacy"]},
        },
    },
    "profile": {
        "summary": "Create, select, inspect, and migrate isolated operator profiles.",
        "usage": "netrune profile <list|show|create|use|paths|migrate-legacy>",
        "actions": {
            "list": {"usage": "netrune profile list", "about": "List profiles and show which one is active.", "examples": ["netrune profile list"]},
            "show": {"usage": "netrune profile show [name]", "about": "Show one profile's paths and effective non-secret settings.", "examples": ["netrune profile show default"]},
            "create": {"usage": "netrune profile create <name>", "about": "Create a neutral, private profile without changing the active profile.", "examples": ["netrune profile create lab"]},
            "use": {"usage": "netrune profile use <name>", "about": "Select the profile used by future commands.", "examples": ["netrune profile use lab"]},
            "paths": {"usage": "netrune profile paths", "about": "Show the active profile's XDG-owned directories.", "examples": ["netrune profile paths --json"]},
            "migrate-legacy": {"usage": "netrune profile migrate-legacy [legacy-local]", "about": "Copy legacy netsnmp state into a private profile, recording a manifest and leaving originals untouched.", "examples": ["netrune profile migrate-legacy legacy-local"]},
        },
    },
    "config": {
        "summary": "Inspect and change non-secret profile configuration.",
        "usage": "netrune config <show|get|set|unset|validate|paths>",
        "actions": {
            "show": {"usage": "netrune config show", "about": "Show effective redacted settings and precedence.", "examples": ["netrune config show --json"]},
            "get": {"usage": "netrune config get <key>", "about": "Read one effective non-secret setting.", "examples": ["netrune config get core_switch_ip"]},
            "set": {"usage": "netrune config set <key> <value>", "about": "Set a profile override. Secret-looking keys are rejected.", "examples": ["netrune config set core_switch_ip 192.0.2.10"]},
            "unset": {"usage": "netrune config unset <key>", "about": "Remove a profile compatibility override.", "examples": ["netrune config unset target_abbreviation_prefix"]},
            "validate": {"usage": "netrune config validate", "about": "Validate effective configuration and flag legacy plaintext credentials.", "examples": ["netrune config validate"]},
            "paths": {"usage": "netrune config paths", "about": "Show global, profile, and compatibility config files.", "examples": ["netrune config paths"]},
        },
    },
    "secrets": {
        "summary": "Manage named sudo-gated encrypted secrets without putting values in arguments or config.",
        "usage": "netrune secrets <list|status|set|delete|import-ssh>",
        "actions": {
            "list": {"usage": "netrune secrets list", "about": "List secret names and recording dates; values are never displayed.", "examples": ["netrune secrets list"]},
            "status": {"usage": "netrune secrets status", "about": "Show encrypted store security and lock state.", "examples": ["netrune secrets status"]},
            "set": {"usage": "netrune secrets set <name>", "about": "Prompt twice for a value and atomically encrypt it.", "examples": ["netrune secrets set snmp/site-a/auth"]},
            "delete": {"usage": "netrune secrets delete <name> --confirm", "about": "Delete one named secret after explicit confirmation.", "examples": ["netrune secrets delete snmp/site-a/auth --confirm"]},
            "import-ssh": {"usage": "netrune secrets import-ssh", "about": "Import the legacy SSH password into ssh/default/password without deleting the original vault.", "examples": ["netrune secrets import-ssh"]},
        },
    },
    "ingest": {
        "summary": "Validate and run declarative, provenance-preserving data channels.",
        "usage": "netrune ingest <channels|validate|run|history|rejects|observations>",
        "actions": {
            "channels": {"usage": "netrune ingest channels", "about": "List TOML channels in the active profile.", "examples": ["netrune ingest channels"]},
            "validate": {"usage": "netrune ingest validate", "about": "Validate every channel manifest without fetching data.", "examples": ["netrune ingest validate"]},
            "run": {"usage": "netrune ingest run <channel>", "about": "Run one enabled channel with duplicate suppression and reject quarantine.", "examples": ["netrune ingest run inventory-csv"]},
            "history": {"usage": "netrune ingest history [--limit N]", "about": "Show ingest runs newest first.", "examples": ["netrune ingest history"]},
            "rejects": {"usage": "netrune ingest rejects [run-id]", "about": "Show redacted rejected-record metadata.", "examples": ["netrune ingest rejects"]},
            "observations": {"usage": "netrune ingest observations [channel]", "about": "Show append-only observations and evidence times.", "examples": ["netrune ingest observations inventory-csv"]},
        },
    },
    "plugin": {
        "summary": "Discover and explicitly enable trusted Python entry-point plugins.",
        "usage": "netrune plugin <list|enable|disable|check|groups>",
        "actions": {
            "list": {"usage": "netrune plugin list", "about": "Discover plugins without importing disabled code.", "examples": ["netrune plugin list"]},
            "enable": {"usage": "netrune plugin enable <group:name>", "about": "Enable one unambiguous installed plugin for this profile.", "examples": ["netrune plugin enable netops.parsers:example"]},
            "disable": {"usage": "netrune plugin disable <group:name>", "about": "Disable one plugin for this profile.", "examples": ["netrune plugin disable netops.parsers:example"]},
            "check": {"usage": "netrune plugin check [group]", "about": "Load enabled plugins in isolation and report API or policy failures.", "examples": ["netrune plugin check"]},
            "groups": {"usage": "netrune plugin groups", "about": "List stable entry-point groups and their trust policy.", "examples": ["netrune plugin groups"]},
        },
    },
    "setup": {
        "summary": "Stand up a working install from the few facts that differ between two of them.",
        "usage": "netrune setup <poller|local> --community <community> [--collector-id NAME] [--watch ADDRESS:INTERFACE] [--publish HOST --confirm]",
        "actions": {
            "poller": {"gist": "A machine that collects and nothing else.", "usage": "netrune setup poller --community <community> [--watch ADDRESS:INTERFACE]", "about": "Set this machine up to collect and nothing else: no exposition, no storage, no dashboards. It creates a profile of its own, gives the collector an identity distinct from every other, writes the SNMP community where the helpers read it, generates the collector unit and starts it, and says whether any of it will survive a reboot. Repeat --watch to give it work in the same breath. Everything it does is a command you could run yourself; none of it is a decision only you can make.", "args": [{"name":"community","text":"SNMP community. The one credential a poller genuinely needs."},{"name":"collector-id","text":"Identity stamped on every reading. Defaults to this machine's name; it must differ from every other collector's."},{"name":"watch","text":"ADDRESS:INTERFACE to start collecting. Repeatable."}], "examples": ["netrune setup poller --community public", "netrune setup poller --community public --watch 198.51.100.10:Gi1/0/16"]},
            "local": {"gist": "A machine that collects, stores, and draws.", "usage": "netrune setup local --community <community> [--publish HOST --confirm]", "about": "Set this machine up to collect, store, and draw: collector, exposition, VictoriaMetrics, and the dashboards. Everything binds to this machine only unless --publish says otherwise, which needs --confirm because it serves your readings and dashboards to anything that can reach that address.", "args": [{"name":"community","text":"SNMP community."},{"name":"publish","text":"Address to serve on instead of loopback. 0.0.0.0 means every interface."}], "examples": ["netrune setup local --community public", "netrune setup local --community public --publish 0.0.0.0 --confirm"]},
        },
        "examples": ["netrune setup poller --community public --watch 198.51.100.10:Gi1/0/16", "netrune setup local --community public"],
    },
    "traffic": {
        "summary": "Interface and reachability monitoring. Collection is watchlist driven: only targets you name are ever polled.",
        "usage": "netrune traffic <action> [arguments] [global flags]",
        "actions": {
            "list": {"usage": "netrune traffic list", "about": "Show every monitored target with its recent activity as a sparkline.", "examples": ["netrune traffic list"]},
            "watch": {"usage": "netrune traffic watch <device> <interface>[,<interface>...] [--interval SECONDS]", "gist": "Monitor interfaces on a switch over SNMP, and that switch's own health.", "about": "Monitor one or more interfaces on a switch over SNMP. Every name is verified against the device before it is accepted, and a comma-separated list is resolved in one SNMP walk. Watching the first port on a switch also starts collecting that switch's own health -- uptime, CPU, memory, temperature, and rejected management access -- which stops again when the last port on it is unwatched.", "args": [{"name":"device","text":"Switch hostname or IP."},{"name":"interface","text":"Interface name as the switch spells it. Separate several with commas."}], "examples": ["netrune traffic watch SITE-A-SW01 Gi1/0/16", "netrune traffic watch SITE-A-SW01 Gi1/0/16,Gi1/0/17,Te1/1/1 --interval 30"]},
            "ping": {"usage": "netrune traffic ping <target>", "about": "Monitor round-trip time and loss to an address from this collector.", "examples": ["netrune traffic ping 198.51.100.10"]},
            "subscribe": {"usage": "netrune traffic subscribe <target> --down 100M --up 20M [--facing isp|lan]", "gist": "Mark a link as one you pay for, so it gets its own tile and joins the WAN total.", "about": "Mark a link as one you pay for, and record what it is sold at. Marking it is what puts it on the overview as its own tile and includes it in the WAN total; the rate itself is kept as a soft limit -- nothing is enforced, and nothing is discarded for exceeding it. The tiles read in bits per second rather than as a share of the contract, so a wrong figure here costs you the soft limit and not the reading. --facing says which way the port looks: 'isp' (default) is the port that reaches the provider, where what the switch receives is your download; 'lan' is the port facing inward, where it is the other way round. --clear removes the subscription.", "args": [{"name":"target","text":"Watch id, or any words that together name one link -- 'SITE-A-SW01 Gi1/0/12' when two switches share a port name. 'netrune traffic list' prints the ids."},{"name":"down","text":"Downstream rate, as 100M, 100 Mbps, or 1.5G."},{"name":"up","text":"Upstream rate."}], "examples": ["netrune traffic subscribe wch-1a2b3c4d --down 100M --up 20M", "netrune traffic subscribe SITE-A-SW01 Gi1/0/12 --down 100M --up 20M", "netrune traffic subscribe Gi1/0/12 --down 500M --facing lan", "netrune traffic subscribe Gi1/0/12 --clear"]},
            "name": {"usage": 'netrune traffic name <target> "<name>" [--color teal|orange|green|violet|#rrggbb]', "gist": "Give a port a name and a colour of your own for the dashboards.", "about": "Give a monitored port a name of your own for dashboards -- \"AFRIX\" rather than Gi1/0/16 -- and optionally pin its colour with --color, so it is the same colour on every chart instead of whatever the grapher assigns by arrival order. Colours: teal, orange, green, violet, or an explicit #rrggbb. Those four were checked together for separation, lightness, and colour-blind readability; a fifth of your own was not. The name is not part of a series' identity, so naming a port that has been collected for weeks keeps its history rather than starting a new series. Everything after the target is the name, so it needs no quoting to contain spaces. --clear removes it and the port shows as the device calls it again.", "args": [{"name":"target","text":"Watch id, device, or interface name."},{"name":"name","text":"What to call it on a chart."}], "examples": ["netrune traffic name Gi1/0/12 AFRIX --color teal", "netrune traffic color Gi1/0/12 teal", "netrune traffic name Gi1/0/16 --clear"]},
            "push": {"gist": "Send this collector's readings straight into storage.", "usage": "netrune traffic push --to http://<storage-host>:8428", "about": "Send this collector's current readings to a VictoriaMetrics import endpoint. They arrive as the counters they are, carrying this collector's id, so they stay distinguishable from the receiving machine's own readings and every dashboard reads them unchanged. This is the other way a poller hands its readings over: pulling fetches them over SSH and needs a path inward, pushing needs a path outward, and a network usually permits one or the other. The receiving machine must have been told to accept it -- storage binds to loopback until 'setup local --accept-push --confirm' says otherwise.", "args": [{"name":"to","text":"Storage URL, without a path. Defaults to traffic_push_url."}], "examples": ["netrune traffic push --to http://198.51.100.5:8428", "netrune setup poller --community public --push-to http://198.51.100.5:8428"]},
            "dashboard": {"gist": "Where the dashboards are, and whether the grapher is up.", "usage": "netrune traffic dashboard [--open] | save [UID|--all] | revert [UID|--all]", "about": "Print every dashboard's URL and say whether the grapher is answering. 'save' keeps a dashboard you have rearranged in the browser, writing it in place of the generated one so it survives the next 'stack init'; 'revert' goes back to the generated version. Dashboards are generated because a generator keeps five of them consistent and hand-edited JSON does not, but a board you have arranged the way you read it should not have to be given up for that. --open launches the overview in a browser. When it is not answering this says which of the two reasons it is -- the service is not started, or the machine's per-user systemd manager is not running at all -- because from a browser those look identical and lead somewhere quite different.", "examples": ["netrune traffic dashboard", "netrune traffic dashboard --open", "netrune traffic dashboard save netrune-overview", "netrune traffic dashboard revert netrune-overview"]},
            "health": {"usage": "netrune traffic health [device] [--since 6h]", "gist": "Uptime, CPU, memory, temperature, and sessions for every watched switch.", "about": "Show switch-level readings for every switch with a watched port: uptime, control-plane CPU, memory, temperature, and open sessions. These are collected automatically alongside the ports, because a port that went quiet reads differently depending on whether its switch rebooted or ran out of CPU. A dash means the switch does not answer that OID; nothing is wrong. Failed SSH logins are in no standard MIB -- read the switch's syslog for those.", "args": [{"name":"device","text":"Limit to one switch. Omit for all of them."}], "examples": ["netrune traffic health", "netrune traffic health SITE-A-SW01"]},
            "unwatch": {"usage": "netrune traffic unwatch <target> [--confirm]", "about": "Stop monitoring one or more targets and discard their samples. A phrase matching several targets needs --confirm.", "args": [{"name":"target","text":"Watch id, device, or interface name."}], "examples": ["netrune traffic unwatch wch-1a2b3c", "netrune traffic unwatch SITE-A-SW01 --confirm"]},
            "pause": {"usage": "netrune traffic pause <target>", "about": "Stop collecting a target without discarding its history. A running collector notices on its next tick.", "args": [{"name":"target","text":"Watch id, device, or interface name. A device pauses every port on it."}], "examples": ["netrune traffic pause Gi1/0/16", "netrune traffic pause SITE-A-SW01"]},
            "resume": {"usage": "netrune traffic resume <target>", "about": "Start collecting a paused target again.", "args": [{"name":"target","text":"Watch id, device, or interface name."}], "examples": ["netrune traffic resume SITE-A-SW01"]},
            "interval": {"usage": "netrune traffic interval <target> <seconds>", "about": "Change how often a target is collected, between 10 and 3600 seconds.", "args": [{"name":"target","text":"Watch id, device, or interface name."},{"name":"seconds","text":"New collection interval."}], "examples": ["netrune traffic interval Gi1/1/1 15"]},
            "status": {"usage": "netrune traffic status", "about": "Show whether a collector is running and when each target last produced a sample.", "examples": ["netrune traffic status"]},
            "interfaces": {"usage": "netrune traffic interfaces <device>", "about": "List the interfaces SNMP reports on a device, with index and description.", "examples": ["netrune traffic interfaces SITE-A-SW01"]},
            "poll": {"usage": "netrune traffic poll", "about": "Collect one round from every enabled watch. Intended for cron as well as by hand.", "examples": ["netrune traffic poll"]},
            "daemon": {"usage": "netrune traffic daemon [--interval SECONDS]", "gist": "Collect continuously, each target at its own interval.", "about": "Collect continuously until interrupted, taking each target at its own interval. --interval overrides every target's interval for this run. Polls only what is on the watchlist.", "examples": ["netrune traffic daemon", "netrune traffic daemon --interval 30"]},
            "exporter": {"usage": "netrune traffic exporter [--bind HOST:PORT] [--once]", "gist": "Serve the collected readings as Prometheus exposition for storage to scrape.", "about": "Publish collected readings as Prometheus exposition for VictoriaMetrics to scrape. Counters are raw and monotonic; rates are derived at query time. Binds loopback, answers GET only, and runs no command. --once prints the body and exits.", "examples": ["netrune traffic exporter", "netrune traffic exporter --once", "netrune traffic exporter --bind 127.0.0.1:9713"]},
            "backfill": {"usage": "netrune traffic backfill [--url URL] [--since WINDOW]", "gist": "Import history collected before the metrics stack existed.", "about": "Import history collected before the metrics stack existed into VictoriaMetrics. Stored rates are published as netrune_history_* gauges, kept separate from the live counter series so a derived value is never read as a measured one.", "examples": ["netrune traffic backfill", "netrune traffic backfill --since 7d --dry-run"]},
            "stack": {"usage": "netrune traffic stack init|show|graphers|up|down|restart|status [--role full|collector] [--grapher NAME] [--dir PATH] [--url URL] [--bind HOST:PORT] [--retention PERIOD]", "gist": "Generate the metrics stack, and start, stop, or inspect its services.", "about": "Write the VictoriaMetrics scrape config, vmalert rules, dashboards for the selected grapher, systemd user units, and a compose file. Dashboards are provisioned from these files rather than edited in a browser. 'graphers' lists which are available. --role collector generates the collector alone -- no exposition, no storage, no dashboards -- which is what a remote poller needs: the machine that pulls from it keeps and draws the readings, and anything published on the poller would be a new listener on the network it was placed there to observe.", "args": [{"name":"grapher","text":"Which dashboard tool to generate for: grafana, perses, or none."},{"name":"role","text":"full (default) or collector. A collector runs nothing that listens."}], "examples": ["netrune traffic stack init", "netrune traffic stack graphers", "netrune traffic stack init --grapher perses", "netrune traffic stack init --dir ~/netrune-metrics --retention 180d", "netrune traffic stack init --role collector"]},
            "export": {"usage": "netrune traffic export [--since WINDOW]", "gist": "Print this collector's readings as JSONL for another install to pull.", "about": "Print this collector's stored readings as JSONL for another install to pull. Read-only, and limited to what this collector measured: a poller does not pass on what it pulled from somewhere else.", "examples": ["netrune traffic export --since 24h"]},
            "pull": {"usage": "netrune traffic pull --remote NAME [--since WINDOW] | --file PATH|- [--dry-run]", "about": "Merge a poller's readings into this install. --remote fetches them over SSH; --file merges an export the poller wrote, which is what to use where SSH between the two subnets is not permitted -- an export is a file, and anything that can move a file will do. '-' reads standard input. A file is merged whole rather than by window, and merging is idempotent, so re-reading one adds nothing. Without --since a fetch resumes from the newest reading already merged, so a repeated pull carries only what is new.", "args": [{"name":"remote","text":"Name of a remote added with 'traffic remote add'. With --file, records the pull against it."},{"name":"file","text":"An export file to merge, or '-' for standard input."}], "examples": ["netrune traffic pull --remote poller1", "netrune traffic pull --remote poller1 --since 24h --dry-run"]},
            "remote": {"usage": "netrune traffic remote add|list|remove NAME [...] | netrune traffic remote NAME <command>", "gist": "Manage remote pollers, and run any traffic command on one over SSH.", "about": "Manage remote pollers, and run any traffic command on one over SSH. Anything that is not add, list, or remove is forwarded verbatim to the real CLI on the poller, so remote control and local control cannot drift apart.", "args": [{"name":"name","text":"Name of the remote poller."}], "examples": ["netrune traffic remote add poller1 --host 100.64.0.5 --ssh-user netrune", "netrune traffic remote list", "netrune traffic remote poller1 watch SITE-A-SW01 Gi1/0/16 --interval 30", "netrune traffic remote poller1 pause SITE-A-SW01"]},
            "verify": {"usage": "netrune traffic verify [--url URL] [--bind HOST:PORT] [--grapher NAME]", "gist": "Walk the pipeline link by link and report the first place it breaks.", "about": "Walk the pipeline link by link and report where it breaks: watchlist, collector, exposition, storage, scraping, rate derivation, and grapher. Checks run in the order data flows, so the first failure is the cause rather than a symptom.", "examples": ["netrune traffic verify", "netrune traffic verify --grapher grafana"]},
            "report": {"usage": "netrune traffic report [target] [--since WINDOW] [--out PATH]", "about": "Write a self-contained HTML report with charts for the collected window.", "examples": ["netrune traffic report", "netrune traffic report Gi1/0/16 --since 6h --out ~/traffic.html"]},
            "show": {"usage": "netrune traffic show [target] [--since WINDOW]", "gist": "Throughput or latency as terminal sparklines, with current and peak.", "about": "Show throughput or latency as terminal sparklines with current and peak values. The window accepts seconds or a duration such as 15m, 6h, or 2d.", "examples": ["netrune traffic show", "netrune traffic show Gi1/0/16 --since 6h"]},
        },
    },
    "path": {
        "summary": "Inspect a bounded endpoint path across cached topology and live read-only forwarding evidence.",
        "usage": "netrune path <inspect|history|show>",
        "actions": {
            "inspect": {"usage": "netrune path inspect <endpoint> --vlan <id> [--from SWITCH] [--to SWITCH] [--depth N] [--max-nodes N] [--cached|--live|--refresh] [--explain]", "about": "Plan from cached topology, then validate VLAN, trunk, STP, LAG, SVI, VRF, route, ARP/ND, and policy evidence where supported. `netrune ghoster` is an alias.", "examples": ["netrune path inspect 02:00:00:00:00:25 --vlan 120", "netrune ghoster 192.0.2.25 --vlan 120 --from SITE-A-CORE-01 --explain", "netrune path inspect endpoint-25 --vlan 120 --cached"]},
            "findings": {"usage": "netrune path findings [--severity LEVEL]", "about": "Query findings across every recorded path run, newest first, with a frequency summary. Answers which switches or interfaces keep failing rather than what one run said.", "options": [{"name":"--severity LEVEL", "text":"critical, error, warning, or info."}], "examples": ["netrune path findings", "netrune path findings --severity critical"]},
            "history": {"usage": "netrune path history [endpoint] [--vlan ID]", "about": "Show chronological path runs newest first with reusable compact run references.", "examples": ["netrune path history", "netrune path history 02:00:00:00:00:25 --vlan 120"]},
            "show": {"usage": "netrune path show <run-id|run-prefix|endpoint|last> [--vlan ID]", "about": "Reopen a persisted path by full ID, compact history reference, or latest endpoint/VLAN match.", "examples": ["netrune path show path-0123456789", "netrune path show 02:00:00:00:00:25 --vlan 120", "netrune path show last"]},
        },
    },
    "excel": {
        "summary": "Correlate your own Excel workbooks with Netrune's inventory, and build tracker workbooks.",
        "usage": "netrune excel <inspect|sync|export>",
        "actions": {
            "inspect": {"usage": "netrune excel inspect <workbook.xlsx> [--sheet NAME] [--map 'Header=field,...'] [--fields LIST]", "about": "Report which rows match which Netrune switch and what is out of date, without writing. Finds each sheet's header row and columns, matches rows by serial, base MAC, IP, or hostname, and lists conflicts and unmatched rows.", "examples": ["netrune excel inspect ~/switches.xlsx", "netrune excel inspect ~/Assets.xlsx --sheet Switches --map 'Mgmt Addr=ip'"]},
            "sync": {"usage": "netrune excel sync <workbook.xlsx> [--sheet NAME] [--map 'Header=field,...'] [--fields LIST] [--fill-only] [--add-missing] [--prefer serial|mac|ip|hostname] [--output PATH] [--highlight] [--no-comments] [--ignore-lock] [--allow-feature-loss] (--dry-run | --confirm)", "about": "Write Netrune's current hostname, IP, model, serial, base MAC, and platform into the matched rows' empty or out-of-date cells (status and last_seen with --fields). Formula cells, other columns, and other sheets are left alone. --confirm backs the original up, saves atomically, reads the file back to verify, and records an audit event; without it nothing is written.", "examples": ["netrune excel sync ~/switches.xlsx --dry-run", "netrune excel sync ~/switches.xlsx --fields mac,serial,model --confirm", "netrune excel sync ~/switches.xlsx --sheet Switches --add-missing --output ~/switches-updated.xlsx --confirm"]},
            "export": {"usage": "netrune excel export <tracker.xlsx> [--migration-rows N] [--confirm]", "about": "Write a new workbook: an Inventory table, a live Summary of formulas and a chart, and a Migration Tracker with dropdowns, lookups, and overdue highlighting. --confirm is needed only to replace an existing file, which is backed up first.", "examples": ["netrune excel export ~/network-tracker.xlsx"]},
        },
    },
    "support": {
        "summary": "Create privacy-redacted diagnostics for support and bug reports.",
        "usage": "netrune support bundle [output.tar.gz]",
        "actions": {
            "bundle": {"usage": "netrune support bundle [output.tar.gz]", "about": "Package version, redacted settings, integrity, drivers, plugins, and recent run summaries. Inventory and raw evidence are excluded.", "examples": ["netrune support bundle", "netrune support bundle ./netops-support.tar.gz"]},
        },
    },
})

LEGACY_NOUN_HINTS: Dict[str, str] = {
    "discover": "netrune inventory scan",
    "discovery": "netrune inventory scan",
    "control": "netrune device <ssh|show|config|inventory>",
    "connect": "netrune device ssh <target>",
    "probe": "netrune diagnose latency <target>",
    "check": "netrune diagnose filtering [domain]",
    "netcheck": "netrune diagnose filtering [domain]",
    "gateprober": "netrune diagnose interface <device> on <interface>",
    "interface": "netrune diagnose interface <device> on <interface>",
 }

VERB_ALIASES: Dict[str, Dict[str, str]] = {
    "inventory": {"update":"scan", "search":"list", "offline":"health offline", "ping-list":"activity", "activity-list":"activity"},
    "ap": {"discover":"scan", "switch":"on-switch", "on_switch":"on-switch", "audit":"moves"},
    "topology": {"discover":"scan", "discover-neighbors":"scan", "links":"neighbors", "change":"changes"},
    "memory": {"query":"switch", "source":"explain", "sources":"explain"},
    "health": {"fast":"check", "fast-health":"check", "down":"offline", "review":"attention"},
    "backup": {"backup":"run", "backup-history":"history", "last":"diff"},
    "device": {"connect":"ssh", "shell":"ssh", "run":"show", "configure":"config"},
    "vlan": {"propagated":"propagation", "find":"locate"},
    "lookup": {"core-lookup":"core", "mac-lookup":"mac"},
    "diagnose": {"probe":"latency", "ping":"latency", "speedtest":"speed", "speed-test":"speed", "netcheck":"filtering", "check":"filtering", "gateprober":"interface", "monitor":"interface"},
    "commands": {"registry":"list", "preview":"run"},
    "db": {"import":"import-flat", "export":"export-flat", "init":"migrate"},
}

GLOBAL_FLAG_HELP = [
    ("--json", "Emit JSON for commands that support structured output."),
    ("--plain", "Prefer plain terminal output when both formats exist."),
    ("--no-color", "Disable ANSI color in helpers that honor NO_COLOR."),
    ("--dry-run", "Preview work without making changes or launching risky actions."),
    ("--confirm", "Explicitly permit guarded config-changing commands."),
    ("--approve", "Alias of --confirm for guarded command execution."),
    ("--execute", "Execute a ready Natural Ask command plan; active operations also require --confirm."),
    ("--limit N", "Limit rows returned by list/history/timeline commands."),
    ("--since WHEN", "Filter by a time expression where supported."),
    ("--status STATUS", "Filter status. Common values: ONLINE, OFFLINE."),
    ("--site SITE", "Filter by site/location token where supported."),
    ("--source SRC", "Filter by source where supported."),
    ("--timeout N", "Per-command timeout in seconds for subprocess wrappers."),
    ("--workers N", "Worker/concurrency hint for commands that support it."),
    ("--depth N", "Maximum switch-link hops for bounded path or recursive VLAN traversal (1-16)."),
    ("--max-nodes N", "Hard node budget for recursive traversal (default 64, maximum 256)."),
    ("--refresh-neighbors", "Query live LLDP/CDP when traversing instead of relying only on cached topology."),
    ("--first", "Resolve ambiguous targets to the first match where supported."),
    ("--all", "Resolve ambiguous targets to all matches where supported."),
    ("--interactive", "Allow interactive resolution where supported."),
    ("--profile NAME", "Use one isolated profile for this command without changing the active profile."),
]

EXIT_CODE_HELP = [
    (0, "success"), (2, "usage"), (3, "partial"), (4, "unreachable"), (5, "unsupported"),
    (6, "validation"), (7, "confirmation required"), (8, "auth"), (9, "timeout"), (10, "internal"),
    (130, "interrupted"), (143, "terminated"),
]

class App(DeviceCommandsMixin, InventoryCommandsMixin, VlanCommandsMixin, TopologyCommandsMixin, LookupCommandsMixin, DiagnoseCommandsMixin):
    def __init__(self, install_dir: Path, profile: str = ""):
        synchronize_environment_aliases()
        os.environ["NETRUNE_CORE_MANAGED"] = "1"
        os.environ["NETOPS_CORE_MANAGED"] = "1"
        self.paths = Paths(install_dir, profile=profile)
        self.config = Config(self.paths)
        for key, value in self.config.public.items():
            canonical_key = "NETRUNE_IDENTITY_STRIP_PREFIXES" if key == "strip_prefixes" else "NETRUNE_" + key.upper()
            legacy_key = canonical_key.replace("NETRUNE_", "NETOPS_", 1)
            os.environ[canonical_key] = value
            os.environ[legacy_key] = value
        self.state = State(self.paths)
        # Retention is an operator setting, and the store cannot read profile
        # configuration on its own.
        self.state.retention_settings = self.config.public
        self.natural_ask = NaturalAskEngine(self)
        self.lock = threading.RLock()
        self.profile_store = ProfileStore(self.paths.home)
        self.plugin_manager = PluginManager(self.paths.config_dir)
        self.loaded_plugins = self.plugin_manager.load_enabled()
        self.plugin_ingest_providers = {
            item.descriptor.name: item.implementation
            for item in self.loaded_plugins
            if item.descriptor.group.endswith(".ingest") and item.descriptor.load_status == "loaded" and item.implementation is not None
        }
        self.plugin_provider_sources = {
            item.descriptor.name: item.descriptor.source
            for item in self.loaded_plugins
            if item.descriptor.group.endswith(".ingest") and item.descriptor.load_status == "loaded"
        }
        self.plugin_parsers = {
            item.descriptor.name: item.implementation
            for item in self.loaded_plugins
            if item.descriptor.group.endswith(".parsers") and item.descriptor.load_status == "loaded" and item.implementation is not None
        }
        self.plugin_exporters = {
            item.descriptor.name: item.implementation
            for item in self.loaded_plugins
            if item.descriptor.group.endswith(".exporters") and item.descriptor.load_status == "loaded" and item.implementation is not None
        }
        self.device_drivers = DEVICE_DRIVERS.clone()
        self.driver_manifest_report = self.device_drivers.load_declarative(self.paths.config_dir / "drivers")
        self.driver_manifest_report.extend(self.device_drivers.load_python_plugins(
            item for item in self.loaded_plugins if item.descriptor.group.endswith(".device_drivers")
        ))
        self.ingest_manager = IngestManager(
            self.state,
            self.paths.config_dir / "channels",
            SecretResolver(self.named_secret_get),
            self.plugin_ingest_providers,
            self.plugin_provider_sources,
        )
        self.path_inspector = PathInspector(self)
    def legacy_cmd(self, helper: str, *args: str) -> List[str]: return [self.paths.tool(helper), *[a for a in args if a]]

    def detect_device_family(self, **evidence: Any) -> DeviceDetection:
        return self.device_drivers.detect(**evidence)

    def driver_for(self, *, family: str = "", **evidence: Any) -> DeviceDriver:
        detection = family or self.device_drivers.detect(**evidence).family
        return self.device_drivers.get(detection)

    def firmware_write_certified(self, driver: DeviceDriver, detection: DeviceDetection, *, platform: Any = "", model: Any = "", hostname: Any = "") -> Tuple[bool, str]:
        """Is this device's firmware trusted for a guarded config/VLAN write?

        Certified means: the command_templates this driver sends for
        config_enter/config_exit/save/vlan writes are known to work against
        this firmware. That's still true either because the detected
        firmware profile is on the driver's own built-in list
        (`driver.firmware_profiles`, curated in devices.py), or via either
        of two operator-configurable, source-edit-free escape hatches --
        checked in this order, first match wins:

        1. `device_certified_firmware` -- comma-separated `family:pattern`
           entries; `pattern` is a case-insensitive regex matched against
           the same raw platform/model/hostname text the built-in detector
           uses. For one exact firmware string.
           netrune config set device_certified_firmware "cisco-ios:VERSION 12\\."

        2. `device_certified_firmware_min` -- comma-separated
           `family:X.Y` entries. Extracts the first `major.minor`-shaped
           number found in that same evidence text and certifies anything
           at or above the given floor -- for "this driver's commands don't
           meaningfully change across an entire firmware range, so don't
           make me enumerate every version" (e.g. IOS 12 through current,
           where config_enter/config_exit/save haven't changed).
           netrune config set device_certified_firmware_min "cisco-ios:12.0"

        Both only ever change *which firmware is trusted to receive* this
        driver's own already-vetted commands -- neither can change what
        gets sent. Changing what gets sent for a firmware/family whose
        syntax genuinely differs is a different, bigger decision (a new or
        edited built-in DeviceDriver in devices.py); see that file's
        REGISTRY.register() calls, or ask for one to be added.

        The actual matching logic lives in devices.py's firmware_certification()
        (a pure function with no Config/App dependency) so this and the
        shell-invoked `python -m netops_platform.devices stream --action config`
        path that really renders the SSH command stream -- the enforcement
        point that matters -- make the identical decision, not two that could
        silently disagree (that gap is exactly what let a device pass this
        preflight check yet still be refused when the write actually ran).

        Returns (certified, source) where source is "built-in", "operator"
        (matched a pattern), or "operator-floor" (matched a version floor).
        """
        evidence = " ".join(str(value or "") for value in (platform, model, hostname)).upper()
        return firmware_certification(
            driver, detection, evidence,
            exact_patterns=str(self.config.public.get("device_certified_firmware") or ""),
            floor_ranges=str(self.config.public.get("device_certified_firmware_min") or ""),
        )

    def import_flat_state(self, domains: Sequence[str], source: str) -> Dict[str, Any]:
        imported = self.state.import_flat_files()
        requested = set(domains)
        runs: List[Dict[str, Any]] = []
        if "device" in requested:
            rows = self.state.rows("SELECT ip,hostname,platform,model,serial,mac,source,last_seen,status FROM devices ORDER BY ip")
            runs.append(self.ingest_manager.record_snapshot(
                "built-in-ssh-scan", "device", rows,
                identity_fields=("ip",), source=source, confidence=85,
            ).to_dict())
        if "ap" in requested:
            rows = self.state.rows("SELECT ip,name,platform,switch_ip,switch_name,switch_port,mac,last_seen,status FROM aps ORDER BY ip,name")
            groups: Dict[str, List[Dict[str, Any]]] = {
                "built-in-cisco-wlc": [],
                "built-in-smartzone": [],
                "built-in-ap-scan": [],
            }
            for row in rows:
                evidence = str(row.get("platform") or "").lower()
                channel = "built-in-smartzone" if re.search(r"smartzone|ruckus|\bvsz\b", evidence) else ("built-in-cisco-wlc" if re.search(r"cisco|\bwlc\b", evidence) else "built-in-ap-scan")
                groups[channel].append(row)
            for channel, observations in groups.items():
                if not observations:
                    continue
                runs.append(self.ingest_manager.record_snapshot(
                    channel, "access-point", observations,
                    identity_fields=("mac", "ip", "name"), source=source, confidence=85,
                ).to_dict())
        if "topology" in requested:
            rows = self.state.rows("SELECT local_ip,local_name,local_port,remote_name,remote_port,remote_ip FROM neighbors ORDER BY local_ip,local_port,remote_name")
            runs.append(self.ingest_manager.record_snapshot(
                "built-in-lldp-cdp", "neighbor-link", rows,
                identity_fields=("local_ip", "local_port", "remote_name", "remote_port"),
                source=source, observed_at_field="observed_at", confidence=80, composite_identity=True,
            ).to_dict())
        return {"imported": imported, "ingest_runs": runs}

    def named_secret_get(self, name: str) -> str:
        if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]*(?:/[a-z0-9][a-z0-9_.-]*)*", str(name or "")):
            raise ValueError("invalid named secret")
        env = os.environ.copy()
        env.update(profile_environment(self.paths.profile_layout))
        process = subprocess.run(
            self.legacy_cmd("netrune-connect", "--secret-get", name),
            text=True,
            stdout=subprocess.PIPE,
            env=env,
            check=False,
        )
        if process.returncode != 0:
            raise RuntimeError(f"named secret could not be unlocked: {name}")
        return process.stdout.rstrip("\r\n")
    def emit(self, data: Any, opts: GlobalOptions, text: Optional[str] = None) -> None:
        # Final output always starts on a clean row, never underneath a
        # leftover status line.
        self._progress_clear(opts)
        print(json_dumps(data) if opts.json else (text if text is not None else self.render_plain(data)))
    def render_plain(self, data: Any) -> str:
        if isinstance(data, list): return self.render_table(data) if data and isinstance(data[0], dict) else "\n".join(map(str, data))
        if isinstance(data, dict) and "rows" in data: return self.render_table(data["rows"])
        if isinstance(data, dict): return self._render_kv(data) if self._color_enabled() else "\n".join(f"{k}: {v}" for k, v in data.items() if not isinstance(v, (list, dict)))
        return str(data)
    @staticmethod
    def _color_enabled(stream: Any = None) -> bool:
        # --plain and --no-color both land here through the same NO_COLOR
        # env var they set at parse time (see dispatch), so this one check
        # covers every way a caller can ask for undecorated output, without
        # threading opts through the 80-odd render_table call sites. stdout
        # and stderr are checked independently -- redirecting one (e.g.
        # `2>error.log` while stdout stays a terminal) must not leak ANSI
        # codes into the redirected stream.
        if os.environ.get("NO_COLOR"):
            return False
        return (stream or sys.stdout).isatty()
    @staticmethod
    def _status_style(value: str) -> str:
        return STATUS_STYLES.get(value.strip().upper(), "")
    @staticmethod
    def _rich_console(width: Optional[int] = None) -> Tuple[Console, io.StringIO]:
        buffer = io.StringIO()
        if width is None:
            width = shutil.get_terminal_size(fallback=(100, 24)).columns
        console = Console(file=buffer, force_terminal=True, width=max(40, width), highlight=False, soft_wrap=False)
        return console, buffer
    def render_table(self, rows: List[Dict[str, Any]], columns: Optional[List[str]] = None) -> str:
        if not rows: return "No records."
        columns = columns or list(rows[0].keys())[:8]
        def display_value(row: Dict[str, Any], column: str) -> str:
            value = row.get(column, "")
            if is_timestamp_field(column):
                value = fmt_time(value) or value
            return str(value if value is not None else "")
        # Every column gets a fixed width computed the same way for both render
        # tiers, rather than letting rich auto-negotiate: its default squeeze
        # algorithm shrinks columns proportionally to their natural width, which
        # starves short columns (IP, STATUS) toward zero on a narrow terminal
        # while a single wide one (NAME, DETAIL) keeps most of the space.
        widths = {c: min(32, max(len(c), *(len(display_value(r, c)) for r in rows))) for c in columns}
        if self._color_enabled():
            table = Table(box=box.SIMPLE_HEAD, header_style="bold", show_edge=False, pad_edge=False)
            for c in columns:
                table.add_column(c.upper(), overflow="ellipsis", no_wrap=True, width=widths[c])
            for row in rows:
                cells = []
                for c in columns:
                    s = display_value(row, c)
                    style = self._status_style(s)
                    cells.append(Text(s, style=style) if style else Text(s))
                table.add_row(*cells)
            # Render at exactly the width the columns need, not the terminal's
            # width: rich's own fit-to-terminal squeeze shrinks columns
            # proportionally to their natural size, which starves a short one
            # (IP, STATUS) toward nothing while a wide one (NAME) keeps most
            # of the space. Measuring first and rendering at that exact width
            # (rather than computing it by hand) means padding/box overhead
            # never has to be guessed. Sizing to content and letting the
            # terminal soft-wrap if it's narrower matches how the plain-text
            # fallback already works.
            content_width = Console(file=io.StringIO(), width=400).measure(table).maximum
            console, buffer = self._rich_console(width=content_width)
            console.print(table)
            return buffer.getvalue().rstrip("\n")
        lines = ["  ".join(c.upper().ljust(widths[c]) for c in columns), "  ".join("-"*widths[c] for c in columns)]
        for row in rows:
            vals=[]
            for c in columns:
                s=display_value(row,c); raw=s[:max(0,widths[c]-3)]+"..." if len(s)>widths[c] else s; cell=raw.ljust(widths[c])
                vals.append(cell)
            lines.append("  ".join(vals))
        return "\n".join(lines)
    def _render_kv(self, data: Dict[str, Any]) -> str:
        table = Table(box=None, show_header=False, show_edge=False, pad_edge=False, padding=(0, 1, 0, 0))
        table.add_column(style="bold", no_wrap=True)
        table.add_column(overflow="ellipsis", no_wrap=True)
        for k, v in data.items():
            if isinstance(v, (list, dict)):
                continue
            s = str(v)
            style = self._status_style(s)
            table.add_row(f"{k}:", Text(s, style=style) if style else Text(s))
        console, buffer = self._rich_console()
        console.print(table)
        return buffer.getvalue().rstrip("\n")
    def render_findings(self, rows: List[Dict[str, Any]], empty: str = "No findings.") -> str:
        if not rows:
            return empty
        color = self._color_enabled()
        severity_style = {"critical": "red", "error": "red", "warning": "yellow", "info": "blue"}
        lines: List[str] = []
        for row in rows:
            severity = str(row.get("severity") or "info").lower()
            label = severity.upper()
            if color and severity_style.get(severity):
                label = Style.parse(f"bold {severity_style[severity]}").render(label)
            heading = "  ".join(
                value for value in (
                    label,
                    str(row.get("code") or "FINDING"),
                    str(row.get("device_id") or ""),
                    str(row.get("interface") or ""),
                ) if value
            )
            lines.append(heading)
            lines.append(f"  {str(row.get('message') or '').strip()}")
        return "\n".join(lines)
    def version_rows(self, rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for idx, row in enumerate(rows, 1):
            item = timestamp_row(row)
            item["version"] = idx
            item["version_label"] = "version 1 (latest/current)" if idx == 1 else f"older version {idx}"
            out.append(item)
        return out
    def child_env(self, opts: GlobalOptions) -> Dict[str, str]:
        # Every helper spawn passes through here, and the helpers read
        # inventory from the flat files. Exporting at this point means a child
        # can never see stale device data, whichever code path changed it.
        self.state.flush_inventory_exports()
        env = os.environ.copy()
        env.update(profile_environment(self.paths.profile_layout))
        for key, value in self.config.public.items():
            env["NETOPS_" + key.upper()] = value
            env["NETRUNE_" + key.upper()] = value
        if opts.confirm:
            env["NETRUNE_CORE_WRITE_REQUEST"] = "audited-confirmation"
            env["NETOPS_CORE_WRITE_REQUEST"] = "audited-confirmation"
        if opts.first:
            env["NETRUNE_RESOLVE_MODE"] = "first"
            env["NETOPS_RESOLVE_MODE"] = "first"
        elif opts.all:
            env["NETRUNE_RESOLVE_MODE"] = "all"
            env["NETOPS_RESOLVE_MODE"] = "all"
        elif opts.interactive:
            env.pop("NETRUNE_RESOLVE_MODE", None)
            env.pop("NETOPS_RESOLVE_MODE", None)
        return env
    @staticmethod
    def _process_group_exists(pgid: int) -> bool:
        try:
            os.killpg(pgid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True

    def _wait_process_group(self, proc: subprocess.Popen, pgid: int, timeout: float) -> bool:
        deadline = time.monotonic() + max(0.0, timeout)
        while self._process_group_exists(pgid) and time.monotonic() < deadline:
            if proc.poll() is None:
                with contextlib.suppress(subprocess.TimeoutExpired):
                    proc.wait(timeout=min(0.1, max(0.01, deadline - time.monotonic())))
            else:
                time.sleep(0.05)
        return not self._process_group_exists(pgid)

    def _terminate_process_group(self, proc: Optional[subprocess.Popen], sig: int = signal.SIGTERM, wait: float = 2.0) -> None:
        """Stop the complete child session, including descendants after parent exit."""
        if not proc:
            return
        # Every managed process is created with start_new_session=True, making
        # its PID the stable process-group ID even if the immediate child exits.
        pgid = proc.pid
        stages = [(sig, wait)]
        if sig not in {signal.SIGTERM, signal.SIGKILL}:
            stages.append((signal.SIGTERM, min(wait, 1.5)))
        if sig != signal.SIGKILL:
            stages.append((signal.SIGKILL, 0.5))
        for current_signal, stage_wait in stages:
            if not self._process_group_exists(pgid):
                break
            with contextlib.suppress(ProcessLookupError):
                os.killpg(pgid, current_signal)
            if self._wait_process_group(proc, pgid, stage_wait):
                break
        with contextlib.suppress(Exception):
            proc.wait(timeout=0.5)

    # Progress is a single transient line on stderr. It never touches stdout,
    # so piping and --json stay clean, and it is cleared before any full-line
    # write so it cannot be left stranded above real output.
    _progress_active = False

    def _progress_enabled(self, opts: Optional[GlobalOptions] = None) -> bool:
        if opts is not None and opts.json:
            return False
        if os.environ.get("NO_COLOR"):
            return False
        if environment_value("NETRUNE_PROGRESS", "NETOPS_PROGRESS", "1") == "0":
            return False
        return sys.stderr.isatty()

    @staticmethod
    def _progress_width() -> int:
        """Width available for one status line, leaving the last cell free.

        Writing into the final column makes a terminal wrap, which turns the
        transient status line into a permanent one that obstructs output.
        """
        try:
            columns = os.get_terminal_size(sys.stderr.fileno()).columns
        except (OSError, ValueError, AttributeError):
            columns = 80
        return max(20, columns - 1)

    def _progress_update(self, message: str, opts: Optional[GlobalOptions] = None) -> None:
        if not self._progress_enabled(opts):
            return
        text = strip_ansi(str(message)).replace("\n", " ").strip()
        if not text.startswith("["):
            text = "[STATUS] " + text
        width = self._progress_width()
        if len(text) > width:
            text = text[: max(1, width - 1)] + "…"
        sys.stderr.write("\r\033[2K" + text)
        sys.stderr.flush()
        App._progress_active = True

    def _progress_clear(self, opts: Optional[GlobalOptions] = None) -> None:
        if not App._progress_active:
            return
        App._progress_active = False
        if not self._progress_enabled(opts):
            return
        sys.stderr.write("\r\033[2K")
        sys.stderr.flush()

    def _progress_step(
        self,
        scope: str,
        detail: str,
        current: int,
        total: int,
        opts: Optional[GlobalOptions] = None,
    ) -> None:
        """Render the standard counted status line for a multi-item run."""
        parts = [f"[STATUS] {scope}"]
        if detail:
            parts.append(detail)
        if total:
            parts.append(f"{current}/{total}")
        parts.append("Ctrl+C cancels")
        self._progress_update(" | ".join(parts), opts)

    def _select_row(self, rows: List[Dict[str, Any]], opts: GlobalOptions, *, label: Callable[[Dict[str, Any]], str], prompt: str) -> Optional[Dict[str, Any]]:
        """Arrow-key picker over an ambiguous match set.

        Returns the picked row, or None when this isn't a real interactive
        terminal (piped, --json, --plain, non-tty) or the user cancelled --
        both cases the caller should treat exactly like "no pick happened"
        and fall back to whatever it already did before this existed.
        """
        if opts.json or opts.plain or not sys.stdin.isatty() or not sys.stdout.isatty():
            return None
        rows = rows[:20]
        texts = [label(row) for row in rows]
        index = 0
        color = self._color_enabled()
        def render(first: bool) -> None:
            if not first:
                sys.stdout.write(f"\033[{len(texts)}A")
            for i, text in enumerate(texts):
                pointer = "> " if i == index else "  "
                line = pointer + (Style.parse("bold cyan").render(text) if color and i == index else text)
                sys.stdout.write("\033[2K" + line + "\n")
            sys.stdout.flush()
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        picked: Optional[Dict[str, Any]] = None
        try:
            tty.setcbreak(fd)
            print(f"{prompt} (↑/↓ and Enter to choose, q to cancel)")
            render(first=True)
            while True:
                ch = os.read(fd, 1)
                if ch == b"\x1b":
                    rest = os.read(fd, 2)
                    if rest == b"[A":
                        index = (index - 1) % len(texts)
                    elif rest == b"[B":
                        index = (index + 1) % len(texts)
                    else:
                        break
                    render(first=False)
                elif ch in (b"\r", b"\n"):
                    picked = rows[index]
                    break
                elif ch in (b"q", b"Q", b"\x03"):
                    break
        except KeyboardInterrupt:
            picked = None
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
            sys.stdout.write(f"\033[{len(texts)}A")
            for _ in texts:
                sys.stdout.write("\033[2K\n")
            sys.stdout.write(f"\033[{len(texts)}A")
            sys.stdout.flush()
        return picked

    def run_subprocess(self, cmd: List[str], opts: GlobalOptions, input_text: Optional[str]=None) -> int:
        if opts.dry_run: self.emit({"dry_run":True,"command":shlex.join(cmd)}, opts, shlex.join(cmd)); return SUCCESS
        proc = None; started = time.monotonic(); progress = self._progress_enabled(opts)
        if Path(cmd[0]).name in {"netrune-probe", "netrune-connect", "gateprober"}:
            progress = False
        try:
            proc = subprocess.Popen(cmd, stdin=subprocess.PIPE if input_text is not None else None, text=True, start_new_session=True, env=self.child_env(opts))
            if input_text is not None and proc.stdin is not None:
                try: proc.stdin.write(input_text); proc.stdin.close()
                except BrokenPipeError: pass
            while True:
                try:
                    code = normalized_exit_code(proc.wait(timeout=0.5))
                    self._terminate_process_group(proc, signal.SIGTERM, 0.25)
                    return code
                except subprocess.TimeoutExpired:
                    elapsed = time.monotonic() - started
                    if opts.timeout and elapsed >= opts.timeout:
                        raise
                    if progress:
                        self._progress_update(f"running {Path(cmd[0]).name} | {int(elapsed)}s | Ctrl+C cancels", opts)
        except subprocess.TimeoutExpired:
            self._terminate_process_group(proc, signal.SIGTERM, 2)
            eprint(f"[ERROR] timed out: {shlex.join(cmd)}"); return TIMEOUT
        except KeyboardInterrupt:
            self._terminate_process_group(proc, signal.SIGINT, 1.5)
            return 130
        except FileNotFoundError: eprint(f"[ERROR] missing helper: {cmd[0]}"); return UNSUPPORTED
        finally:
            self._progress_clear(opts)
    def run_interactive(self, cmd: List[str], opts: GlobalOptions) -> int:
        if opts.dry_run: self.emit({"dry_run":True,"command":shlex.join(cmd)}, opts, shlex.join(cmd)); return SUCCESS
        proc: Optional[subprocess.Popen] = None
        started = time.monotonic()
        try:
            proc = subprocess.Popen(cmd, env=self.child_env(opts), start_new_session=True)
            while True:
                try:
                    code = normalized_exit_code(proc.wait(timeout=0.5))
                    self._terminate_process_group(proc, signal.SIGTERM, 0.25)
                    return code
                except subprocess.TimeoutExpired:
                    if opts.timeout and (time.monotonic() - started) >= opts.timeout:
                        self._terminate_process_group(proc, signal.SIGTERM, 2)
                        eprint(f"[ERROR] timed out: {shlex.join(cmd)}")
                        return TIMEOUT
        except KeyboardInterrupt:
            self._terminate_process_group(proc, signal.SIGINT, 1.5)
            return 130
        except FileNotFoundError:
            eprint(f"Missing helper: {cmd[0]}"); return UNSUPPORTED

    def run_vault_interactive(self, cmd: List[str], opts: GlobalOptions) -> int:
        """Run a vault-aware helper in the foreground so PAM retains its tty ticket."""
        if opts.dry_run:
            self.emit({"dry_run": True, "command": shlex.join(cmd)}, opts, shlex.join(cmd))
            return SUCCESS
        proc: Optional[subprocess.Popen] = None
        started = time.monotonic()

        def stop_child(sig: int, wait: float) -> None:
            if not proc or proc.poll() is not None:
                return
            with contextlib.suppress(ProcessLookupError):
                proc.send_signal(sig)
            try:
                proc.wait(timeout=wait)
                return
            except subprocess.TimeoutExpired:
                pass
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            with contextlib.suppress(Exception):
                proc.wait(timeout=0.5)

        try:
            proc = subprocess.Popen(cmd, env=self.child_env(opts), start_new_session=False)
            while True:
                try:
                    return normalized_exit_code(proc.wait(timeout=0.5))
                except subprocess.TimeoutExpired:
                    if opts.timeout and (time.monotonic() - started) >= opts.timeout:
                        stop_child(signal.SIGTERM, 2)
                        eprint(f"[ERROR] timed out: {shlex.join(cmd)}")
                        return TIMEOUT
        except KeyboardInterrupt:
            # The terminal sends SIGINT to both Netrune and its foreground helper.
            stop_child(signal.SIGINT, 1.5)
            return 130
        except FileNotFoundError:
            eprint(f"Missing helper: {cmd[0]}")
            return UNSUPPORTED

    def capture(self, cmd: List[str], timeout: int=120, opts: Optional[GlobalOptions]=None) -> Tuple[int,str,str]:
        proc: Optional[subprocess.Popen] = None
        try:
            proc = subprocess.Popen(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True, env=self.child_env(opts or GlobalOptions()))
            out, err = proc.communicate(timeout=timeout)
            code = normalized_exit_code(proc.returncode)
            self._terminate_process_group(proc, signal.SIGTERM, 0.25)
            return code, out or "", err or ""
        except subprocess.TimeoutExpired:
            self._terminate_process_group(proc, signal.SIGTERM, 2)
            self._terminate_process_group(proc, signal.SIGKILL, 1)
            out = ""; err = "timeout"
            if proc:
                with contextlib.suppress(Exception):
                    extra_out, extra_err = proc.communicate(timeout=1); out = extra_out or ""; err = extra_err or err
            return TIMEOUT, out, err
        except KeyboardInterrupt:
            self._terminate_process_group(proc, signal.SIGINT, 1.5)
            raise
        except FileNotFoundError as exc: return UNSUPPORTED,"",str(exc)
    def capture_streamed(self, cmd: List[str], timeout: int=0, opts: Optional[GlobalOptions]=None) -> Tuple[int,str,str]:
        """Capture stdout while forwarding stderr progress immediately."""
        proc: Optional[subprocess.Popen] = None
        stdout_lines: List[str] = []
        stderr_lines: List[str] = []
        try:
            proc = subprocess.Popen(
                cmd,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=1,
                start_new_session=True,
                env=self.child_env(opts or GlobalOptions()),
            )
            def drain(stream: Any, rows: List[str], forward: bool = False) -> None:
                if stream is None:
                    return
                for line in iter(stream.readline, ""):
                    rows.append(line)
                    if forward:
                        print(line.rstrip("\n"), file=sys.stderr, flush=True)
                stream.close()
            out_thread = threading.Thread(target=drain, args=(proc.stdout, stdout_lines), daemon=True)
            err_thread = threading.Thread(target=drain, args=(proc.stderr, stderr_lines, True), daemon=True)
            out_thread.start(); err_thread.start()
            started = time.monotonic()
            timed_out = False
            while proc.poll() is None:
                if timeout and time.monotonic() - started >= timeout:
                    self._terminate_process_group(proc, signal.SIGTERM, 2)
                    stderr_lines.append("timeout\n")
                    timed_out = True
                    break
                time.sleep(0.1)
            # A helper that exits while leaving descendants behind can keep
            # inherited pipes and reader threads alive indefinitely.
            self._terminate_process_group(proc, signal.SIGTERM, 0.25)
            out_thread.join(timeout=2); err_thread.join(timeout=2)
            code = TIMEOUT if timed_out else normalized_exit_code(proc.returncode)
            return code, "".join(stdout_lines), "".join(stderr_lines)
        except KeyboardInterrupt:
            self._terminate_process_group(proc, signal.SIGINT, 1.5)
            raise
        except FileNotFoundError as exc:
            return UNSUPPORTED, "", str(exc)
    def _wrap(self, text: str, indent: str = "    ", width: int = 88) -> List[str]:
        return textwrap.wrap(str(text), width=width, initial_indent=indent, subsequent_indent=indent) or [indent]

    def _actions_for(self, noun: str) -> Dict[str, Any]:
        return HELP_TOPICS.get(noun, {}).get("actions", {})

    def _usage_line(self, noun: str = "", action: str = "") -> str:
        if noun and action:
            return self._actions_for(noun).get(action, {}).get("usage", HELP_TOPICS.get(noun, {}).get("usage", "netrune <domain> <action> [arguments]"))
        if noun:
            return HELP_TOPICS.get(noun, {}).get("usage", f"netrune {noun} <action> [arguments]")
        return "netrune <domain> <action> [arguments] [global flags]"

    def _examples_for(self, noun: str = "", action: str = "") -> List[str]:
        if noun and action:
            return list(self._actions_for(noun).get(action, {}).get("examples", []))[:4]
        if noun:
            out: List[str] = []
            for doc in self._actions_for(noun).values():
                out.extend(doc.get("examples", [])[:1])
            return out[:4]
        return ["netrune inventory list ZONE10", "netrune health offline", "netrune memory switch ZONE10", "netrune help diagnose interface"]

    def _legacy_suggestion(self, noun: str, args: Sequence[str]) -> str:
        if noun in {"discover", "discovery"}:
            if "--details" in args or "details" in args:
                key = "--details" if "--details" in args else "details"
                idx = list(args).index(key)
                target = args[idx + 1] if idx + 1 < len(args) else "<target>"
                return f"netrune inventory details {target}"
            if "--aps" in args or "aps" in args:
                return "netrune ap scan"
            if "--topology" in args or "topology" in args:
                key = "--topology" if "--topology" in args else "topology"
                idx = list(args).index(key)
                target = args[idx + 1] if idx + 1 < len(args) else "<target>"
                return f"netrune topology show {target}"
        return LEGACY_NOUN_HINTS.get(noun, "")

    def _suggest(self, value: str, choices: Sequence[str]) -> str:
        if not value:
            return ""
        matches = difflib.get_close_matches(value, list(choices), n=1, cutoff=0.55)
        return matches[0] if matches else ""

    def _verb_suggestion(self, noun: str, verb: str) -> str:
        alias = VERB_ALIASES.get(noun, {}).get(verb)
        if alias:
            if " " in alias:
                return f"netrune {alias}"
            return f"netrune {noun} {alias}"
        close = self._suggest(verb, self._actions_for(noun).keys())
        return f"netrune {noun} {close}" if close else f"netrune help {noun}"

    def usage_error(self, noun: str, action: str, opts: GlobalOptions, message: str, suggestion: str = "", code: int = USAGE) -> int:
        usage = self._usage_line(noun, action)
        examples = self._examples_for(noun, action)
        payload = {"ok": False, "error": message, "usage": usage, "suggestion": suggestion, "examples": examples, "exit_code": code}
        if opts.json:
            print(json_dumps(payload))
        else:
            color = self._color_enabled(sys.stderr)
            def label(text: str, style: str) -> str:
                return Style.parse(style).render(text) if color else text
            eprint(f"{label('Error:', 'bold red')} {message}")
            if suggestion:
                eprint(f"{label('Try:', 'bold cyan')} {suggestion}")
            eprint(f"{label('Usage:', 'bold')} {usage}")
            if examples:
                eprint(label("Examples:", "bold"))
                for ex in examples[:3]:
                    eprint(f"  {ex}")
            if noun:
                eprint(f"{label('Help:', 'dim')} netrune help {noun}" + (f" {action}" if action else ""))
            else:
                eprint(f"{label('Help:', 'dim')} netrune help")
        return code

    def unknown_action(self, noun: str, verb: str, opts: GlobalOptions) -> int:
        return self.usage_error(noun, "", opts, f"Unknown {noun} action: {verb}", self._verb_suggestion(noun, verb))

    @staticmethod
    def _action_gist(doc: Mapping[str, Any]) -> str:
        return action_gist(doc)

    def handle_help(self, noun: str, args: List[str], opts: GlobalOptions) -> bool:
        if not args:
            return False
        if args[0] in {"-h", "--help", "help"}:
            self.cmd_help(noun, args[1] if len(args) > 1 else "", opts)
            return True
        if len(args) > 1 and args[1] in {"-h", "--help", "help"}:
            self.cmd_help(noun, args[0], opts)
            return True
        return False

    def cmd_help(self, noun: str = "", action: str = "", opts: Optional[GlobalOptions] = None) -> None:
        opts = opts or GlobalOptions()
        noun = (noun or "").strip()
        action = (action or "").strip()
        if noun in {"-h", "--help", "help"}:
            noun, action = action, ""
        if noun in LEGACY_NOUN_HINTS:
            payload = {"ok": True, "legacy": noun, "replacement": LEGACY_NOUN_HINTS[noun]}
            if opts.json:
                print(json_dumps(payload))
            else:
                print(f"`netrune {noun}` is legacy. Use: {LEGACY_NOUN_HINTS[noun]}")
            return
        if noun and noun not in HELP_TOPICS:
            suggestion = self._suggest(noun, HELP_TOPICS.keys())
            payload = {"ok": False, "error": f"Unknown help topic: {noun}", "suggestion": f"netrune help {suggestion}" if suggestion else "netrune help"}
            if opts.json:
                print(json_dumps(payload))
            else:
                print(payload["error"])
                print(f"Try: {payload['suggestion']}")
            return
        if opts.json:
            if noun and action:
                doc = self._actions_for(noun).get(action)
                print(json_dumps({"ok": bool(doc), "noun": noun, "action": action, "help": doc or {}, "global_flags": GLOBAL_FLAG_HELP}))
            elif noun:
                print(json_dumps({"ok": True, "noun": noun, "help": HELP_TOPICS[noun], "global_flags": GLOBAL_FLAG_HELP}))
            else:
                print(json_dumps({"ok": True, "version": VERSION, "topics": HELP_TOPICS, "global_flags": GLOBAL_FLAG_HELP, "exit_codes": EXIT_CODE_HELP}))
            return
        color = self._color_enabled()
        def label(text: str) -> str:
            return Style.parse("bold").render(text) if color else text
        def command(text: str) -> str:
            return Style.parse("bold cyan").render(text) if color else text
        if not noun:
            print(label(f"Netrune Platform v{VERSION}"))
            print("")
            print(label("Usage:"))
            print("  netrune <domain> <action> [arguments] [global flags]")
            print("  netrune help <domain> [action]")
            print("  netrune <domain> <action> --help")
            print("")
            print(label("Domains:"))
            for key, topic in HELP_TOPICS.items():
                actions = ", ".join(topic.get("actions", {}).keys())
                print(f"  {command(key.ljust(11))} {topic['summary']}")
                print(f"              actions: {actions}")
            print("")
            print(label("Common examples:"))
            for ex in self._examples_for():
                print(f"  {ex}")
            print("")
            print(label("Global flags:"))
            for flag, desc in GLOBAL_FLAG_HELP:
                print(f"  {flag:<16} {desc}")
            print("")
            print(label("Exit codes: ") + ", ".join(f"{code} {name}" for code, name in EXIT_CODE_HELP))
            return
        topic = HELP_TOPICS[noun]
        actions = topic.get("actions", {})
        if action:
            if action not in actions:
                suggestion = self._verb_suggestion(noun, action)
                print(f"Unknown {noun} action: {action}")
                print(f"Try: {suggestion}")
                print(f"Help: netrune help {noun}")
                return
            doc = actions[action]
            print(command(f"netrune {noun} {action}"))
            print("")
            print(label("Usage:"))
            print(f"  {doc.get('usage', self._usage_line(noun, action))}")
            print("")
            print(label("Purpose:"))
            for line in self._wrap(doc.get("about", "")):
                print(line)
            if doc.get("args"):
                print("")
                print(label("Arguments:"))
                width = max(16, *(len(arg["name"]) for arg in doc["args"]))
                for arg in doc["args"]:
                    print(f"  {arg['name']:<{width}} {arg['text']}")
            if doc.get("options"):
                print("")
                print(label("Options:"))
                for opt in doc["options"]:
                    print(f"  {opt['name']:<16} {opt['text']}")
            if doc.get("examples"):
                print("")
                print(label("Examples:"))
                for ex in doc["examples"]:
                    print(f"  {ex}")
            print("")
            print("Global help: netrune help")
            return
        print(command(f"netrune {noun}"))
        print("")
        print(topic["summary"])
        print("")
        print(label("Usage:"))
        print(f"  {topic.get('usage', self._usage_line(noun))}")
        print("")
        print(label("Actions:"))
        for name, doc in actions.items():
            print(f"  {name:<15} {action_gist(doc)}")
        print("")
        print(label("Examples:"))
        for ex in self._examples_for(noun):
            print(f"  {ex}")
        print("")
        print(f"Action help: netrune help {noun} <action>")

    def dispatch(self, argv: List[str]) -> int:
        opts,args=parse_global(argv)
        if not args:
            self.cmd_help(opts=opts); return SUCCESS
        if args[0] in {"--version", "version"}:
            if opts.json:
                print(json_dumps({"name": "Netrune", "version": VERSION, "schema_version": SCHEMA_VERSION}))
            else:
                print(f"Netrune {VERSION}")
            return SUCCESS
        if args[0] in {"-h", "--help"}:
            self.cmd_help(opts=opts); return SUCCESS
        if args[0] == "help":
            self.cmd_help(args[1] if len(args) > 1 else "", args[2] if len(args) > 2 else "", opts); return SUCCESS
        noun=args.pop(0)
        try:
            if noun == "ghoster":
                noun = "path"
                args.insert(0, "inspect")
            table={"init":self.cmd_init,"setup":self.cmd_setup,"profile":self.cmd_profile,"config":self.cmd_config,"secrets":self.cmd_secrets,"ingest":self.cmd_ingest,"plugin":self.cmd_plugin,"path":self.cmd_path,"excel":self.cmd_excel,"traffic":self.cmd_traffic,"support":self.cmd_support,"inventory":self.cmd_inventory,"ap":self.cmd_ap,"topology":self.cmd_topology,"memory":self.cmd_memory,"health":self.cmd_health,"backup":self.cmd_backup,"device":self.cmd_device,"vault":self.cmd_vault,"vlan":self.cmd_vlan,"lookup":self.cmd_lookup,"diagnose":self.cmd_diagnose,"workflow":self.cmd_workflow,"commands":self.cmd_commands,"ask":self.cmd_ask,"db":self.cmd_db}
            if noun not in table:
                legacy = self._legacy_suggestion(noun, args)
                if legacy:
                    return self.usage_error("", "", opts, f"`netrune {noun}` is legacy or not a current domain.", legacy)
                close = self._suggest(noun, table.keys())
                suggestion = f"netrune {close}" if close else "netrune help"
                return self.usage_error("", "", opts, f"Unknown Netrune domain: {noun}", suggestion)
            try:
                return table[noun](args, opts)
            finally:
                # Any command that changed inventory owes the shell helpers a
                # refreshed flat export. Doing it here means no call site has
                # to remember, which is what went wrong before.
                self.state.flush_inventory_exports()
        except KeyboardInterrupt: eprint("Interrupted."); return 130
        except Exception as exc:
            if opts.json: print(json_dumps({"ok":False,"error":str(exc),"exit_code":INTERNAL}))
            else: eprint(f"Error: {exc}")
            return INTERNAL

    def cmd_init(self, args: List[str], opts: GlobalOptions) -> int:
        if self.handle_help("init", args, opts): return SUCCESS
        profile = self.paths.profile
        migrate = "--migrate-legacy" in args
        checks = []
        for command, required, capability in (
            ("ssh", True, "device access"),
            ("ping", True, "local reachability diagnostics"),
            ("ip", True, "Linux route and interface diagnostics"),
            ("gpg", False, "encrypted named secrets"),
            ("sudo", False, "PAM-gated vault authentication"),
            ("snmpwalk", False, "legacy SNMP discovery"),
            ("iperf3", False, "controlled throughput tests"),
            ("speedtest", False, "Internet speed tests"),
            ("traceroute", False, "Layer 3 route diagnostics"),
            ("ethtool", False, "local interface diagnostics"),
        ):
            location = shutil.which(command)
            checks.append({"command": command, "required": required, "available": bool(location), "path": location or "", "capability": capability})
        migration = self.profile_store.migrate_legacy("legacy-local") if migrate else None
        next_commands = ["netrune config show"]
        if not valid_ssh_username(self.config.public.get("ssh_user") or self.config.secret.get("ssh_user")):
            next_commands.append("netrune config set ssh_user <username>")
        next_commands.extend(["netrune ingest channels", "netrune diagnose doctor"])
        payload = {
            "ok": all(row["available"] for row in checks if row["required"]),
            "profile": profile,
            "paths": self.paths.profile_layout.to_dict(),
            "checks": checks,
            "migration": migration,
            "next_commands": next_commands,
        }
        missing = [row["command"] for row in checks if row["required"] and not row["available"]]
        text = (
            f"Netrune profile initialized: {profile}\n"
            f"Config: {self.paths.config_dir}\nState: {self.paths.state_dir}\nCache: {self.paths.cache_dir}\n\n"
            + self.render_table(checks, ["command", "required", "available", "capability"])
            + (f"\n\nMissing required tools: {', '.join(missing)}" if missing else "\n\nRequired capabilities are available.")
            + "\n\nNext:\n" + "\n".join(f"  {command}" for command in next_commands)
        )
        self.emit(payload, opts, text)
        return SUCCESS if payload["ok"] else PARTIAL

    def cmd_profile(self, args: List[str], opts: GlobalOptions) -> int:
        if self.handle_help("profile", args, opts): return SUCCESS
        verb = args[0] if args else "list"
        rest = args[1:]
        if verb == "list":
            rows = self.profile_store.list()
            self.emit({"ok": True, "active": self.profile_store.active(), "rows": rows}, opts, self.render_table(rows, ["active", "name", "configured", "updated_at"]))
            return SUCCESS
        if verb in {"show", "status"}:
            name = rest[0] if rest else self.paths.profile
            payload = self.profile_store.show(name)
            self.emit({"ok": True, **payload}, opts, self.render_plain(payload))
            return SUCCESS
        if verb == "create":
            if not rest: return self.usage_error("profile", "create", opts, "Missing profile name.", "netrune profile create lab", VALIDATION)
            layout = self.profile_store.ensure(rest[0])
            payload = {"ok": True, "created": layout.name, "layout": layout.to_dict()}
            self.emit(payload, opts, f"Profile ready: {layout.name}\nConfig: {layout.config_dir}")
            return SUCCESS
        if verb == "use":
            if not rest: return self.usage_error("profile", "use", opts, "Missing profile name.", "netrune profile use default", VALIDATION)
            layout = self.profile_store.use(rest[0])
            self.emit({"ok": True, "active": layout.name, "layout": layout.to_dict()}, opts, f"Active profile: {layout.name}\nNew processes will use {layout.config_dir}")
            return SUCCESS
        if verb in {"migrate", "migrate-legacy", "export-legacy"}:
            destination = rest[0] if rest else "legacy-local"
            payload = self.profile_store.migrate_legacy(destination)
            database_action = payload["database_migration"]["action"]
            self.emit({"ok": True, **payload}, opts, f"Legacy migration prepared private profile {destination}. Original files were not changed.\nDatabase: {database_action} | Copied: {len(payload['copied'])} | Skipped: {len(payload['skipped'])} | Pending named secrets: {len(payload['pending_secret_names'])}")
            return SUCCESS
        if verb == "paths":
            payload = self.paths.profile_layout.to_dict()
            self.emit({"ok": True, "profile": self.paths.profile, "paths": payload}, opts, "\n".join(f"{key}: {value}" for key, value in payload.items()))
            return SUCCESS
        return self.unknown_action("profile", verb, opts)

    def _write_profile_config_value(self, key: str, value: Optional[str]) -> None:
        if not re.fullmatch(r"[a-z][a-z0-9_]{1,63}", key):
            raise ValueError("configuration keys use lowercase letters, digits, and underscores")
        if SECRET_KEY_RE.search(key):
            raise ValueError("secret values must be stored with 'netrune secrets set'")
        if value is not None and any(character in value for character in "\r\n\x00"):
            raise ValueError("configuration values cannot contain control lines")
        current = read_kv(self.paths.config_file)
        if value is None:
            current.pop(key, None)
        else:
            current[key] = value
        lines = ["# Netrune profile compatibility configuration"] + [f"{name}={current[name]}" for name in sorted(current)]
        # Keep the copy already in memory in step with the file. Anything that
        # writes a setting and then acts on it in the same process -- 'setup'
        # does exactly that -- would otherwise act on the value it started with.
        if value is None:
            self.config.public.pop(key, None)
        else:
            self.config.public[key] = value
        staged = self.paths.config_file.with_name(f".{self.paths.config_file.name}.{os.getpid()}.tmp")
        staged.write_text("\n".join(lines) + "\n", encoding="utf-8")
        staged.chmod(0o600)
        os.replace(staged, self.paths.config_file)

    def cmd_config(self, args: List[str], opts: GlobalOptions) -> int:
        if self.handle_help("config", args, opts): return SUCCESS
        verb = args[0] if args else "show"
        rest = args[1:]
        if verb == "show":
            payload = {
                "ok": True,
                "profile": self.paths.profile,
                "precedence": ["CLI", "environment", "active profile", "global config", "neutral defaults"],
                "settings": self.config.public_safe(),
                "profile_file": str(self.paths.profile_file),
                "compatibility_file": str(self.paths.config_file),
            }
            self.emit(payload, opts, f"Profile: {self.paths.profile}\n" + self.render_table([{"key": key, "value": value} for key, value in sorted(payload["settings"].items())], ["key", "value"]))
            return SUCCESS
        if verb == "get":
            if not rest: return self.usage_error("config", "get", opts, "Missing key.", "netrune config get core_switch_ip", VALIDATION)
            key = rest[0]
            if key not in self.config.public: return self.usage_error("config", "get", opts, f"Unknown configuration key: {key}", "netrune config show", VALIDATION)
            self.emit({"ok": True, "key": key, "value": self.config.public_safe().get(key)}, opts, str(self.config.public_safe().get(key, "")))
            return SUCCESS
        if verb == "set":
            if len(rest) < 2: return self.usage_error("config", "set", opts, "Provide a key and value.", "netrune config set core_switch_ip 192.0.2.10", VALIDATION)
            self._write_profile_config_value(rest[0], " ".join(rest[1:]))
            self.emit({"ok": True, "profile": self.paths.profile, "key": rest[0], "updated": True}, opts, f"Updated {rest[0]} in profile {self.paths.profile}.")
            return SUCCESS
        if verb == "unset":
            if not rest: return self.usage_error("config", "unset", opts, "Missing key.", "netrune config unset target_abbreviation_prefix", VALIDATION)
            self._write_profile_config_value(rest[0], None)
            self.emit({"ok": True, "profile": self.paths.profile, "key": rest[0], "removed": True}, opts, f"Removed profile override: {rest[0]}")
            return SUCCESS
        if verb in {"path", "paths"}:
            payload = {"global": str(self.paths.config_root / "config.toml"), "profile": str(self.paths.profile_file), "compatibility": str(self.paths.config_file)}
            self.emit({"ok": True, **payload}, opts, "\n".join(f"{key}: {value}" for key, value in payload.items()))
            return SUCCESS
        if verb == "validate":
            findings = []
            prefix = str(self.config.public.get("target_abbreviation_prefix") or "").strip().strip(".")
            if prefix:
                try:
                    parts = [int(value) for value in prefix.split(".")]
                    if not 1 <= len(parts) <= 3 or any(value < 0 or value > 255 for value in parts): raise ValueError
                except ValueError:
                    findings.append({"severity": "error", "key": "target_abbreviation_prefix", "detail": "must contain one to three IPv4 octets"})
            if self.paths.env_file.exists() and read_kv(self.paths.env_file):
                findings.append({"severity": "warning", "key": "legacy .env", "detail": "plaintext legacy credentials remain; migrate them to named secrets"})
            ssh_user = str(self.config.public.get("ssh_user") or self.config.secret.get("ssh_user") or "")
            if not ssh_user:
                findings.append({"severity": "warning", "key": "ssh_user", "detail": "required for device SSH; set with 'netrune config set ssh_user <username>'"})
            elif not valid_ssh_username(ssh_user):
                findings.append({"severity": "error", "key": "ssh_user", "detail": "must be 1-255 characters without whitespace"})
            certified_firmware = str(self.config.public.get("device_certified_firmware") or "").strip()
            if certified_firmware:
                known_families = {driver.family for driver in self.device_drivers.all()}
                for entry in certified_firmware.split(","):
                    entry = entry.strip()
                    if not entry:
                        continue
                    if ":" not in entry:
                        findings.append({"severity": "error", "key": "device_certified_firmware", "detail": f"entry {entry!r} must be family:pattern"})
                        continue
                    family, _, pattern = entry.partition(":")
                    family, pattern = family.strip(), pattern.strip()
                    if family not in known_families:
                        findings.append({"severity": "error", "key": "device_certified_firmware", "detail": f"unknown driver family {family!r}; run 'netrune device support' to list known families"})
                    if not pattern:
                        findings.append({"severity": "error", "key": "device_certified_firmware", "detail": f"entry for {family!r} has an empty pattern"})
                    else:
                        try:
                            re.compile(pattern)
                        except re.error as exc:
                            findings.append({"severity": "error", "key": "device_certified_firmware", "detail": f"invalid regex for {family!r}: {exc}"})
            certified_firmware_min = str(self.config.public.get("device_certified_firmware_min") or "").strip()
            if certified_firmware_min:
                known_families = {driver.family for driver in self.device_drivers.all()}
                for entry in certified_firmware_min.split(","):
                    entry = entry.strip()
                    if not entry:
                        continue
                    if ":" not in entry:
                        findings.append({"severity": "error", "key": "device_certified_firmware_min", "detail": f"entry {entry!r} must be family:X.Y"})
                        continue
                    family, _, floor_text = entry.partition(":")
                    family, floor_text = family.strip(), floor_text.strip()
                    if family not in known_families:
                        findings.append({"severity": "error", "key": "device_certified_firmware_min", "detail": f"unknown driver family {family!r}; run 'netrune device support' to list known families"})
                    if not re.match(r"^\d{1,3}\.\d{1,3}$", floor_text):
                        findings.append({"severity": "error", "key": "device_certified_firmware_min", "detail": f"entry for {family!r} must be a major.minor version number, e.g. 12.0 (got {floor_text!r})"})
            payload = {"ok": not any(row["severity"] == "error" for row in findings), "profile": self.paths.profile, "findings": findings}
            self.emit(payload, opts, self.render_table(findings, ["severity", "key", "detail"]) if findings else "Configuration is valid.")
            return SUCCESS if payload["ok"] else VALIDATION
        return self.unknown_action("config", verb, opts)

    def cmd_secrets(self, args: List[str], opts: GlobalOptions) -> int:
        if self.handle_help("secrets", args, opts): return SUCCESS
        verb = args[0] if args else "list"
        rest = args[1:]
        helper = self.paths.tool("netrune-connect")
        mapping = {
            "list": [helper, "--secret-list"],
            "status": [helper, "--secret-status"],
            "import-ssh": [helper, "--secret-import-ssh"],
        }
        if verb == "set":
            if not rest: return self.usage_error("secrets", "set", opts, "Missing secret name.", "netrune secrets set snmp/site-a/auth", VALIDATION)
            mapping[verb] = [helper, "--secret-set", rest[0]]
        elif verb in {"delete", "remove"}:
            if not rest: return self.usage_error("secrets", "delete", opts, "Missing secret name.", "netrune secrets delete snmp/site-a/auth", VALIDATION)
            name = rest[0]
            _, listing, _ = self.capture([helper, "--secret-list"], opts=opts)
            recorded = ""
            found = False
            for line in listing.splitlines()[1:]:
                row_name, _, row_recorded = line.partition("|")
                if row_name == name:
                    found, recorded = True, row_recorded
                    break
            if not found:
                return self.usage_error("secrets", "delete", opts, f"No named secret '{name}' is recorded.", "netrune secrets list", VALIDATION)
            if not opts.confirm:
                self.emit(
                    {"ok": False, "requires_confirm": True, "name": name, "recorded": recorded}, opts,
                    f"Would delete secret: {name} (recorded {recorded}).\n"
                    "This cannot be undone; the value is not backed up anywhere.\n"
                    f"Re-run with --confirm: netrune secrets delete {name} --confirm")
                return VALIDATION
            rc = self.run_subprocess([helper, "--secret-delete", name], opts)
            self.state.record_audit_event("secrets", "secret-delete", result=("success" if rc == SUCCESS else "failed"),
                                          target=name, detail={"recorded": recorded})
            return rc
        if verb not in mapping:
            return self.unknown_action("secrets", verb, opts)
        return self.run_subprocess(mapping[verb], opts)

    def cmd_ingest(self, args: List[str], opts: GlobalOptions) -> int:
        if self.handle_help("ingest", args, opts): return SUCCESS
        verb = args[0] if args else "channels"
        rest = args[1:]
        if verb in {"channels", "list"}:
            rows = self.ingest_manager.sync_channels()
            ok = not any(row.get("status") == "invalid" for row in rows)
            self.emit({"ok": ok, "profile": self.paths.profile, "rows": rows}, opts, self.render_table(rows, ["status", "enabled", "name", "kind", "entity_kind", "manifest_path", "updated_at", "error"]))
            return SUCCESS if ok else PARTIAL
        if verb == "validate":
            rows = [{key: value for key, value in row.items() if key != "manifest"} for row in self.ingest_manager.validation()]
            ok = all(row["status"] == "valid" for row in rows)
            self.emit({"ok": ok, "rows": rows}, opts, self.render_table(rows, ["status", "name", "kind", "path", "error"]) if rows else "No ingest channel manifests found.")
            return SUCCESS if ok else VALIDATION
        if verb == "run":
            if not rest: return self.usage_error("ingest", "run", opts, "Missing channel name.", "netrune ingest run inventory-csv", VALIDATION)
            try:
                result = self.ingest_manager.run(rest[0], stdin=sys.stdin if not sys.stdin.isatty() else None)
            except ValueError as exc:
                return self.usage_error("ingest", "run", opts, str(exc), "netrune ingest validate", VALIDATION)
            payload = result.to_dict()
            if result.accepted:
                payload["reconciliation"] = self.state.sync_derived_state()
            self.emit({"ok": result.status in {"completed", "partial"}, **payload}, opts, f"Ingest {result.channel}: {result.status}\nReceived: {result.received} | Accepted: {result.accepted} | Duplicates: {result.duplicates} | Rejected: {result.rejected}\nRun: {result.run_id} | Recorded: {fmt_time(result.finished_at)}" + (f"\nError: {result.message}" if result.message else ""))
            return SUCCESS if result.status == "completed" else (PARTIAL if result.status == "partial" else INTERNAL)
        if verb == "history":
            rows = timestamp_rows(self.ingest_manager.history(opts.limit))
            self.emit({"ok": True, "rows": rows, "chronology": CHRONOLOGY}, opts, self.render_table(rows, ["run_id", "channel", "status", "started_at", "finished_at", "received", "accepted", "duplicates", "rejected"]))
            return SUCCESS
        if verb == "rejects":
            rows = timestamp_rows(self.ingest_manager.rejects(rest[0] if rest else "", opts.limit))
            self.emit({"ok": True, "rows": rows, "chronology": CHRONOLOGY}, opts, self.render_table(rows, ["received_at", "run_id", "channel", "record_index", "error_code", "message"]))
            return SUCCESS
        if verb == "observations":
            channel = rest[0] if rest else ""
            rows = self.state.rows(
                "SELECT id,entity_kind,stable_source_id,channel,observed_at,received_at,completeness,status,confidence,raw_evidence_hash FROM observations "
                + ("WHERE channel=? " if channel else "") + "ORDER BY observed_at DESC,id DESC LIMIT ?",
                ((channel, opts.limit) if channel else (opts.limit,)),
            )
            rows = timestamp_rows(rows)
            # observation_fields holds the per-field detail behind each
            # observation and had no reader, so the field-level provenance the
            # ingest path records was invisible.
            fields = []
            if rows:
                placeholders = ",".join("?" for _ in rows)
                fields = self.state.rows(
                    f"SELECT observation_id,field_name,value_json,source,confidence,observed_at "
                    f"FROM observation_fields WHERE observation_id IN ({placeholders}) "
                    "ORDER BY observation_id DESC,field_name",
                    tuple(int(row["id"]) for row in rows),
                )
                by_observation: Dict[int, List[Dict[str, Any]]] = {}
                for field in fields:
                    by_observation.setdefault(int(field["observation_id"]), []).append(field)
                for row in rows:
                    row["field_count"] = len(by_observation.get(int(row["id"]), []))
            text = self.render_table(rows, ["observed_at", "entity_kind", "stable_source_id", "channel", "completeness", "status", "confidence", "field_count"])
            if fields:
                text += "\n\nField provenance\n" + self.render_table(
                    timestamp_rows(fields)[: opts.limit],
                    ["observation_id", "field_name", "source", "confidence", "observed_at"],
                )
            self.emit({"ok": True, "rows": rows, "fields": timestamp_rows(fields), "chronology": CHRONOLOGY}, opts, text)
            return SUCCESS
        return self.unknown_action("ingest", verb, opts)

    def cmd_plugin(self, args: List[str], opts: GlobalOptions) -> int:
        if self.handle_help("plugin", args, opts): return SUCCESS
        verb = args[0] if args else "list"
        rest = args[1:]
        if verb in {"list", "discover"}:
            descriptors = self.plugin_manager.discover()
            rows = [item.to_dict() for item in descriptors]
            self.emit({"ok": True, "rows": rows, "groups": list(PLUGIN_GROUPS)}, opts, self.render_table(rows, ["enabled", "load_status", "group", "name", "distribution", "version", "api_version", "error"]))
            return SUCCESS
        if verb in {"enable", "disable"}:
            if not rest: return self.usage_error("plugin", verb, opts, "Missing plugin id (<group>:<name>).", "netrune plugin list", VALIDATION)
            try:
                if opts.dry_run:
                    descriptor = self.plugin_manager.descriptor(rest[0])
                    payload = {"ok": True, "dry_run": True, "plugin": descriptor.to_dict(), "would_enable": verb == "enable"}
                    self.emit(payload, opts, f"Dry run: plugin {rest[0]} would be {'enabled' if verb == 'enable' else 'disabled'}.")
                    return SUCCESS
                descriptor = self.plugin_manager.set_enabled(rest[0], verb == "enable")
            except ValueError as exc:
                return self.usage_error("plugin", verb, opts, str(exc), "netrune plugin list", VALIDATION)
            self.emit({"ok": True, "plugin": descriptor.to_dict()}, opts, f"Plugin {rest[0]} is now {'enabled' if verb == 'enable' else 'disabled'}.")
            return SUCCESS
        if verb in {"check", "load"}:
            rows = [item.descriptor.to_dict() for item in self.plugin_manager.load_enabled(rest[0] if rest else "")]
            ok = all(row["load_status"] == "loaded" for row in rows)
            self.emit({"ok": ok, "rows": rows, "driver_manifests": self.driver_manifest_report}, opts, self.render_table(rows, ["load_status", "group", "name", "distribution", "version", "api_version", "error"]))
            return SUCCESS if ok else PARTIAL
        if verb == "groups":
            rows = [{"group": value, "policy": "trusted Python entry point; disabled until enabled; writes prohibited"} for value in PLUGIN_GROUPS]
            self.emit({"ok": True, "rows": rows}, opts, self.render_table(rows, ["group", "policy"]))
            return SUCCESS
        return self.unknown_action("plugin", verb, opts)

    @property
    def traffic(self) -> TrafficMonitor:
        if not hasattr(self, "_traffic"):
            self._traffic = TrafficMonitor(self)
        return self._traffic

    def cmd_setup(self, args: List[str], opts: GlobalOptions) -> int:
        from netops_platform.setup_cli import dispatch
        return dispatch(self, args, opts)

    def write_snmp_community(self, community: str) -> Path:
        from netops_platform.setup_cli import write_snmp_community
        return write_snmp_community(self, community)

    def cmd_traffic(self, args: List[str], opts: GlobalOptions) -> int:
        from netops_platform.traffic_cli import dispatch
        return dispatch(self, args, opts)

    def cmd_path(self, args: List[str], opts: GlobalOptions) -> int:
        from netops_platform.path_cli import dispatch
        return dispatch(self, args, opts)

    def cmd_excel(self, args: List[str], opts: GlobalOptions) -> int:
        from netops_platform.excel_cli import dispatch
        return dispatch(self, args, opts)

    def cmd_support(self, args: List[str], opts: GlobalOptions) -> int:
        if self.handle_help("support", args, opts): return SUCCESS
        verb = args[0] if args else "bundle"
        rest = args[1:]
        if verb != "bundle": return self.unknown_action("support", verb, opts)
        output = Path(rest[0]).expanduser() if rest else None
        payload = create_support_bundle(self, output)
        self.emit(payload, opts, f"Redacted support bundle: {payload['path']}\nSHA-256: {payload['sha256']}\nBytes: {payload['bytes']} | Recorded: {fmt_time(payload['recorded_at'])}\nExcluded: {', '.join(payload['excluded'])}")
        return SUCCESS

    def cmd_db(self,args:List[str],opts:GlobalOptions)->int:
        if self.handle_help("db", args, opts): return SUCCESS
        verb=args[0] if args else "status"
        if verb in {"init","migrate"}:
            payload=self.state.migrate(); payload["reconciliation"]=self.state.sync_derived_state(origin="migration"); payload["counts"]=self.state.counts()
            self.emit(payload,opts,f"SQLite ready: {self.paths.sqlite_db} (schema {payload.get('schema_version')})"); return SUCCESS
        if verb in {"import","import-flat"}: return self.cmd_inventory(["import-flat"],opts)
        if verb in {"export","export-flat"}: return self.cmd_inventory(["export-flat"],opts)
        if verb=="path": print(self.paths.sqlite_db); return SUCCESS
        if verb=="status":
            payload=self.state.db_status_payload()
            text="\n".join([f"SQLite: {payload['db_path']}", f"Schema: {payload['schema_version']} (expected {payload['expected_schema_version']})", f"Cache: {payload['cache_dir']}", f"Applied migrations: {len(payload['applied_migrations'])}"]+[f"{k}: {v}" for k,v in payload["counts"].items()]+[f"sqlite_bytes: {payload['files']['sqlite_bytes']}", f"wal_bytes: {payload['files']['wal_bytes']}"])
            self.emit(payload,opts,text); return SUCCESS
        if verb=="integrity":
            payload=self.state.integrity_check(); self.emit(payload,opts,"SQLite integrity: "+("ok" if payload.get("ok") else "failed: "+", ".join(payload.get("integrity_check") or []))); return SUCCESS if payload.get("ok") else INTERNAL
        if verb=="repair":
            payload=self.state.repair(); payload["pruned"]=self.state.prune_history(); self.emit(payload,opts,"SQLite repair complete: "+("ok" if payload.get("ok") else "integrity check failed")); return SUCCESS if payload.get("ok") else INTERNAL
        if verb=="history":
            rows=self.state.rows(
                "SELECT created_at,action,command,exit_code,read_only FROM command_history "
                "ORDER BY created_at DESC,id DESC LIMIT ?",(opts.limit,))
            self.emit({"ok":True,"rows":timestamp_rows(rows),"count":len(rows)},opts,
                      self.render_table(timestamp_rows(rows),["created_at","action","exit_code","read_only","command"]))
            return SUCCESS if rows else PARTIAL
        if verb=="prune":
            removed=self.state.prune_history()
            total=sum(removed.values())
            rows=[{"table":k,"rows_removed":v} for k,v in sorted(removed.items())]
            self.emit({"ok":True,"removed":removed,"rows_removed":total,"retention_days":self.state.RETENTION_DEFAULTS},opts,
                      (f"Pruned {total} row(s) past retention.\n"+self.render_table(rows,["table","rows_removed"])) if rows
                      else "Nothing past retention. Audit events are never pruned.")
            return SUCCESS
        if verb=="vacuum":
            payload=self.state.vacuum(); self.emit(payload,opts,f"SQLite vacuum complete: {payload.get('bytes', 0)} bytes"); return SUCCESS
        return self.unknown_action("db", verb, opts)

    def ap_rows(self,pattern:str,opts:GlobalOptions)->List[Dict[str,Any]]:
        return self.reconciled_ap_rows(pattern_or_all(pattern), opts)

    @staticmethod
    def _manual_merge_arguments(args: Sequence[str], *, expected: int) -> Tuple[List[str], str, str]:
        """Shared `--reason`/positional parsing for every manual merge/unmerge
        verb. Lives here, not in a domain mixin, because both the inventory
        (device) and AP merge commands need it and `cmd_ap` itself lives
        directly on `App`."""
        positional: List[str] = []
        reason = ""
        error = ""
        index = 0
        while index < len(args):
            value = str(args[index])
            if value == "--reason":
                if index + 1 >= len(args):
                    return positional, reason, "--reason requires text"
                reason = str(args[index + 1]).strip()
                index += 2
                continue
            if value.startswith("-"):
                return positional, reason, f"unknown option: {value}"
            if value.lower() != "into":
                positional.append(value)
            index += 1
        if len(positional) != expected:
            error = f"expected {expected} positional argument{'s' if expected != 1 else ''}"
        return positional, reason, error

    def cmd_ap(self,args:List[str],opts:GlobalOptions)->int:
        if self.handle_help("ap", args, opts): return SUCCESS
        verb=args[0] if args else "list"; rest=args[1:]
        if verb=="scan":
            rc=self.run_subprocess(self.legacy_cmd("netrune-discovery","--discover-aps"),opts)
            if rc==0 and not opts.dry_run:
                try: self.import_flat_state(("ap",), "wireless-controller-scan")
                except Exception as exc: eprint(f"Observation recording failed: {exc}"); return PARTIAL
            return rc
        if verb in {"list","show"}: rows=self.ap_rows(pattern_or_all(" ".join(rest).strip()),opts); self.emit({"ok":True,"rows":rows,"count":len(rows)},opts,self.render_table(rows,["ip","name","platform","switch_name","switch_port","status","last_seen"])); return SUCCESS
        if verb in {"unjoined","not-joined","nonjoined"}:
            pattern=" ".join(rest).strip()
            rows=reconcile_ap_rows(self.state.rows("SELECT * FROM aps WHERE lower(COALESCE(switch_port,'')) IN ('not-joined','not joined','unjoined','nonjoined') ORDER BY last_seen DESC,name"))
            if pattern: rows=[row for row in rows if ap_rows_match(row,pattern)]
            rows=rows[:opts.limit]
            self.emit({"ok":True,"rows":rows,"count":len(rows)},opts,self.render_table(rows,["ip","name","mac","switch_name","switch_port","status","last_seen"])); return SUCCESS
        if verb in {"on-switch","switch"}:
            if not rest: return self.usage_error("ap","on-switch",opts,"Missing switch target.","netrune ap on-switch ZONE10")
            return self.memory_switch(" ".join(rest),opts,aps_only=True)
        if verb=="moves": rows=self.state.rows("SELECT * FROM ap_move_events ORDER BY created_at DESC,id DESC LIMIT ?",(opts.limit,)); self.emit({"ok":True,"rows":rows},opts,self.render_table(rows,["created_at","ap_ip","ap_name","previous_switch_ip","previous_switch_port","current_switch_ip","current_switch_port"])); return SUCCESS
        if verb=="timeline": return self.relationship_timeline(rest[0] if rest else "ap_attachment",opts,rel_type="ap_attachment")
        if verb=="merge": return self.cmd_ap_merge(rest,opts)
        if verb in {"unmerge","merge-revoke"}: return self.cmd_ap_unmerge(rest,opts)
        if verb=="merges": rows=timestamp_rows(self.state.list_ap_merges(include_revoked=opts.all)); self.emit({"ok":True,"rows":rows,"count":len(rows),"chronology":CHRONOLOGY},opts,self.render_table(rows,["created_at","merge_id","source_name","source_ip","target_name","target_ip","reason","suppressed_observations","revoked_at"])); return SUCCESS
        return self.unknown_action("ap", verb, opts)

    def resolve_ap_record(self, target: str) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]]]:
        """Alias-aware AP resolver for `ap merge`/`ap unmerge`, the AP analog
        of `resolve_device_record`. Simpler than the device version -- it
        relies on `reconciled_ap_rows`' own aliasing (reconciliation plus any
        prior manual AP merge) rather than also replaying
        `inventory_identity_state`'s full historical-name index, which is a
        depth the device resolver needs for its broader "inventory list"
        role but this merge-endpoint lookup does not.
        """
        raw = self.natural_ask.apply_aliases(str(target or "").strip(), strict=True)
        normalized = normalize_target_literal(raw)
        if not normalized and not raw:
            return None, []
        needle = raw.lower().strip()
        rows = self.reconciled_ap_rows("", GlobalOptions(limit=10000))
        exact = [
            row for row in rows
            if str(row.get("ip") or "").lower() == needle
            or str(row.get("name") or "").lower() == needle
            or any(str(alias or "").lower() == needle for alias in row.get("aliases") or [])
        ]
        if len(exact) == 1:
            return exact[0], exact
        if len(exact) > 1:
            return None, exact[:20]
        if not needle:
            return None, []
        candidates = [row for row in rows if ap_rows_match(row, needle)]
        return (candidates[0], candidates) if len(candidates) == 1 else (None, candidates[:20])

    AP_MERGE_ROLE_LABELS = {"source": "old-ap", "target": "current-ap"}

    def _resolve_raw_ap_record(self, target: str) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]]]:
        normalized = normalize_target_literal(str(target or "").strip())
        raw = str(target or "").strip()
        if not normalized and not raw:
            return None, []
        rows = self.state.rows("SELECT ip,name,platform,switch_ip,switch_name,switch_port,mac,last_seen,status FROM aps ORDER BY name,ip")
        exact = [
            row for row in rows
            if str(row.get("ip") or "").lower() == normalized.lower()
            or str(row.get("name") or "").lower() == raw.lower()
        ]
        if len(exact) == 1:
            return exact[0], exact
        if len(exact) > 1:
            return None, exact[:20]
        return None, []

    def _resolve_ap_merge_endpoint(self, target: str) -> Optional[Dict[str, Any]]:
        row, raw_choices = self._resolve_raw_ap_record(target)
        if row:
            return row
        if len(raw_choices) > 1:
            return None
        reconciled, choices = self.resolve_ap_record(target)
        if len(choices) > 1:
            return None
        if reconciled:
            addresses = [reconciled.get("ip"), *(reconciled.get("addresses") or [])]
            for address in (str(value or "").strip() for value in addresses):
                if not address:
                    continue
                active = self.state.one(
                    "SELECT ip,name,platform,switch_ip,switch_name,switch_port,mac,last_seen,status FROM aps WHERE ip=?",
                    (address,),
                )
                if active:
                    return active
        # The `aps` table is replaced wholesale on every `ap scan` (it mirrors
        # a controller's current sweep), so the identity this command exists
        # to retire is routinely already gone from the live table by the time
        # an operator reviews a continuity candidate. Fall back to the
        # historical record rather than requiring the operator to race the
        # next scan.
        historical = self.state.rows(
            "SELECT ip,name,platform,switch_ip,switch_name,switch_port,mac,last_seen,status FROM inventory_identity_state "
            "WHERE entity_type='ap' AND (lower(COALESCE(name,''))=lower(?) OR COALESCE(ip,'')=?) ORDER BY last_seen DESC LIMIT 20",
            (target, normalize_target_literal(target)),
        )
        # `inventory_identity_state` keeps one row per identity_kind (ip/mac/
        # name), so the same AP shows up up to three times here -- dedupe by
        # the entity it actually describes before judging ambiguity.
        distinct = {(row.get("ip"), row.get("mac"), str(row.get("name") or "").lower()): row for row in historical}
        if len(distinct) == 1:
            return next(iter(distinct.values()))
        return None

    def _ap_merge_endpoint_detail(self, target: str, role: str) -> str:
        label = self.AP_MERGE_ROLE_LABELS.get(role, role)
        for _, choices in (self._resolve_raw_ap_record(target), self.resolve_ap_record(target)):
            if len(choices) > 1:
                names = ", ".join(str(row.get("name") or row.get("ip")) for row in choices[:8])
                more = "" if len(choices) <= 8 else f", and {len(choices) - 8} more"
                return (
                    f"The {label} '{target}' matched {len(choices)} APs: {names}{more}. "
                    "Use an exact name or management IP."
                )
        historical = self.state.one(
            "SELECT ip,name,last_seen FROM inventory_identity_state WHERE entity_type='ap' "
            "AND (lower(COALESCE(name,''))=lower(?) OR lower(COALESCE(identity_value,''))=lower(?) OR COALESCE(ip,'')=?) "
            "ORDER BY last_seen DESC LIMIT 1",
            (target, target, normalize_target_literal(target)),
        )
        if historical:
            return (
                f"The {label} '{target}' is historical memory, not an active record. It was last seen as "
                f"{historical.get('name') or historical.get('ip')} ({historical.get('ip')}) on {fmt_time(historical.get('last_seen'))}. "
                "Review 'netrune ap merges' and revoke an existing merge before retiring it again."
            )
        return f"The {label} '{target}' matched no active or historical AP record."

    def cmd_ap_merge(self, args: List[str], opts: GlobalOptions) -> int:
        positional, reason, error = self._manual_merge_arguments(args, expected=2)
        usage = "netrune ap merge <old-ap> <current-ap> --reason 'hardware replacement' --dry-run"
        if error:
            return self.usage_error("ap", "merge", opts, error, usage, VALIDATION)
        if not reason:
            return self.usage_error("ap", "merge", opts, "A merge reason is required for chronology and audit.", usage, VALIDATION)
        source = self._resolve_ap_merge_endpoint(positional[0])
        target = self._resolve_ap_merge_endpoint(positional[1])
        if not source or not target:
            failed = "source" if not source else "target"
            detail = self._ap_merge_endpoint_detail(positional[0] if not source else positional[1], failed)
            return self.usage_error("ap", "merge", opts, detail, "netrune ap list <target>", VALIDATION)
        if str(source.get("ip") or "") == str(target.get("ip") or ""):
            detail = (
                f"'{positional[0]}' and '{positional[1]}' both resolve to {source.get('name') or source.get('ip')} "
                f"({source.get('ip')}). They are already one AP, so there is nothing to merge."
            )
            return self.usage_error("ap", "merge", opts, detail, "netrune ap merges", VALIDATION)
        assessment = identity_match_evidence(source, target, "ap")
        preview = {
            "ok": True,
            "operation": "manual-ap-merge",
            "source": self.state._ap_snapshot(source),
            "target": self.state._ap_snapshot(target),
            "assessment": assessment,
            "reason": reason,
            "effects": [
                "source removed from active inventory",
                "source identities and observations retained in chronological memory",
                "source name and address resolve to the current target",
                "future matching source observations are suppressed until merge revocation",
            ],
            "requires_confirmation": True,
        }
        text = (
            f"Manual AP merge preview\n"
            f"Historical source: {source.get('name') or source.get('ip')} ({source.get('ip')})\n"
            f"Current target: {target.get('name') or target.get('ip')} ({target.get('ip')})\n"
            f"Automatic assessment: {'same AP' if assessment['same_device'] else 'manual override'} | Confidence: {assessment['confidence']}%\n"
            f"Conflicts retained as evidence: {', '.join(assessment['conflicts']) or 'none'}\n"
            f"Reason: {reason}"
        )
        if opts.dry_run:
            self.emit(preview, opts, text)
            return SUCCESS
        if not opts.confirm:
            return self.usage_error("ap", "merge", opts, "Manual merge requires --dry-run for review or --confirm to apply.", usage, CONFIRM_REQUIRED)
        actor = os.environ.get("SUDO_USER") or os.environ.get("USER") or str(os.getuid())
        try:
            merge = self.state.create_manual_merge("ap", source, target, reason, actor)
            reconciliation = self.state.sync_derived_state()
            compatibility = self.state.export_flat_files()
        except ValueError as exc:
            return self.usage_error("ap", "merge", opts, str(exc), usage, VALIDATION)
        self.state.record_audit_event(
            "ap_device_merged", "ap-merge", actor=actor, actor_uid=os.getuid(),
            target=f"{merge['source_key']}->{merge['target_key']}", result="success", reason=reason,
            detail={"merge_id": merge["merge_id"], "source_ip": merge["source_ip"], "target_ip": merge["target_ip"]},
        )
        payload = {**preview, "merge": timestamp_row(merge), "reconciliation": reconciliation, "compatibility_export": compatibility, "applied": True}
        self.emit(payload, opts, text + f"\nMerge: {merge['merge_id']} | Recorded: {fmt_time(merge['created_at'])}")
        return SUCCESS

    def cmd_ap_unmerge(self, args: List[str], opts: GlobalOptions) -> int:
        positional, reason, error = self._manual_merge_arguments(args, expected=1)
        usage = "netrune ap unmerge <merge_id> --reason 'restore observation' --confirm"
        if error:
            return self.usage_error("ap", "unmerge", opts, error, usage, VALIDATION)
        if not reason:
            return self.usage_error("ap", "unmerge", opts, "A revocation reason is required.", usage, VALIDATION)
        if not opts.confirm:
            return self.usage_error("ap", "unmerge", opts, "Restoring a retired AP requires --confirm.", usage, CONFIRM_REQUIRED)
        actor = os.environ.get("SUDO_USER") or os.environ.get("USER") or str(os.getuid())
        try:
            merge = self.state.revoke_manual_merge("ap", positional[0], reason, actor)
            reconciliation = self.state.sync_derived_state()
            compatibility = self.state.export_flat_files()
        except ValueError as exc:
            return self.usage_error("ap", "unmerge", opts, str(exc), usage, VALIDATION)
        self.state.record_audit_event(
            "ap_device_merge_revoked", "ap-unmerge", actor=actor, actor_uid=os.getuid(),
            target=str(merge.get("merge_id") or positional[0]), result="success", reason=reason,
            detail={"merge_id": merge.get("merge_id")},
        )
        payload = {"ok": True, "merge": timestamp_row(merge), "reconciliation": reconciliation, "compatibility_export": compatibility}
        self.emit(payload, opts, f"Restored AP merge {merge.get('merge_id')} | Recorded: {fmt_time(merge.get('revoked_at'))}")
        return SUCCESS
    def memory_switch_payload(self,target:str,opts:GlobalOptions)->Dict[str,Any]:
        target_clean = str(target or "").strip()
        normalized = normalize_target_literal(target_clean)
        is_ip = bool(IP_RE.fullmatch(normalized))
        if is_ip:
            ip = normalized
            switches = self.state.rows(
                "SELECT ip,hostname,platform,status,last_seen FROM devices WHERE lower(ip)=lower(?) OR lower(hostname)=lower(?) OR lower(substr(hostname,1,instr(hostname||'.','.')-1))=lower(?) ORDER BY hostname LIMIT 20",
                (ip, target_clean, target_clean),
            )
            aps = self.state.rows("SELECT * FROM aps WHERE switch_ip = ? ORDER BY status,switch_port,name", (ip,))
            neighbors = self.state.rows("SELECT * FROM neighbors WHERE local_ip = ? ORDER BY local_port,remote_name LIMIT ?", (ip, opts.limit))
            rels = self.state.rows(
                "SELECT * FROM relationships_current WHERE rel_type IN ('ap_attachment','neighbor_link','port_occupancy') AND status!='disappeared' AND (subject_id = ? OR object_id = ? OR switch_ip = ?) ORDER BY COALESCE(last_seen,updated_at,first_seen,0) DESC,rel_type,status,confidence DESC,switch_port LIMIT ?",
                (ip, ip, ip, opts.limit),
            )
            ip_json = f'%"{ip}"%'
            events = self.state.rows(
                "SELECT * FROM relationship_events WHERE rel_type IN ('ap_attachment','neighbor_link','port_occupancy') AND (subject_id = ? OR object_id = ? OR current_json LIKE ? OR previous_json LIKE ?) ORDER BY created_at DESC,id DESC LIMIT ?",
                (ip, ip, ip_json, ip_json, opts.limit),
            )
        else:
            target_lower = target_clean.lower()
            like = f"%{target_lower}%"
            switches = self.state.rows(
                "SELECT ip,hostname,platform,status,last_seen FROM devices WHERE lower(ip)=lower(?) OR lower(hostname)=lower(?) OR lower(hostname) LIKE ? OR lower(substr(hostname,1,instr(hostname||'.','.')-1))=lower(?) ORDER BY hostname LIMIT 20",
                (target_clean, target_clean, like, target_clean),
            )
            aps = self.state.rows("SELECT * FROM aps WHERE lower(COALESCE(switch_name,'')) LIKE ? OR lower(COALESCE(switch_ip,''))=lower(?) ORDER BY status,switch_port,name", (like, target_clean))
            neighbors = self.state.rows("SELECT * FROM neighbors WHERE lower(COALESCE(local_name,'')) LIKE ? OR lower(COALESCE(local_ip,''))=lower(?) ORDER BY local_port,remote_name LIMIT ?", (like, target_clean, opts.limit))
            rels = self.state.rows(
                "SELECT * FROM relationships_current WHERE rel_type IN ('ap_attachment','neighbor_link','port_occupancy') AND status!='disappeared' AND (subject_id LIKE ? OR object_id LIKE ? OR switch_ip = ? OR switch_name LIKE ? OR attrs_json LIKE ?) ORDER BY COALESCE(last_seen,updated_at,first_seen,0) DESC,rel_type,status,confidence DESC,switch_port LIMIT ?",
                (f"%{target_clean}%", f"%{target_clean}%", target_clean, f"%{target_clean}%", f"%{target_clean}%", opts.limit),
            )
            events = self.state.rows(
                "SELECT * FROM relationship_events WHERE rel_type IN ('ap_attachment','neighbor_link','port_occupancy') AND (subject_id LIKE ? OR object_id LIKE ? OR current_json LIKE ? OR previous_json LIKE ?) ORDER BY created_at DESC,id DESC LIMIT ?",
                (f"%{target_clean}%", f"%{target_clean}%", f"%{target_clean}%", f"%{target_clean}%", opts.limit),
            )
        switches = timestamp_rows(switches)
        aps = timestamp_rows(reconcile_ap_rows(aps)[:opts.limit])
        rels = timestamp_rows(rels)
        events = self.version_rows(events)
        latest_recorded_at = max(
            [int(row.get("last_seen") or row.get("updated_at") or 0) for row in rels]
            + [int(row.get("created_at") or 0) for row in events]
            + [int(row.get("last_seen") or 0) for row in aps]
            + [0]
        )
        return {"ok":True,"target":target_clean,"switches":switches,"attachments":{"aps":aps,"neighbors":neighbors,"relationships":rels},"timeline":events,"counts":{"switches":len(switches),"aps":len(aps),"neighbors":len(neighbors),"relationships":len(rels),"events":len(events)},"sources":["controller","topology","core_lookup","relationship_events"],"chronology":CHRONOLOGY,"time_format":TIME_FORMAT,"latest_recorded_at":latest_recorded_at or None,"latest_recorded_at_iso":fmt_time(latest_recorded_at),"timestamp_note":"last_seen is the latest canonical observation or memory reconciliation; event created_at is when a state transition was recorded"}
    def memory_switch(self,target:str,opts:GlobalOptions,aps_only:bool=False)->int:
        p=self.memory_switch_payload(target,opts); text=f"Memory: {target}\nSwitch matches: {p['counts']['switches']} | APs: {p['counts']['aps']} | Neighbors: {p['counts']['neighbors']} | Events: {p['counts']['events']}\n\nAPs\n"+self.render_table(p["attachments"]["aps"],["switch_port","name","ip","mac","status","last_seen"])
        if not aps_only: text+="\n\nNeighbors\n"+self.render_table(p["attachments"]["neighbors"],["local_port","remote_name","remote_port","remote_ip"])
        if not aps_only: text+="\n\nCurrent relationships (newest recorded first)\n"+self.render_table(p["attachments"]["relationships"],["rel_type","subject_id","object_id","source","status","first_seen","last_seen"])
        text+="\n\nRecent relationship timeline\n"+self.render_table(p["timeline"],["created_at","event_type","rel_type","subject_id","object_id","source","detail"]); self.emit(p,opts,text); return SUCCESS
    def relationship_timeline(self,target:str,opts:GlobalOptions,rel_type:str="",subject_kind:str="")->int:
        payload=self.relationship_timeline_payload(target,opts.limit,rel_type,subject_kind); rows=payload["rows"]; self.emit(payload,opts,self.render_table(rows,["version","version_label","created_at","event_type","rel_type","subject_id","object_id","source"])); return SUCCESS
    def cmd_memory(self,args:List[str],opts:GlobalOptions)->int:
        if self.handle_help("memory", args, opts): return SUCCESS
        verb=args[0] if args else "switch"; rest=args[1:]
        if verb=="refresh": self.state.import_flat_files(); self.emit({"ok":True,"counts":self.state.counts()},opts,"Memory refreshed from canonical inventory, AP, topology, and lookup observations."); return SUCCESS
        if verb=="switch":
            if not rest: return self.usage_error("memory","switch",opts,"Missing switch target.","netrune memory switch ZONE10")
            return self.memory_switch(" ".join(rest),opts)
        if verb=="device":
            if not rest: return self.usage_error("memory","device",opts,"Missing device name or IP.","netrune memory device ZONE34")
            payload=self.memory_device_payload(rest[0],opts.limit); rows=payload["current"]; self.emit(payload,opts,self.render_table(rows,["rel_type","subject_kind","subject_id","object_kind","object_id","status","first_seen","last_seen"])); return SUCCESS
        if verb in {"ip","mac"}:
            if not rest: return self.usage_error("memory",verb,opts,f"Missing {verb} value.",f"netrune memory {verb} <value>")
            return self.relationship_timeline(norm_mac(rest[0]) if verb=="mac" else rest[0],opts,subject_kind=verb)
        if verb=="port":
            if len(rest)<2: return self.usage_error("memory","port",opts,"Missing switch and/or port.","netrune memory port ZONE34 Gi1/0/7")
            payload=self.memory_port_payload(rest[0],rest[1],opts.limit); rows=payload["current"]; events=payload["timeline"]; self.emit(payload,opts,"Current port occupancy (newest recorded first)\n"+self.render_table(rows,["subject_id","object_kind","object_id","source","confidence","status","first_seen","last_seen"])+"\n\nTimeline (newest first)\n"+self.render_table(events,["created_at","event_type","subject_id","object_id","source","detail"])); return SUCCESS
        if verb=="timeline": return self.relationship_timeline(rest[0] if rest else "",opts)
        if verb=="explain": target=rest[0] if rest else ""; payload=self.memory_explain_payload(target); self.emit(payload,opts,self.render_table(payload["rows"],["rel_type","source","count","avg_confidence","last_seen"])); return SUCCESS
        if verb=="export": rows=timestamp_rows(self.state.rows("SELECT * FROM relationships_current ORDER BY COALESCE(last_seen,updated_at,first_seen,0) DESC,rel_type,subject_id,object_id")); self.emit({"ok":True,"rows":rows,"chronology":CHRONOLOGY,"time_format":TIME_FORMAT},opts); return SUCCESS
        if verb=="prune": return self.usage_error("memory","prune",opts,"Relationship history is retained forever by default. Pruning is not enabled yet.","netrune memory export --json",CONFIRM_REQUIRED)
        return self.unknown_action("memory", verb, opts)

    def health_state_rows(self, target: str = "", opts: Optional[GlobalOptions] = None, status: str = "") -> List[Dict[str, Any]]:
        opts = opts or GlobalOptions()
        q = (target or "").strip()
        clauses: List[str] = []
        args: List[Any] = []
        if q:
            like = f"%{q}%"
            clauses.append("(entity_id LIKE ? OR name LIKE ? OR platform LIKE ? OR switch_ip LIKE ? OR switch_port LIKE ?)")
            args.extend([like, like, like, like, like])
        wanted_status = (status or opts.status or "").strip().upper()
        if wanted_status:
            clauses.append("upper(status)=?")
            args.append(wanted_status)
        where = "WHERE " + " AND ".join(clauses) if clauses else ""
        args.append(opts.limit)
        return self.state.rows(f"SELECT entity_type,entity_id,name,platform,status,first_seen,last_seen,last_failed,outage_started_at,flap_count,switch_ip,switch_port,updated_at FROM health_state {where} ORDER BY CASE upper(status) WHEN 'OFFLINE' THEN 0 WHEN 'ATTENTION' THEN 1 WHEN 'FAILED' THEN 2 ELSE 3 END, flap_count DESC, COALESCE(last_failed,last_seen,updated_at) DESC LIMIT ?", tuple(args))

    def health_summary_payload(self, target: str = "", opts: Optional[GlobalOptions] = None) -> Dict[str, Any]:
        opts = opts or GlobalOptions()
        rows = self.health_state_rows(target, opts)
        counts: Dict[str, int] = {}
        for row in rows:
            key = str(row.get("status") or "UNKNOWN").upper()
            counts[key] = counts.get(key, 0) + 1
        return {"ok": True, "target": target, "counts": counts, "rows": rows, "total": len(rows)}

    def cmd_health(self,args:List[str],opts:GlobalOptions)->int:
        if self.handle_help("health", args, opts): return SUCCESS
        verb=args[0] if args else "status"; rest=args[1:]
        if verb=="check":
            target=" ".join(rest).strip()
            cmd=self.legacy_cmd("netrune-discovery","--fast-health",target) if target else self.legacy_cmd("netrune-discovery","--fast-health")
            rc=self.run_subprocess(cmd,opts)
            if rc==0 and not opts.dry_run:
                self.state.import_flat_files()
            return rc
        if verb=="status":
            target=" ".join(rest).strip()
            payload=self.health_summary_payload(target,opts)
            text="Health status"
            if target: text+=f": {target}"
            text+=f"\nTotal: {payload['total']}"
            if payload["counts"]:
                text+=" | "+" | ".join(f"{k}: {v}" for k,v in sorted(payload["counts"].items()))
            text+="\n"+self.render_table(payload["rows"],["entity_type","entity_id","name","platform","status","last_seen","last_failed","flap_count"])
            self.emit(payload,opts,text); return SUCCESS
        if verb=="offline":
            target=" ".join(rest).strip()
            rows=self.health_state_rows(target,opts,status="OFFLINE")
            self.emit({"ok":True,"target":target,"rows":rows,"count":len(rows)},opts,self.render_table(rows,["entity_type","entity_id","name","platform","status","last_failed","flap_count"])); return SUCCESS if not rows else PARTIAL
        if verb=="attention":
            payload=self.attention_payload(opts.limit)
            rows=payload.get("items",[])
            self.emit(payload,opts,self.render_table(rows,["kind","level","title","text"])); return SUCCESS if not rows else PARTIAL
        if verb=="timeline":
            target=" ".join(rest).strip()
            if target:
                like=f"%{target}%"
                rows=self.version_rows(self.state.rows("SELECT * FROM health_events WHERE entity_id LIKE ? OR detail LIKE ? ORDER BY created_at DESC,id DESC LIMIT ?",(like,like,opts.limit)))
            else:
                rows=self.version_rows(self.state.rows("SELECT * FROM health_events ORDER BY created_at DESC,id DESC LIMIT ?",(opts.limit,)))
            self.emit({"ok":True,"target":target,"rows":rows,"count":len(rows)},opts,self.render_table(rows,["version","version_label","created_at","entity_type","entity_id","event_type","previous_value","current_value"])); return SUCCESS
        return self.unknown_action("health", verb, opts)

    def inventory_history_payload(self, target: str = "", limit: int = 100) -> Dict[str, Any]:
        q = (target or "").strip()
        rows = self.version_rows(self.state.rows("SELECT * FROM inventory_history WHERE (?='' OR ip LIKE ? OR mac LIKE ? OR name LIKE ? OR identity_value LIKE ?) ORDER BY created_at DESC,id DESC LIMIT ?", (q, f"%{q}%", f"%{q}%", f"%{q}%", f"%{q}%", limit)))
        return {"ok": True, "target": q, "rows": rows, "count": len(rows), "chronology": CHRONOLOGY, "time_format": TIME_FORMAT, "latest_recorded_at": rows[0].get("created_at") if rows else None, "latest_recorded_at_iso": rows[0].get("recorded_at_iso", "") if rows else ""}

    def relationship_timeline_payload(self, target: str = "", limit: int = 100, rel_type: str = "", subject_kind: str = "") -> Dict[str, Any]:
        clauses: List[str] = []
        args: List[Any] = []
        if target:
            clauses.append("(subject_id LIKE ? OR object_id LIKE ? OR previous_json LIKE ? OR current_json LIKE ?)")
            args.extend([f"%{target}%"] * 4)
        if rel_type:
            clauses.append("rel_type=?")
            args.append(rel_type)
        if subject_kind:
            clauses.append("subject_kind=?")
            args.append(subject_kind)
        where = "WHERE " + " AND ".join(clauses) if clauses else ""
        rows = self.version_rows(self.state.rows(f"SELECT * FROM relationship_events {where} ORDER BY created_at DESC,id DESC LIMIT ?", (*args, limit)))
        return {"ok": True, "target": target, "rows": rows, "count": len(rows), "chronology": CHRONOLOGY, "time_format": TIME_FORMAT, "latest_recorded_at": rows[0].get("created_at") if rows else None, "latest_recorded_at_iso": rows[0].get("recorded_at_iso", "") if rows else ""}

    def memory_device_payload(self, target: str, limit: int = 100) -> Dict[str, Any]:
        rows = timestamp_rows(self.state.rows("SELECT * FROM relationships_current WHERE status!='disappeared' AND (object_id LIKE ? OR subject_id LIKE ? OR attrs_json LIKE ?) ORDER BY COALESCE(last_seen,updated_at,first_seen,0) DESC,rel_type,confidence DESC LIMIT ?", (f"%{target}%", f"%{target}%", f"%{target}%", limit)))
        events = self.relationship_timeline_payload(target, limit).get("rows", [])
        latest_recorded_at = max([int(row.get("last_seen") or row.get("updated_at") or 0) for row in rows] + [int(row.get("created_at") or 0) for row in events] + [0])
        return {"ok": True, "mode": "device", "target": target, "current": rows, "timeline": events, "count": len(rows), "chronology": CHRONOLOGY, "time_format": TIME_FORMAT, "latest_recorded_at": latest_recorded_at or None, "latest_recorded_at_iso": fmt_time(latest_recorded_at), "timestamp_note": "last_seen is the latest canonical observation or memory reconciliation; event created_at is when a state transition was recorded"}

    def memory_port_payload(self, switch: str, port: str, limit: int = 100) -> Dict[str, Any]:
        port = str(port or "").strip()
        if port.isdigit():
            port_like = f"%/{port}"
            rows = self.state.rows(
                "SELECT * FROM relationships_current WHERE rel_type='port_occupancy' AND status!='disappeared' AND (subject_id LIKE ? OR switch_name LIKE ? OR switch_ip LIKE ?) AND (switch_port=? OR switch_port LIKE ?) ORDER BY COALESCE(last_seen,updated_at,first_seen,0) DESC,status,confidence DESC LIMIT ?",
                (f"%{switch}%", f"%{switch}%", f"%{switch}%", port, port_like, limit),
            )
            event_port = f"%/{port}\"%"
        else:
            rows = self.state.rows(
                "SELECT * FROM relationships_current WHERE rel_type='port_occupancy' AND status!='disappeared' AND (subject_id LIKE ? OR switch_name LIKE ? OR switch_ip LIKE ?) AND switch_port=? ORDER BY COALESCE(last_seen,updated_at,first_seen,0) DESC,status,confidence DESC LIMIT ?",
                (f"%{switch}%", f"%{switch}%", f"%{switch}%", port, limit),
            )
            event_port = f"%\"switch_port\":\"{port}\"%"
        events = self.state.rows(
            "SELECT * FROM relationship_events WHERE rel_type='port_occupancy' AND ((current_json LIKE ? AND current_json LIKE ?) OR (previous_json LIKE ? AND previous_json LIKE ?)) ORDER BY created_at DESC,id DESC LIMIT ?",
            (f"%{switch}%", event_port, f"%{switch}%", event_port, limit),
        )
        rows = timestamp_rows(rows)
        events = self.version_rows(events)
        latest_recorded_at = max([int(row.get("last_seen") or row.get("updated_at") or 0) for row in rows] + [int(row.get("created_at") or 0) for row in events] + [0])
        return {"ok": True, "mode": "port", "target": switch, "port": port, "current": rows, "timeline": events, "count": len(rows), "chronology": CHRONOLOGY, "time_format": TIME_FORMAT, "latest_recorded_at": latest_recorded_at or None, "latest_recorded_at_iso": fmt_time(latest_recorded_at), "timestamp_note": "last_seen is the latest canonical observation or memory reconciliation; event created_at is when a state transition was recorded"}

    def memory_explain_payload(self, target: str = "") -> Dict[str, Any]:
        rows = timestamp_rows(self.state.rows("SELECT rel_type,source,COUNT(*) AS count,ROUND(AVG(confidence),1) AS avg_confidence,MAX(COALESCE(last_seen,updated_at,first_seen,0)) AS last_seen FROM relationships_current WHERE (?='' OR subject_id LIKE ? OR object_id LIKE ? OR attrs_json LIKE ?) GROUP BY rel_type,source ORDER BY last_seen DESC,rel_type,source", (target, f"%{target}%", f"%{target}%", f"%{target}%")))
        return {"ok": True, "mode": "explain", "target": target, "rows": rows, "chronology": CHRONOLOGY, "time_format": TIME_FORMAT, "latest_recorded_at": rows[0].get("last_seen") if rows else None, "latest_recorded_at_iso": rows[0].get("last_seen_iso", "") if rows else ""}

    def live_log(self, area: str, message: str) -> None:
        """Emit concise progress on stderr so job SSE and final output stay distinct."""
        # Retire any transient status line first; otherwise its text stays on
        # the row this log line is about to share.
        self._progress_clear()
        print(f"[{area.upper()}] {strip_ansi(str(message)).replace(chr(10), ' ')[:240]}", file=sys.stderr, flush=True)

    def resolve_device_record(self, target: str) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]]]:
        raw = self.natural_ask.apply_aliases(str(target or "").strip(), strict=True)
        # An abbreviated address is an address, not a name fragment.
        expanded = expand_abbreviated_target(raw, self.config.public.get("target_abbreviation_prefix", ""))
        if expanded:
            raw = expanded
        normalized = normalize_target_literal(raw)
        if not normalized:
            return None, []
        with self.state.connect() as con:
            observations = [dict(row) for row in con.execute("SELECT ip,hostname,hostname AS name,platform,model,serial,mac,source,status,last_seen FROM devices ORDER BY hostname,ip")]
            rows = reconcile_device_rows(observations)
            self.state._overlay_manual_device_merges(con, rows)
        identity_history = self.state.rows("SELECT identity_kind,identity_value,ip,mac,name,model,serial FROM inventory_identity_state WHERE entity_type='device'")
        identity_history_index = self.state._device_history_index(identity_history)
        for row in rows:
            addresses = set(row.get("addresses") or ([row.get("ip")] if row.get("ip") else []))
            macs = {norm_mac(value) for value in row.get("macs") or ([row.get("mac")] if row.get("mac") else []) if norm_mac(value)}
            serials = {
                re.sub(r"[^A-Z0-9]", "", str(value or "").upper())
                for value in (row.get("serials") or ([row.get("serial")] if row.get("serial") else []))
                if re.sub(r"[^A-Z0-9]", "", str(value or "").upper())
                not in {"", "NA", "NONE", "NULL", "UNKNOWN", "NOTAVAILABLE"}
            }
            aliases = set(row.get("aliases") or [])
            current_identity = {
                "ip": row.get("ip") or "",
                "mac": next(iter(macs), ""),
                "serial": next(iter(serials), ""),
                "hostname": row.get("hostname") or row.get("name") or "",
                "model": row.get("model") or "",
                "addresses": sorted(addresses),
                "macs": sorted(macs),
                "serials": sorted(serials),
            }
            for historical in self.state._matching_device_history(current_identity, identity_history, identity_history_index):
                aliases.add(str(historical.get("name") or "").strip())
                if historical.get("identity_kind") == "name":
                    aliases.add(str(historical.get("identity_value") or "").strip())
            row["aliases"] = sorted(alias for alias in aliases if alias)
            row["alias_names"] = ", ".join(row["aliases"])
        def exact_match(names: Sequence[Any], addresses: Sequence[Any]) -> bool:
            return any(str(value or "").lower() == normalized.lower() for value in addresses) or any(
                str(value or "").lower() == raw.lower()
                or str(value or "").split(".", 1)[0].lower() == raw.lower()
                for value in names
            )

        # A device that holds the name/address *now* outranks one that only
        # held it in the past: after a rename or an IP reuse, the old holder
        # keeps that identity as an alias/historical address, and treating
        # both as equally exact made the name every operator would type for
        # the current switch ambiguous. Old identities still resolve when no
        # device currently holds them.
        current = [row for row in rows if exact_match(
            [row.get("hostname"), row.get("name")],
            [row.get("ip"), *(row.get("addresses") or [])],
        )]
        exact = current or [row for row in rows if exact_match(
            row.get("aliases") or [],
            row.get("historical_addresses") or [],
        )]
        if len(exact) == 1:
            return exact[0], exact
        if len(exact) > 1:
            return None, exact[:20]
        token = re.sub(r"[^a-z0-9]", "", raw.lower())
        candidates = []
        for row in rows:
            values = [row.get("ip"), *(row.get("addresses") or []), *(row.get("historical_addresses") or []), row.get("hostname"), *(row.get("aliases") or [])]
            haystacks = [re.sub(r"[^a-z0-9.]", "", str(value or "").lower()) for value in values]
            if any(raw.lower() in value or (token and token in value.replace(".", "")) for value in haystacks):
                candidates.append(row)
        return (candidates[0], candidates) if len(candidates) == 1 else (None, candidates[:20])

    def cached_switch_neighbors(self, device: Dict[str, Any]) -> List[Dict[str, Any]]:
        ip = str(device.get("ip") or "")
        name = clean_display_name(device.get("hostname") or "")
        rows = self.state.rows(
            "SELECT local_ip,local_name,local_port,remote_name,remote_port,remote_ip FROM neighbors "
            "WHERE local_ip=? OR lower(local_name)=lower(?) ORDER BY local_port,remote_name",
            (ip, name),
        )
        reverse = self.state.rows(
            "SELECT local_ip,local_name,local_port,remote_name,remote_port,remote_ip FROM neighbors "
            "WHERE remote_ip=? OR lower(remote_name)=lower(?) ORDER BY remote_port,local_name",
            (ip, name),
        )
        for row in reverse:
            rows.append({
                "local_ip": ip,
                "local_name": name,
                "local_port": row.get("remote_port"),
                "remote_name": row.get("local_name"),
                "remote_port": row.get("local_port"),
                "remote_ip": row.get("local_ip"),
            })
        unique: Dict[Tuple[str, str], Dict[str, Any]] = {}
        for raw in rows:
            row = dict(raw)
            row["source"] = "topology-cache"
            remote_identity = str(row.get("remote_ip") or "").strip() or compact_name(clean_display_name(row.get("remote_name") or "")).lower()
            key = (
                normalize_interface(row.get("local_port")),
                remote_identity,
            )
            if key[0] and key[1] and self._switch_neighbor_evidence(row):
                unique[key] = row
        return list(unique.values())

    def _switch_neighbor_evidence(self, row: Dict[str, Any]) -> bool:
        remote_ip = str(row.get("remote_ip") or "").strip()
        remote_name = clean_display_name(row.get("remote_name") or "")
        if remote_ip and self.state.one("SELECT ip FROM devices WHERE ip=?", (remote_ip,)):
            return True
        if remote_name:
            resolved, choices = self.resolve_device_record(remote_name)
            if resolved and len(choices) == 1:
                return True
        evidence = " ".join(str(row.get(key) or "") for key in ("platform", "capabilities", "remote_name")).lower()
        return bool(re.search(r"\b(?:switch|bridge|router|catalyst|nexus|procurve|aruba|juniper|ruckus|arista)\b|(?:^|[-_])sw\d*", evidence))

    def _neighbor_on_port(self, rows: List[Dict[str, Any]], port: str) -> Optional[Dict[str, Any]]:
        return next((row for row in rows if interface_matches(row.get("local_port"), port)), None)

    def inspect_path_forwarding_node(
        self,
        device: Dict[str, Any],
        endpoint_mac: str,
        vlan: int,
        opts: GlobalOptions,
    ) -> Dict[str, Any]:
        """Query one switch for one MAC and resolve the learned egress neighbor."""
        target = str(device.get("ip") or "")
        clean = norm_mac(endpoint_mac)
        observed_at = now()
        driver = self.driver_for(
            platform=device.get("platform"),
            model=device.get("model"),
            hostname=device.get("hostname"),
        )
        templates = list(driver.command_templates.get("mac_lookup") or ())
        if not clean or not target:
            return {"observed_at": observed_at, "error": "A valid endpoint MAC and switch IP are required."}
        if not templates:
            return {
                "observed_at": observed_at,
                "driver_family": driver.family,
                "error": f"{driver.family} has no registered forwarding-table lookup command.",
            }

        values = {
            "mac_plain": clean,
            "mac_dotted": self.canonical_mac(clean, "dotted"),
            "mac_colon": self.canonical_mac(clean, "colon"),
            "mac_hyphen": f"{clean[:6]}-{clean[6:]}",
        }
        all_hits: List[Dict[str, Any]] = []
        commands: List[str] = []
        errors: List[str] = []
        timeout = min(int(getattr(opts, "timeout", 0) or 120), 180)
        for template in templates:
            command = template.format(**values)
            commands.append(command)
            rc, stdout, stderr = self.capture(self.legacy_cmd("netrune-control", "show", target, command), timeout)
            raw = (stdout or "") + (stderr or "")
            parsed = parse_mac_table_output(raw, clean)
            all_hits.extend(parsed)
            if rc != 0:
                errors.append(" ".join(clean_network_output(raw).split())[:240] or f"command exited {rc}")
            if parsed:
                break

        requested = [row for row in all_hits if str(row.get("vlan") or "") == str(vlan)]
        reported_vlans = sorted({str(row.get("vlan") or "") for row in all_hits if str(row.get("vlan") or "")})
        if all_hits and reported_vlans and not requested:
            return {
                "observed_at": observed_at,
                "driver_family": driver.family,
                "commands": commands,
                "hits": all_hits,
                "error_code": "MAC_VLAN_MISMATCH",
                "reported_vlans": reported_vlans,
                "error": f"MAC {values['mac_dotted']} is learned on VLAN(s) {', '.join(reported_vlans)}, not requested VLAN {vlan}.",
            }
        candidates = requested or all_hits
        unique_ports = {
            normalize_interface(row.get("port")): row
            for row in candidates
            if normalize_interface(row.get("port"))
        }
        if not unique_ports:
            return {
                "observed_at": observed_at,
                "driver_family": driver.family,
                "commands": commands,
                "hits": all_hits,
                "error": errors[-1] if errors and not all_hits else f"MAC {values['mac_dotted']} was not learned on VLAN {vlan}.",
            }

        selected = sorted(unique_ports.values(), key=lambda row: (str(row.get("vlan") or "") != str(vlan), str(row.get("port") or "")))[0]
        port = str(selected.get("port") or "")
        neighbors = self.cached_switch_neighbors(device)
        neighbor = self._neighbor_on_port(neighbors, port)
        if getattr(opts, "refresh_neighbors", False) or not neighbor:
            live = self.live_switch_neighbors(device, min(timeout, 120))
            neighbor = self._neighbor_on_port(live, port) or neighbor
            neighbors.extend(row for row in live if not self._neighbor_on_port(neighbors, str(row.get("local_port") or "")))
        next_device = self._neighbor_device(neighbor) if neighbor else None
        return {
            "observed_at": observed_at,
            "driver_family": driver.family,
            "commands": commands,
            "hits": all_hits,
            "selected": selected,
            "port": port,
            "ambiguous": len(unique_ports) > 1,
            "neighbor": neighbor or {},
            "next_device": next_device or {},
            "errors": errors,
        }


    CMD_MARKER_RE = re.compile(r"^###NETRUNE-CMD (\d+)###\s*$", re.M)

    def capture_batch(
        self,
        target: str,
        commands: Sequence[str],
        timeout: int = 120,
        opts: Optional[GlobalOptions] = None,
    ) -> List[Tuple[str, str]]:
        """Run several read-only commands in one SSH login.

        Returns one (command, output) pair per requested command. Logging in
        once instead of once per command is the difference between six
        authentications for a switch and one.
        """
        wanted = [str(item).strip() for item in commands if str(item).strip()]
        if not target or not wanted:
            return []
        rc, out, err = self.capture(
            self.legacy_cmd("netrune-control", "show-batch", target, *wanted), timeout
        )
        text = (out or "") + (err or "")
        if rc != 0 and not self.CMD_MARKER_RE.search(text):
            # Transport failed outright: attribute the error to every command
            # so callers see the same shape they would from a single read.
            return [(command, text) for command in wanted]
        if not self.CMD_MARKER_RE.search(text):
            # No boundaries came back, so the transcript cannot be split. Give
            # the whole thing to the first command rather than silently
            # returning nothing for every one of them.
            return [(command, text if index == 0 else "") for index, command in enumerate(wanted)]
        pieces = self.CMD_MARKER_RE.split(text)
        # split() yields [prefix, index, body, index, body, ...]
        results: Dict[int, str] = {}
        for position in range(1, len(pieces) - 1, 2):
            with contextlib.suppress(ValueError):
                results[int(pieces[position])] = pieces[position + 1]
        # The stream is pager + commands, so command N of the request is
        # marker N + len(pager) in the transcript.
        driver_offset = len(results) - len(wanted)
        return [
            (command, results.get(index + 1 + max(0, driver_offset), ""))
            for index, command in enumerate(wanted)
        ]

    @contextlib.contextmanager
    def vault_session_scope(self, opts: GlobalOptions, minutes: int = 30):
        """Hold the vault open for one multi-device run, then close it again.

        Each device read otherwise costs a separate vault unlock, which on a
        Windows Hello PAM stack is one biometric prompt per switch. The session
        is scoped to this command: if the operator already unlocked the vault
        it is left exactly as found, and a session opened here is always closed
        on the way out, including on error or interrupt.
        """
        already_open = bool(self.vault_session_payload().get("active"))
        # Only worth attempting where a prompt can actually be answered. With
        # no terminal, or with prompting disabled, the unlock would just fail
        # slowly and the run should proceed and authenticate per device.
        interactive = sys.stdin.isatty() and sys.stderr.isatty()
        if environment_value("NETRUNE_VAULT_NONINTERACTIVE", "NETOPS_VAULT_NONINTERACTIVE", "").lower() in {"1", "true", "yes"}:
            interactive = False
        opened = False
        if not already_open and not opts.dry_run and interactive:
            command = self.legacy_cmd("netrune-connect", "--unlock-vault", "--ttl", str(max(1, min(int(minutes), 480))))
            try:
                opened = self.run_vault_interactive(command, opts) == SUCCESS
            except Exception:
                opened = False
            if not opened:
                # Not fatal: the run still works, it just authenticates per device.
                self.live_log("vault", "Could not hold the vault open; each switch will authenticate separately.")
        try:
            yield opened
        finally:
            if opened:
                with contextlib.suppress(Exception):
                    self.run_vault_interactive(self.legacy_cmd("netrune-connect", "--lock-vault"), opts)

    def _default_stp_jobs(self) -> int:
        try:
            return max(1, min(8, int(self.config.public.get("stp_scan_workers") or 8)))
        except (TypeError, ValueError):
            return 8

    def collect_path_capabilities(
        self,
        device: Dict[str, Any],
        vlan: int,
        endpoint: str,
        interfaces: Sequence[str],
        opts: GlobalOptions,
    ) -> Dict[str, Any]:
        """Read and record the semantic evidence path inspection gates on.

        Path inspection has always known how to judge SVI, LAG, VRF, route and
        ARP evidence; nothing ever produced it, so those judgements could not
        run. This is the producer. Everything is read in one login, and a fact
        that cannot be determined is recorded as unknown rather than guessed —
        a false negative here would block a working path.
        """
        target = str(device.get("ip") or "")
        driver = self.driver_for(
            platform=device.get("platform"), model=device.get("model"), hostname=device.get("hostname"),
        )
        identity = target or str(device.get("hostname") or "")
        observed_at = now()
        recorded: Dict[str, str] = {}
        if not identity:
            return {"observed_at": observed_at, "recorded": recorded}

        endpoint_ip = str(endpoint or "").strip()
        try:
            ipaddress.ip_address(endpoint_ip)
        except ValueError:
            endpoint_ip = ""
        path_ports = [str(item) for item in interfaces if str(item or "").strip()]

        plan: List[Tuple[str, str]] = []

        def add(capability: str, operation: str, **values: Any) -> None:
            templates = driver.command_templates.get(operation)
            if not templates or not driver.supports(capability):
                return
            with contextlib.suppress(Exception):
                plan.append((capability, templates[0].format(**values)))

        add("svi", "svi", vlan=vlan)
        add("lag", "lag")
        add("vrf", "vrf")
        if endpoint_ip:
            add("routes", "routes", destination=endpoint_ip)
            add("arp_nd", "arp_nd", destination=endpoint_ip)
        policy_port = next(
            (port for port in path_ports if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9./:_-]{0,31}", port)), ""
        )
        if policy_port:
            add("interface_policy", "interface_policy", interface=policy_port)
        if not plan:
            return {"observed_at": observed_at, "recorded": recorded}

        timeout = min(int(getattr(opts, "timeout", 0) or 120), 180)
        output = dict(self.capture_batch(target, [command for _, command in plan], timeout))

        def store(capability: str, state: str, facts: Dict[str, Any], raw: str, confidence: int) -> None:
            self.state.record_capability_evidence(
                identity, capability, state, facts, raw=raw,
                driver_family=driver.family, confidence=confidence, observed_at=observed_at,
            )
            recorded[capability] = state

        for capability, command in plan:
            raw = output.get(command, "")
            if capability == "svi":
                parsed = parse_svi_output(raw, vlan)
                store("svi", "supported" if parsed.get("parsed") else "unknown",
                      {"vlan": str(vlan), "interface": parsed.get("interface") or f"Vlan{vlan}",
                       "state": parsed.get("state") or "unknown", "exists": parsed.get("exists"),
                       "command": command},
                      raw, 92 if parsed.get("parsed") else 40)
            elif capability == "lag":
                parsed = parse_lag_output(raw)
                member = next(
                    (parsed["interfaces"][normalize_interface(port)] for port in path_ports
                     if normalize_interface(port) in parsed["interfaces"]), None,
                )
                if member:
                    store("lag", "supported",
                          {"interface": member["interface"], "group": member["group"],
                           "operational": member["operational"], "command": command},
                          raw, 90)
                else:
                    # No path interface belongs to a bundle: nothing to judge,
                    # and no interface means the gate correctly skips it.
                    store("lag", "supported",
                          {"interface": "", "operational": None,
                           "note": "no path interface is a link-aggregation member",
                           "command": command},
                          raw, 60)
            elif capability == "vrf":
                parsed = parse_vrf_output(raw)
                owning = next(
                    (row["name"] for row in parsed.get("vrfs") or []
                     if any(normalize_interface(item) == normalize_interface(f"Vlan{vlan}")
                            for item in row.get("interfaces") or [])), "",
                )
                store("vrf", "supported" if parsed.get("parsed") else "unknown",
                      {"vlan": str(vlan), "vrf": owning,
                       # No expected VRF is supplied, so membership is reported
                       # and never asserted as a mismatch.
                       "matches": None, "vrfs": [row["name"] for row in parsed.get("vrfs") or []],
                       "command": command},
                      raw, 70 if parsed.get("parsed") else 40)
            elif capability == "routes":
                parsed = parse_route_output(raw, endpoint_ip)
                store("routes", "supported" if parsed.get("parsed") else "unknown",
                      {"destination": endpoint_ip, "route_present": parsed.get("route_present"),
                       "via": parsed.get("via") or "", "command": command},
                      raw, 88 if parsed.get("parsed") else 40)
            elif capability == "arp_nd":
                rows = parse_arp_output(raw, endpoint_ip)
                store("arp_nd", "supported" if rows else "unknown",
                      {"destination": endpoint_ip, "neighbor_present": bool(rows) or None,
                       "mac": (rows[0].get("mac") if rows else ""), "command": command},
                      raw, 88 if rows else 40)
            elif capability == "interface_policy":
                references = sorted({
                    match.group(1) for match in
                    re.finditer(r"(?im)^\s*(?:ip\s+)?access-(?:group|list)\s+(\S+)", clean_network_output(raw))
                })
                store("interface_policy", "supported",
                      {"interface": policy_port, "references": references,
                       # This driver reads the attachment but cannot prove
                       # whether a listed policy blocks the flow.
                       "semantics_supported": False, "command": command},
                      raw, 70)
        return {"observed_at": observed_at, "recorded": recorded, "commands": [c for _, c in plan]}

    def inspect_path_layer3(self, device: Dict[str, Any], vlan: int, opts: GlobalOptions) -> Dict[str, Any]:
        """Collect conservative Layer 3 termination evidence for one VLAN."""
        target = str(device.get("ip") or "")
        driver = self.driver_for(
            platform=device.get("platform"),
            model=device.get("model"),
            hostname=device.get("hostname"),
        )
        templates = list(driver.command_templates.get("svi") or ())
        observed_at = now()
        if not target or not templates:
            return {
                "observed_at": observed_at,
                "driver_family": driver.family,
                "parsed": False,
                "state": "unknown",
                "error": "No registered SVI inspection command is available.",
            }
        timeout = min(int(getattr(opts, "timeout", 0) or 120), 180)
        commands: List[str] = []
        last: Dict[str, Any] = {}
        for template in templates:
            command = template.format(vlan=vlan)
            commands.append(command)
            rc, stdout, stderr = self.capture(self.legacy_cmd("netrune-control", "show", target, command), timeout)
            parsed = parse_svi_output((stdout or "") + (stderr or ""), vlan)
            parsed.update({"exit_code": rc, "driver_family": driver.family, "observed_at": observed_at, "commands": commands[:]})
            last = parsed
            if parsed.get("parsed"):
                return parsed
        return last or {
            "observed_at": observed_at,
            "driver_family": driver.family,
            "parsed": False,
            "state": "unknown",
            "commands": commands,
        }

    def icmp_probe(self, target: str, opts: Optional[GlobalOptions] = None, count: int = 3) -> Dict[str, Any]:
        """Ping a target from this host and return parsed reachability.

        Deliberately local rather than device-sourced: the collector measures
        what it can reach, which is the reading a remote poller is there to
        provide.
        """
        clean = str(target or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,253}", clean):
            return {"ok": False, "unreachable": True, "error": "invalid target"}
        count = max(1, min(int(count), 20))
        timeout = min(int(getattr(opts, "timeout", 0) or 10), 30)
        rc, out, err = self.capture(["ping", "-c", str(count), "-W", "2", clean], timeout)
        parsed = parse_ping_output((out or "") + (err or ""), count)
        loss = parsed.get("packet_loss_pct")
        return {
            "ok": rc == 0,
            "target": clean,
            "unreachable": rc != 0 or (loss is not None and float(loss) >= 100),
            "packet_loss_pct": loss,
            "avg_ms": parsed.get("avg_ms"),
            "min_ms": parsed.get("min_ms"),
            "max_ms": parsed.get("max_ms"),
            "jitter_ms": parsed.get("jitter_ms"),
        }



    def safe_show_command(self, command: str) -> bool:
        raw = str(command or "")
        if any(token in raw for token in ("\n", "\r", "\x00", ";", "&&", "||", "`", "$(")):
            return False
        cmd = " ".join(raw.strip().split()).lower()
        if not re.match(r"^(show|sh|display|get)\b", cmd):
            return False
        blocked = ["running-config", "startup-config", "tech-support", " run", " start", "secret", "password", "passwd", "community", "credential", "crypto", "private-key", "certificate", "write", "erase", "delete", "copy ", "reload", "configure", "conf t"]
        return not any(term in cmd for term in blocked)

    def reconciled_ap_rows(self, pattern: str = "", opts: Optional[GlobalOptions] = None) -> List[Dict[str, Any]]:
        opts = opts or GlobalOptions()
        with self.state.connect() as con:
            rows = reconcile_ap_rows([dict(r) for r in con.execute("SELECT * FROM aps")])
            self.state._overlay_manual_ap_merges(con, rows)
        if pattern and not is_all_keyword(pattern):
            rows = [row for row in rows if ap_rows_match(row, pattern)]
        if opts.status:
            rows = [row for row in rows if norm_status(row.get("status")) == opts.status]
        if opts.site:
            rows = [row for row in rows if opts.site.lower() in json.dumps(row, default=str).lower()]
        return rows[:opts.limit]

    def ask_payload(self, question: str, opts: GlobalOptions, session: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        from netops_platform.ask_cli import ask_payload
        return ask_payload(self, question, opts, session=session)

    def execute_ask_plan(self, payload: Dict[str, Any], opts: GlobalOptions) -> int:
        from netops_platform.ask_cli import execute_ask_plan
        return execute_ask_plan(self, payload, opts)

    def cmd_ask(self, args: List[str], opts: GlobalOptions) -> int:
        from netops_platform.ask_cli import dispatch
        return dispatch(self, args, opts)
    def _identity_candidate_items(self, limit: int) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Build `health attention` items from pending identity-swap candidates.

        A floor is applied here, not where the candidate was written, so a
        weak isolated pair and a weak pair that is one of several sharing a
        site-rename pattern can be told apart: a cluster of
        `continuity_cluster_min_members` or more is surfaced regardless of
        each member's own confidence (the pattern itself is the evidence),
        while an unclustered single still has to clear the floor on its own.
        """
        config = self.state._continuity_config()
        ttl_cutoff = now() - config["attention_ttl_days"] * 86400
        raw = self.state.rows(
            "SELECT * FROM relationships_current WHERE rel_type='identity_swap_candidate' AND status!='disappeared' "
            "AND last_seen>=? ORDER BY confidence DESC,last_seen DESC LIMIT ?",
            (ttl_cutoff, limit),
        )
        parsed: List[Dict[str, Any]] = []
        for row in raw:
            try:
                attrs = json.loads(row.get("attrs_json") or "{}")
            except (TypeError, json.JSONDecodeError):
                continue
            if not isinstance(attrs.get("old"), dict) or not isinstance(attrs.get("new"), dict):
                continue
            parsed.append({**attrs, "confidence": row.get("confidence"), "row": row})
        clusters, singles = cluster_rename_candidates(parsed, min_members=config["cluster_min_members"])
        items: List[Dict[str, Any]] = []
        for cluster in clusters:
            members = cluster["members"]
            example = members[0]
            items.append({
                "kind": "identity_rename_cluster",
                "level": "warning",
                "title": f"{cluster['old_location_prefix']} -> {cluster['new_location_prefix']} ({cluster['member_count']} {example.get('entity_type', 'device')}s)",
                "text": (
                    f"{cluster['member_count']} {example.get('entity_type', 'device')}s that disappeared from "
                    f"{cluster['old_location_prefix']} look like they reappeared as {cluster['new_location_prefix']} "
                    f"(role/number preserved). First to confirm: netrune {'ap' if example.get('entity_type') == 'ap' else 'inventory'} "
                    f"merge '{example['old'].get('name') or example['old'].get('ip')}' '{example['new'].get('name') or example['new'].get('ip')}' --reason 'site rename' --dry-run"
                ),
                "row": cluster,
            })
        for single in singles:
            if int(single.get("confidence") or 0) < config["confidence_floor"]:
                continue
            old, new, entity_type = single["old"], single["new"], single.get("entity_type", "device")
            verb = "ap" if entity_type == "ap" else "inventory"
            old_label = old.get("name") or old.get("ip") or "?"
            new_label = new.get("name") or new.get("ip") or "?"
            items.append({
                "kind": "identity_swap_candidate",
                "level": "warning",
                "title": f"{old_label} -> {new_label}?",
                "text": (
                    f"{entity_type} '{old_label}' disappeared, '{new_label}' appeared with matching signals "
                    f"(confidence {single.get('confidence')}%). Review: netrune {verb} merge '{old_label}' '{new_label}' "
                    "--reason '...' --dry-run"
                ),
                "row": single["row"],
            })
        return items, raw

    def attention_payload(self, limit: int = 80) -> Dict[str, Any]:
        limit = clean_limit(limit, 80, 300)
        health = self.state.rows("SELECT entity_type,entity_id,name,platform,status,last_seen,last_failed,outage_started_at,flap_count,switch_ip,switch_port FROM health_state WHERE status='OFFLINE' OR flap_count>=3 OR (last_seen IS NOT NULL AND last_seen < strftime('%s','now') - 86400) ORDER BY status,flap_count DESC,last_seen LIMIT ?", (limit,))
        topology = self.state.rows("SELECT * FROM topology_events ORDER BY created_at DESC,id DESC LIMIT ?", (limit,))
        moves = self.state.rows("SELECT * FROM ap_move_events ORDER BY created_at DESC,id DESC LIMIT ?", (limit,))
        backups = self.state.rows("SELECT * FROM backup_history ORDER BY created_at DESC,id DESC LIMIT ?", (limit,))
        identity_items, identity_candidates = self._identity_candidate_items(limit)
        items: List[Dict[str, Any]] = []
        for row in health:
            level = "danger" if str(row.get("status") or "").upper() == "OFFLINE" else "warning"
            items.append({"kind": "health", "level": level, "title": row.get("name") or row.get("entity_id"), "text": f"{row.get('entity_type')} {row.get('status')} flaps={row.get('flap_count')}", "row": row})
        for row in topology[:20]:
            items.append({"kind": "topology", "level": "warning", "title": row.get("event_type"), "text": f"{row.get('local_ip')} {row.get('local_port')} -> {row.get('remote_name')}", "row": row})
        for row in moves[:20]:
            items.append({"kind": "ap_move", "level": "warning", "title": row.get("ap_name") or row.get("ap_ip"), "text": f"{row.get('previous_switch_ip')}/{row.get('previous_switch_port')} -> {row.get('current_switch_ip')}/{row.get('current_switch_port')}", "row": row})
        for row in backups[:20]:
            if row.get("status") not in {"saved", "unchanged"}:
                items.append({"kind": "backup", "level": "warning", "title": row.get("hostname") or row.get("device_ip"), "text": row.get("message") or row.get("status"), "row": row})
        items.extend(identity_items[:20])
        return {"ok": True, "items": items[:limit], "health": health, "topology_changes": topology, "ap_moves": moves, "backups": backups, "identity_candidates": identity_candidates}


    def command_registry(self) -> List[CommandSpec]:
        tool = self.paths.tool
        return [
            CommandSpec("init-run", "Initialize profile", [tool("netrune"), "init"], "Create neutral profile state and check host capabilities.", writes_local=True, domain="init", safety_class="local-write"),
            CommandSpec("profile-list", "List profiles", [tool("netrune"), "profile", "list"], "List isolated Netrune profiles.", domain="profile", output_type="table"),
            CommandSpec("profile-show", "Show profile", [tool("netrune"), "profile", "show", "<name>"], "Show profile paths and non-secret settings.", args=["name"], domain="profile", output_type="table"),
            CommandSpec("profile-create", "Create profile", [tool("netrune"), "profile", "create", "<name>"], "Create a neutral isolated profile.", writes_local=True, args=["name"], domain="profile", safety_class="local-write"),
            CommandSpec("profile-use", "Select profile", [tool("netrune"), "profile", "use", "<name>"], "Select the profile used by future commands.", writes_local=True, args=["name"], domain="profile", safety_class="local-write"),
            CommandSpec("profile-paths", "Profile paths", [tool("netrune"), "profile", "paths"], "Show active profile XDG paths.", domain="profile", output_type="table"),
            CommandSpec("profile-migrate-legacy", "Migrate legacy profile", [tool("netrune"), "profile", "migrate-legacy", "<name>"], "Copy legacy netsnmp state without deleting the source.", writes_local=True, args=["name"], domain="profile", safety_class="local-write"),
            CommandSpec("config-show", "Show configuration", [tool("netrune"), "config", "show"], "Show effective redacted profile settings.", domain="config", output_type="table"),
            CommandSpec("config-get", "Get configuration", [tool("netrune"), "config", "get", "<key>"], "Read one effective non-secret setting.", args=["key"], domain="config", output_type="text"),
            CommandSpec("config-set", "Set configuration", [tool("netrune"), "config", "set", "<key>", "<value>"], "Set one non-secret profile override.", writes_local=True, args=["key", "value"], domain="config", safety_class="local-write"),
            CommandSpec("config-unset", "Unset configuration", [tool("netrune"), "config", "unset", "<key>"], "Remove one profile override.", writes_local=True, args=["key"], domain="config", safety_class="local-write"),
            CommandSpec("config-validate", "Validate configuration", [tool("netrune"), "config", "validate"], "Validate effective settings and legacy-secret state.", domain="config", output_type="table"),
            CommandSpec("config-paths", "Configuration paths", [tool("netrune"), "config", "paths"], "Show global and profile configuration files.", domain="config", output_type="table"),
            CommandSpec("secrets-list", "List named secrets", [tool("netrune"), "secrets", "list"], "List named secrets without values.", domain="secrets", output_type="table"),
            CommandSpec("secrets-status", "Named secret status", [tool("netrune"), "secrets", "status"], "Show named-secret store security and lock state.", domain="secrets", output_type="table"),
            CommandSpec("secrets-set", "Set named secret", [tool("netrune"), "secrets", "set", "<name>"], "Prompt for and encrypt one named secret.", read_only=False, writes_local=True, args=["name"], domain="secrets", output_type="terminal", run_supported=False, safety_class="local-write"),
            CommandSpec("secrets-delete", "Delete named secret", [tool("netrune"), "secrets", "delete", "<name>", "--confirm"], "Delete one named secret after confirmation.", read_only=False, writes_local=True, args=["name"], domain="secrets", output_type="terminal", run_supported=False, safety_class="local-write"),
            CommandSpec("secrets-import-ssh", "Import SSH secret", [tool("netrune"), "secrets", "import-ssh"], "Import the legacy SSH vault into ssh/default/password.", read_only=False, writes_local=True, domain="secrets", output_type="terminal", run_supported=False, safety_class="local-write"),
            CommandSpec("ingest-channels", "List ingest channels", [tool("netrune"), "ingest", "channels"], "List declarative channels in the active profile.", writes_local=True, domain="ingest", output_type="table"),
            CommandSpec("ingest-validate", "Validate ingest channels", [tool("netrune"), "ingest", "validate"], "Validate channel manifests without fetching records.", domain="ingest", output_type="table"),
            CommandSpec("ingest-run", "Run ingest channel", [tool("netrune"), "ingest", "run", "<channel>"], "Run one provenance-preserving ingest channel.", writes_local=True, args=["channel"], domain="ingest", timeout_seconds=1800),
            CommandSpec("ingest-history", "Ingest history", [tool("netrune"), "ingest", "history"], "Show ingest runs newest first.", domain="ingest", output_type="table"),
            CommandSpec("ingest-rejects", "Ingest rejects", [tool("netrune"), "ingest", "rejects", "<run_id>"], "Show redacted quarantine metadata.", args=["run_id"], domain="ingest", output_type="table"),
            CommandSpec("ingest-observations", "Ingest observations", [tool("netrune"), "ingest", "observations", "<channel>"], "Show append-only channel observations.", args=["channel"], domain="ingest", output_type="table"),
            CommandSpec("plugin-list", "List plugins", [tool("netrune"), "plugin", "list"], "Discover plugins without importing disabled code.", domain="plugin", output_type="table"),
            CommandSpec("plugin-enable", "Enable plugin", [tool("netrune"), "plugin", "enable", "<plugin_id>"], "Enable one trusted entry point in this profile.", writes_local=True, args=["plugin_id"], domain="plugin", safety_class="local-write"),
            CommandSpec("plugin-disable", "Disable plugin", [tool("netrune"), "plugin", "disable", "<plugin_id>"], "Disable one plugin in this profile.", writes_local=True, args=["plugin_id"], domain="plugin", safety_class="local-write"),
            CommandSpec("plugin-check", "Check plugins", [tool("netrune"), "plugin", "check", "<group>"], "Load enabled plugins and isolate failures.", args=["group"], domain="plugin", output_type="table"),
            CommandSpec("plugin-groups", "Plugin groups", [tool("netrune"), "plugin", "groups"], "List stable entry-point groups and policy.", domain="plugin", output_type="table"),
            CommandSpec("path-inspect", "Inspect forwarding path", [tool("netrune"), "path", "inspect", "<endpoint>", "--vlan", "<vlan>"], "Inspect a bounded L2/L3 endpoint path with cached and live read-only evidence.", writes_local=True, args=["endpoint", "vlan", "source", "destination", "depth", "max_nodes", "mode", "explain"], domain="path", safety_class="network-read", timeout_seconds=1800),
            CommandSpec("traffic-list", "Monitored targets", [tool("netrune"), "traffic", "list"], "Show every monitored target with recent activity.", domain="traffic", output_type="table"),
            CommandSpec("traffic-poll", "Collect traffic samples", [tool("netrune"), "traffic", "poll"], "Collect one round from every enabled watch.", writes_local=True, domain="traffic", output_type="text", safety_class="network-read"),
            CommandSpec("traffic-show", "Traffic graphs", [tool("netrune"), "traffic", "show"], "Show throughput and latency as terminal sparklines.", domain="traffic", output_type="text"),
            CommandSpec("traffic-subscribe", "Record a link's subscribed rate", [tool("netrune"), "traffic", "subscribe", "<target>", "--down", "<down>"], "Record what a service link is sold at, so utilisation is measured against the contract rather than the port's line rate.", writes_local=True, args=["target", "down"], domain="traffic", output_type="text", safety_class="local-write"),
            CommandSpec("traffic-name", "Name a monitored port", [tool("netrune"), "traffic", "name", "<target>", "<name>"], "Give a monitored port a name of your own for dashboards. History is unaffected.", writes_local=True, args=["target", "name"], domain="traffic", output_type="text", safety_class="local-write"),
            CommandSpec("setup-poller", "Set up a collector", [tool("netrune"), "setup", "poller", "--community", "<community>"], "Stand up a machine that collects and nothing else, from a community and an identity.", writes_local=True, args=["community"], domain="setup", output_type="text", safety_class="local-write"),
            CommandSpec("setup-local", "Set up this machine", [tool("netrune"), "setup", "local", "--community", "<community>"], "Stand up collector, storage, and dashboards on this machine.", writes_local=True, args=["community"], domain="setup", output_type="text", safety_class="local-write"),
            CommandSpec("traffic-push", "Push readings to storage", [tool("netrune"), "traffic", "push", "--to", "<url>"], "Send this collector's readings straight into a VictoriaMetrics import endpoint.", args=["to"], domain="traffic", output_type="text", safety_class="network-read"),
            CommandSpec("traffic-dashboard", "Dashboard links", [tool("netrune"), "traffic", "dashboard"], "Print every dashboard's URL and whether the grapher is answering.", domain="traffic", output_type="text"),
            CommandSpec("traffic-health", "Switch health", [tool("netrune"), "traffic", "health"], "Show uptime, control-plane CPU, memory, temperature, and sessions for every switch with a watched port.", domain="traffic", output_type="table"),
            CommandSpec("traffic-exporter", "Metrics exposition", [tool("netrune"), "traffic", "exporter"], "Publish collected readings as Prometheus exposition on loopback for VictoriaMetrics to scrape.", domain="traffic", output_type="terminal", run_supported=False),
            CommandSpec("traffic-backfill", "Import history", [tool("netrune"), "traffic", "backfill"], "Import history collected before the metrics stack existed into VictoriaMetrics.", writes_local=False, domain="traffic", output_type="text", safety_class="read-only"),
            CommandSpec("traffic-export", "Export readings", [tool("netrune"), "traffic", "export"], "Print this collector's stored readings as JSONL for another install to pull.", domain="traffic", output_type="text", safety_class="read-only"),
            CommandSpec("traffic-pull", "Pull from a poller", [tool("netrune"), "traffic", "pull", "--remote", "<remote>"], "Fetch readings from a remote poller over SSH and merge them locally.", writes_local=True, args=["remote"], domain="traffic", output_type="text", safety_class="local-write"),
            CommandSpec("traffic-remote", "Remote pollers", [tool("netrune"), "traffic", "remote", "list"], "List configured remote pollers and when each was last pulled.", domain="traffic", output_type="table"),
            CommandSpec("traffic-verify", "Verify the pipeline", [tool("netrune"), "traffic", "verify"], "Walk the metrics pipeline link by link and report where it breaks.", domain="traffic", output_type="text", safety_class="read-only"),
            CommandSpec("traffic-stack", "Generate metrics stack", [tool("netrune"), "traffic", "stack", "init"], "Write the VictoriaMetrics, vmalert, and Perses provisioning files.", writes_local=True, domain="traffic", output_type="text", safety_class="local-write"),
            CommandSpec("traffic-report", "Traffic report", [tool("netrune"), "traffic", "report"], "Write a self-contained HTML report with charts for the collected window.", writes_local=True, domain="traffic", output_type="text", safety_class="local-write"),
            CommandSpec("traffic-watch", "Monitor an interface", [tool("netrune"), "traffic", "watch", "<device>", "<interface>"], "Start collecting throughput for one interface over SNMP.", writes_local=True, args=["device", "interface"], domain="traffic", output_type="text", safety_class="network-read"),
            CommandSpec("traffic-ping", "Monitor reachability", [tool("netrune"), "traffic", "ping", "<target>"], "Start collecting round-trip time and loss to one address.", writes_local=True, args=["target"], domain="traffic", output_type="text", safety_class="network-read"),
            CommandSpec("traffic-unwatch", "Stop monitoring", [tool("netrune"), "traffic", "unwatch", "<target>"], "Stop monitoring one or more targets and discard their samples.", read_only=False, writes_local=True, args=["target"], domain="traffic", risk_level="warning", run_supported=False, safety_class="local-write"),
            CommandSpec("traffic-pause", "Pause monitoring", [tool("netrune"), "traffic", "pause", "<target>"], "Stop collecting a target without discarding its history.", writes_local=True, args=["target"], domain="traffic", output_type="text", safety_class="local-write"),
            CommandSpec("traffic-resume", "Resume monitoring", [tool("netrune"), "traffic", "resume", "<target>"], "Start collecting a paused target again.", writes_local=True, args=["target"], domain="traffic", output_type="text", safety_class="local-write"),
            CommandSpec("traffic-interval", "Change collection interval", [tool("netrune"), "traffic", "interval", "<target>", "<seconds>"], "Change how often a target is collected.", writes_local=True, args=["target", "seconds"], domain="traffic", output_type="text", safety_class="local-write"),
            CommandSpec("traffic-status", "Collector status", [tool("netrune"), "traffic", "status"], "Show whether a collector is running and when each target last produced a sample.", domain="traffic", output_type="table"),
            CommandSpec("traffic-interfaces", "SNMP interface list", [tool("netrune"), "traffic", "interfaces", "<device>"], "List the interfaces SNMP reports on a device.", args=["device"], domain="traffic", output_type="table", safety_class="network-read"),
            CommandSpec("traffic-daemon", "Traffic collector", [tool("netrune"), "traffic", "daemon"], "Collect continuously until interrupted. Runs in a terminal you keep open.", writes_local=True, domain="traffic", output_type="terminal", run_supported=False, safety_class="network-read"),
            CommandSpec("path-findings", "Path findings", [tool("netrune"), "path", "findings"], "Query findings across every recorded path run with a frequency summary.", domain="path", output_type="table"),
            CommandSpec("path-history", "Path history", [tool("netrune"), "path", "history", "<endpoint>", "--vlan", "<vlan>"], "Show chronological path inspections with reusable run references.", args=["endpoint", "vlan"], domain="path", output_type="table"),
            CommandSpec("excel-inspect", "Inspect Excel workbook", [tool("netrune"), "excel", "inspect", "<workbook>"], "Match a workbook's rows to Netrune switches and report what is out of date, without writing.", args=["workbook"], domain="excel", output_type="table", run_supported=False),
            CommandSpec("excel-sync", "Sync Excel workbook", [tool("netrune"), "excel", "sync", "<workbook>", "--dry-run"], "Fill and update a workbook's switch rows from Netrune's inventory. Apply explicitly in the CLI with --confirm.", writes_local=True, args=["workbook"], domain="excel", risk_level="warning", output_type="table", run_supported=False, safety_class="local-write", state_effects=["workbook file", "audit_events"]),
            CommandSpec("excel-export", "Export Excel tracker", [tool("netrune"), "excel", "export", "<workbook>"], "Write a new inventory, summary, and migration tracker workbook from Netrune's inventory.", writes_local=True, args=["workbook"], domain="excel", output_type="text", run_supported=False, safety_class="local-write", state_effects=["workbook file", "audit_events"]),
            CommandSpec("path-show", "Show path run", [tool("netrune"), "path", "show", "<reference>", "--vlan", "<vlan>"], "Open a path by full ID, unique prefix, endpoint/VLAN, or latest reference.", args=["reference", "vlan"], domain="path", output_type="table"),
            CommandSpec("support-bundle", "Create support bundle", [tool("netrune"), "support", "bundle"], "Create a redacted support archive without inventory, secrets, raw evidence, or backups.", writes_local=True, domain="support", output_type="table", safety_class="local-write"),
            CommandSpec("vault-status", "Vault status", [tool("netrune"), "vault", "status"], "Show the SSH vault format, permissions, recording time, and non-prompting lock state.", domain="vault", output_type="table"),
            CommandSpec("vault-set", "Set vault password", [tool("netrune"), "vault", "set"], "Store a new SSH password in the terminal sudo-gated GPG vault.", read_only=False, writes_local=True, domain="vault", output_type="terminal", risk_level="warning", run_supported=False, safety_class="local-write"),
            CommandSpec("vault-migrate", "Migrate vault", [tool("netrune"), "vault", "migrate"], "Convert a legacy passphrase GPG vault to terminal sudo-gated GPG without exposing the SSH password.", read_only=False, writes_local=True, domain="vault", output_type="terminal", risk_level="warning", run_supported=False, safety_class="local-write"),
            CommandSpec("vault-unlock", "Unlock vault", [tool("netrune"), "vault", "unlock"], "Authenticate once and hold the SSH vault open for a bounded window so a batch of commands does not re-prompt.", read_only=False, writes_local=True, domain="vault", output_type="terminal", risk_level="warning", run_supported=False, safety_class="local-write"),
            CommandSpec("vault-lock", "Lock vault", [tool("netrune"), "vault", "lock"], "End an open vault session immediately and erase the cached key.", read_only=False, writes_local=True, domain="vault", output_type="terminal", run_supported=False, safety_class="local-write"),
            CommandSpec("db-migrate", "Migrate database", [tool("netrune"), "db", "migrate"], "Apply SQLite schema migrations and reconcile derived state.", writes_local=True, domain="db", safety_class="local-write"),
            CommandSpec("db-status", "Database status", [tool("netrune"), "db", "status"], "Show database paths, schema version, file sizes, and record counts.", domain="db", output_type="table"),
            CommandSpec("db-path", "Database path", [tool("netrune"), "db", "path"], "Print the active SQLite database path.", domain="db", output_type="text"),
            CommandSpec("db-integrity", "Database integrity", [tool("netrune"), "db", "integrity"], "Run SQLite integrity checks without modifying state.", domain="db", output_type="table"),
            CommandSpec("db-repair", "Repair database", [tool("netrune"), "db", "repair"], "Reindex and repair recoverable SQLite structures, then verify integrity.", writes_local=True, domain="db", safety_class="local-write"),
            CommandSpec("db-history", "Command history", [tool("netrune"), "db", "history"], "Show recorded command executions with exit codes.", domain="db", output_type="table"),
            CommandSpec("db-prune", "Prune history", [tool("netrune"), "db", "prune"], "Delete operational history past its retention window; audit events are never pruned.", writes_local=True, domain="db", output_type="table", safety_class="local-write"),
            CommandSpec("db-vacuum", "Vacuum database", [tool("netrune"), "db", "vacuum"], "Compact the SQLite database.", writes_local=True, domain="db", safety_class="local-write"),
            CommandSpec("inventory-import-flat", "Import flat files", [tool("netrune"), "inventory", "import-flat"], "Import legacy flat caches into SQLite.", writes_local=True, domain="inventory"),
            CommandSpec("inventory-export-flat", "Export flat files", [tool("netrune"), "inventory", "export-flat"], "Export SQLite inventory back to legacy flat files.", writes_local=True, domain="inventory"),
            CommandSpec("inventory-scan", "Inventory scan", [tool("netrune"), "inventory", "scan", "<target>"], "Refresh switch/router inventory.", writes_local=True, args=["target"], domain="inventory"),
            CommandSpec("inventory-list", "Inventory list", [tool("netrune"), "inventory", "list", "<target>"], "Search current canonical device and AP inventory.", args=["target"], domain="inventory", output_type="table"),
            CommandSpec("inventory-details", "Inventory details", [tool("netrune"), "inventory", "details", "<target>"], "Collect detailed inventory for one target.", args=["target"], domain="inventory", output_type="table", safety_class="network-read"),
            CommandSpec("inventory-activity", "Inventory activity", [tool("netrune"), "inventory", "activity", "<target>"], "Ping one or more inventory targets and report current activity.", args=["target"], domain="inventory", output_type="table", safety_class="network-read"),
            CommandSpec("inventory-forget", "Forget a device", [tool("netrune"), "inventory", "forget", "<target>"], "Drop a device's inventory and derived state so the next scan adopts it afresh. Apply explicitly in the CLI with --confirm.", read_only=False, writes_local=False, args=["target"], domain="inventory", risk_level="warning", run_supported=False, safety_class="read-only"),
            CommandSpec("inventory-merge", "Preview device identity merge", [tool("netrune"), "inventory", "merge", "<source>", "<target>", "--reason", "<reason>", "--dry-run"], "Preview retiring an old device into a current device while preserving chronological evidence. Apply explicitly in the CLI with --confirm.", writes_local=False, args=["source", "target", "reason"], domain="inventory", risk_level="warning", run_supported=False, safety_class="read-only", arg_schema=[{"name":"source","label":"Historical Device","type":"text","required":True,"placeholder":"exact hostname or IP"},{"name":"target","label":"Current Device","type":"text","required":True,"placeholder":"exact hostname or IP"},{"name":"reason","label":"Audit Reason","type":"text","required":True,"placeholder":"approved replacement or correction"}]),
            CommandSpec("inventory-merges", "Manual identity merges", [tool("netrune"), "inventory", "merges"], "List active manual device merges and their chronology.", domain="inventory", output_type="table"),
            CommandSpec("inventory-unmerge", "Plan device merge revocation", [tool("netrune"), "inventory", "unmerge", "<merge_id>", "--reason", "<reason>"], "Prepare restoration of a manually retired source device. Apply explicitly in the CLI with --confirm.", writes_local=False, args=["merge_id", "reason"], domain="inventory", risk_level="warning", run_supported=False, safety_class="read-only", arg_schema=[{"name":"merge_id","label":"Merge ID","type":"text","required":True},{"name":"reason","label":"Revocation Reason","type":"text","required":True}]),
            CommandSpec("health-check", "Fast health check", [tool("netrune"), "health", "check", "<target>"], "Ping known/supplied devices and APs, then refresh health state.", writes_local=True, args=["target"], domain="health"),
            CommandSpec("health-status", "Health status", [tool("netrune"), "health", "status", "<target>"], "Read current canonical health, optionally filtered by target.", args=["target"], domain="health", output_type="table"),
            CommandSpec("health-offline", "Offline health records", [tool("netrune"), "health", "offline", "<target>"], "List current offline entities, optionally filtered by target.", args=["target"], domain="health", output_type="table"),
            CommandSpec("health-attention", "Health attention", [tool("netrune"), "health", "attention"], "Show health, topology, AP movement, and backup items needing review.", domain="health", output_type="table"),
            CommandSpec("health-timeline", "Health timeline", [tool("netrune"), "health", "timeline", "<target>"], "Read health state changes newest first.", args=["target"], domain="health", output_type="table"),
            CommandSpec("ap-scan", "AP scan", [tool("netrune"), "ap", "scan"], "Refresh AP inventory.", writes_local=True, domain="ap"),
            CommandSpec("ap-list", "AP list", [tool("netrune"), "ap", "list", "<target>"], "Search current reconciled AP inventory.", args=["target"], domain="ap", output_type="table"),
            CommandSpec("ap-unjoined", "Unjoined APs", [tool("netrune"), "ap", "unjoined", "<target>"], "List AP observations that are not joined to a controller.", args=["target"], domain="ap", output_type="table"),
            CommandSpec("ap-on-switch", "APs on switch", [tool("netrune"), "ap", "on-switch", "<target>"], "Show canonical APs attached to a switch or site.", args=["target"], domain="ap", output_type="table"),
            CommandSpec("ap-moves", "AP moves", [tool("netrune"), "ap", "moves"], "Show recorded AP attachment changes newest first.", domain="ap", output_type="table"),
            CommandSpec("ap-timeline", "AP timeline", [tool("netrune"), "ap", "timeline", "<target>"], "Show AP attachment history newest first.", args=["target"], domain="ap", output_type="table"),
            CommandSpec("ap-merge", "Preview AP identity merge", [tool("netrune"), "ap", "merge", "<source>", "<target>", "--reason", "<reason>", "--dry-run"], "Preview retiring an old AP into a current AP while preserving chronological evidence. Apply explicitly in the CLI with --confirm.", writes_local=False, args=["source", "target", "reason"], domain="ap", risk_level="warning", run_supported=False, safety_class="read-only", arg_schema=[{"name":"source","label":"Historical AP","type":"text","required":True,"placeholder":"exact AP name or IP"},{"name":"target","label":"Current AP","type":"text","required":True,"placeholder":"exact AP name or IP"},{"name":"reason","label":"Audit Reason","type":"text","required":True,"placeholder":"vendor replacement or correction"}]),
            CommandSpec("ap-merges", "Manual AP identity merges", [tool("netrune"), "ap", "merges"], "List active manual AP merges and their chronology.", domain="ap", output_type="table"),
            CommandSpec("ap-unmerge", "Plan AP merge revocation", [tool("netrune"), "ap", "unmerge", "<merge_id>", "--reason", "<reason>"], "Prepare restoration of a manually retired source AP. Apply explicitly in the CLI with --confirm.", writes_local=False, args=["merge_id", "reason"], domain="ap", risk_level="warning", run_supported=False, safety_class="read-only", arg_schema=[{"name":"merge_id","label":"Merge ID","type":"text","required":True},{"name":"reason","label":"Revocation Reason","type":"text","required":True}]),
            CommandSpec("topology-scan", "Topology scan", [tool("netrune"), "topology", "scan"], "Refresh LLDP/CDP topology.", writes_local=True, domain="topology"),
            CommandSpec("topology-stp", "Topology spanning tree", [tool("netrune"), "topology", "stp", "<target>"], "Read spanning tree from switches and derive switch links from designated-bridge addresses.", args=["target"], writes_local=True, domain="topology", output_type="table", safety_class="network-read"),
            CommandSpec("topology-links", "Topology spanning-tree links", [tool("netrune"), "topology", "links"], "Show spanning-tree derived switch links with source confidence.", domain="topology", output_type="table"),
            CommandSpec("topology-show", "Topology show", [tool("netrune"), "topology", "show", "<target>"], "Show topology, optionally querying one target.", args=["target"], domain="topology", output_type="table", safety_class="network-read"),
            CommandSpec("topology-changes", "Topology changes", [tool("netrune"), "topology", "changes"], "Show recorded topology changes newest first.", domain="topology", output_type="table"),
            CommandSpec("topology-timeline", "Topology timeline", [tool("netrune"), "topology", "timeline", "<target>"], "Show neighbor-link history newest first.", args=["target"], domain="topology", output_type="table"),
            CommandSpec("memory-refresh", "Memory refresh", [tool("netrune"), "memory", "refresh"], "Recompute relationship memory from canonical state.", writes_local=True, domain="memory"),
            CommandSpec("memory-switch", "Memory switch", [tool("netrune"), "memory", "switch", "<target>"], "Show APs, neighbors, relationships, and timeline for a switch/site.", args=["target"], domain="memory", output_type="table"),
            CommandSpec("memory-device", "Memory device", [tool("netrune"), "memory", "device", "<target>"], "Show current identity relationships and history for a device.", args=["target"], domain="memory", output_type="table"),
            CommandSpec("memory-ip", "Memory IP", [tool("netrune"), "memory", "ip", "<target>"], "Show historical ownership and relationship events for an IP.", args=["target"], domain="memory", output_type="table"),
            CommandSpec("memory-mac", "Memory MAC", [tool("netrune"), "memory", "mac", "<target>"], "Show identity and movement history for a MAC address.", args=["target"], domain="memory", output_type="table"),
            CommandSpec("memory-port", "Memory port", [tool("netrune"), "memory", "port", "<target>", "<interface>"], "Show current and historical occupancy for a switch port.", args=["target", "interface"], domain="memory", output_type="table"),
            CommandSpec("memory-timeline", "Memory timeline", [tool("netrune"), "memory", "timeline", "<target>"], "Search all relationship events newest first.", args=["target"], domain="memory", output_type="table"),
            CommandSpec("memory-explain", "Explain memory sources", [tool("netrune"), "memory", "explain", "<target>"], "Explain relationship sources, confidence, and last observations.", args=["target"], domain="memory", output_type="table"),
            CommandSpec("memory-export", "Export memory", [tool("netrune"), "memory", "export", "--json"], "Export all current relationships as JSON.", domain="memory", output_type="json"),
            CommandSpec("memory-prune", "Prune memory", [tool("netrune"), "memory", "prune"], "Memory pruning is intentionally disabled because history is retained by default.", read_only=False, writes_local=True, domain="memory", risk_level="danger", run_supported=False),
            CommandSpec("ask-query", "Natural Ask", [tool("netrune"), "ask", "<question>"], "Run a deterministic question workflow over current inventory and relationship memory.", args=["question"], domain="ask", output_type="table", examples=['netrune ask "How many APs are offline in ZONE10?"']),
            CommandSpec("ask-chat", "Ask chat", [tool("netrune"), "ask"], "Open the stateful Natural Ask terminal session.", domain="ask", output_type="terminal", run_supported=False),
            CommandSpec("ask-patterns", "Ask patterns", [tool("netrune"), "ask", "patterns"], "List supported retrieval and command-center examples.", domain="ask", output_type="table"),
            CommandSpec("ask-aliases", "Ask aliases", [tool("netrune"), "ask", "aliases"], "List deterministic phrase aliases.", domain="ask", output_type="table"),
            CommandSpec("ask-alias-set", "Set Ask alias", [tool("netrune"), "ask", "alias", "set", "<phrase>", "<alias_target>"], "Create or update a durable deterministic phrase alias.", writes_local=True, args=["phrase", "alias_target"], domain="ask", safety_class="local-write"),
            CommandSpec("ask-alias-remove", "Remove Ask alias", [tool("netrune"), "ask", "alias", "remove", "<phrase>"], "Remove a durable deterministic phrase alias.", writes_local=True, args=["phrase"], domain="ask", safety_class="local-write"),
            CommandSpec("backup-run", "Backup online", [tool("netrune"), "backup", "run", "<target>"], "Online-only changed-only config backup.", writes_local=True, args=["target"], domain="backup"),
            CommandSpec("backup-history", "Backup history", [tool("netrune"), "backup", "history", "<target>"], "Show backup history for a target.", args=["target"], domain="backup"),
            CommandSpec("backup-diff", "Backup diff", [tool("netrune"), "backup", "diff", "<target>"], "Diff latest changed backups for a target.", args=["target"], domain="backup"),
            CommandSpec("backup-verify", "Verify backups", [tool("netrune"), "backup", "verify"], "Review recorded backup checksums, paths, and statuses.", domain="backup", output_type="table"),
            CommandSpec("diagnose-latency", "Latency probe", [tool("netrune"), "diagnose", "latency", "<target>"], "Run latency probing.", writes_local=True, args=["target", "count"], domain="diagnose"),
            CommandSpec("diagnose-core-ping", "Point-of-truth core ping", [tool("netrune"), "diagnose", "core-ping", "<target>"], "Issue ICMP from the configured/selected core switch and store parsed latency.", writes_local=True, args=["target", "core", "count"], domain="diagnose", examples=["netrune diagnose core-ping 192.0.2.50 --count 5"]),
            CommandSpec("diagnose-speed", "Internet speed test", [tool("netrune"), "diagnose", "speed"], "Measure this Netrune host's routed Internet path with verified profile-based testing.", writes_local=True, args=["profile", "runs", "ca_file"], domain="diagnose", timeout_seconds=1800),
            CommandSpec("diagnose-throughput", "Controlled throughput", [tool("netrune"), "diagnose", "throughput", "<target>"], "Measure TCP receiver goodput between this client and a controlled iperf3 server.", writes_local=True, args=["target", "port", "seconds", "parallel", "direction", "bind"], domain="diagnose", timeout_seconds=720),
            CommandSpec("diagnose-port-health", "Port health", [tool("netrune"), "diagnose", "port-health", "<device>", "on", "<interface>"], "Sample link negotiation and switch error-counter deltas.", writes_local=True, args=["device", "interface", "sample_seconds", "expected_speed"], domain="diagnose", safety_class="network-read", timeout_seconds=240),
            CommandSpec("diagnose-cable", "Cable diagnostic status", [tool("netrune"), "diagnose", "cable", "<device>", "on", "<interface>"], "Read the last recorded copper cable/TDR result without starting a test.", writes_local=True, args=["device", "interface"], domain="diagnose", safety_class="network-read", timeout_seconds=180),
            CommandSpec("diagnose-cable-test", "Start cable diagnostic", [tool("netrune"), "diagnose", "cable", "<device>", "on", "<interface>", "--test", "--dry-run"], "Preview a potentially disruptive copper TDR. Confirmed execution remains CLI-only.", read_only=False, writes_local=True, args=["device", "interface", "wait"], domain="diagnose", risk_level="danger", run_supported=False, safety_class="disruptive"),
            CommandSpec("diagnose-doctor", "Diagnostic readiness", [tool("netrune"), "diagnose", "doctor"], "Audit diagnostic dependencies, routing, host limitations, trust, and core settings.", writes_local=True, args=["online"], domain="diagnose"),
            CommandSpec("diagnose-filtering", "Filtering check", [tool("netrune"), "diagnose", "filtering", "<target>"], "DNS/TLS/filtering diagnostics.", writes_local=True, args=["target"], domain="diagnose"),
            CommandSpec("diagnose-interface", "Interface monitor", [tool("netrune"), "diagnose", "interface", "<device>", "on", "<interface>"], "Legacy interface rate monitor; command-center jobs default to one finite sample.", writes_local=True, args=["device", "interface", "chart", "once"], domain="diagnose"),
            CommandSpec("lookup-core", "Core lookup", [tool("netrune"), "lookup", "core", "<target>"], "Core IP/MAC lookup cached into memory.", writes_local=True, args=["target"], domain="lookup"),
            CommandSpec("lookup-mac", "MAC lookup", [tool("netrune"), "lookup", "mac", "<target>", "<mac>"], "MAC lookup from one target or from all current switches with target=all.", writes_local=True, args=["target", "mac"], domain="lookup", timeout_seconds=120),
            CommandSpec("lookup-mac-all", "MAC search across switches", [tool("netrune"), "lookup", "mac", "all", "<mac>"], "Search every online switch for a MAC and separate the access port it is attached to from the uplinks it transits.", args=["mac"], writes_local=True, domain="lookup", output_type="table", safety_class="network-read"),
            CommandSpec("lookup-mac-inspect", "MAC evidence inspection", [tool("netrune"), "lookup", "mac", "inspect", "<mac>"], "Correlate cached MAC identity, location, IP, vendor, and history evidence.", args=["mac"], domain="lookup", output_type="table"),
            CommandSpec("lookup-mac-locate", "Direct MAC location", [tool("netrune"), "lookup", "mac", "locate", "<mac>"], "Search switch forwarding tables without requiring an endpoint IP.", writes_local=True, args=["mac", "scope"], domain="lookup", timeout_seconds=0),
            CommandSpec("lookup-mac-profile", "MAC edge profile", [tool("netrune"), "lookup", "mac", "profile", "<mac>"], "Locate a MAC and profile likely edge ports with interface, LLDP/CDP, PoE, device-tracking, and core evidence.", writes_local=True, args=["mac", "scope"], domain="lookup", timeout_seconds=0),
            CommandSpec("lookup-mac-history", "MAC movement history", [tool("netrune"), "lookup", "mac", "history", "<mac>"], "Show newest-first identity and switch-port events for a MAC.", args=["mac"], domain="lookup", output_type="table"),
            CommandSpec("lookup-mac-vendor", "MAC OUI vendor", [tool("netrune"), "lookup", "mac", "vendor", "<mac>"], "Resolve a MAC prefix from the locally installed OUI database.", args=["mac"], domain="lookup", output_type="text"),
            CommandSpec("lookup-mac-online", "IEEE MAC assignment", [tool("netrune"), "lookup", "mac", "online", "<mac>"], "Resolve the longest authoritative IEEE MA-L/MA-M/MA-S assignment with cache provenance.", writes_local=True, args=["mac"], domain="lookup", output_type="table", safety_class="network-read"),
            CommandSpec("lookup-mac-registry", "IEEE MAC registry status", [tool("netrune"), "lookup", "mac", "registry", "status"], "Show cached IEEE registry files, row counts, checksums, sources, and last refresh time.", domain="lookup", output_type="table"),
            CommandSpec("lookup-mac-registry-refresh", "Refresh IEEE MAC registry", [tool("netrune"), "lookup", "mac", "registry", "refresh"], "Refresh all IEEE public MAC assignment CSV registries into the private local cache.", writes_local=True, domain="lookup", output_type="table", safety_class="network-read"),
            CommandSpec("device-show", "Device show", [tool("netrune"), "device", "show", "<target>", "<command>"], "Run a policy-checked read-only show command.", args=["target", "command"], domain="device", safety_class="network-read"),
            CommandSpec("device-ssh", "Device SSH", [tool("netrune"), "device", "ssh", "<target>"], "Open an interactive SSH session in a terminal.", args=["target"], domain="device", output_type="terminal", run_supported=False),
            CommandSpec("device-inventory", "Device inventory", [tool("netrune"), "device", "inventory", "<target>"], "Run the device inventory helper for one target.", args=["target"], domain="device", safety_class="network-read"),
            CommandSpec("device-support", "Device support profile", [tool("netrune"), "device", "support", "<target>"], "Classify a device and show driver capability maturity for Cisco, Aruba, or Ruckus.", args=["target"], domain="device", output_type="table"),
            CommandSpec("device-identity", "Device identity comparison", [tool("netrune"), "device", "identity", "<target>", "<target2>"], "Explain confidence and conflicts between two switch identity records.", args=["target", "target2"], domain="device", output_type="table"),
            CommandSpec("device-trust-status", "SSH trust status", [tool("netrune"), "device", "trust", "status", "<target>"], "Inspect managed SSH host-key fingerprints without network access.", args=["target"], domain="device", output_type="table"),
            CommandSpec("device-trust-scan", "Scan SSH host keys", [tool("netrune"), "device", "trust", "scan", "<target>"], "Retrieve SSH host keys and SHA-256 fingerprints without enrolling them.", args=["target"], domain="device", output_type="table", safety_class="network-read"),
            CommandSpec("device-trust-enroll", "Enroll SSH host key", [tool("netrune"), "device", "trust", "enroll", "<target>", "--fingerprint", "<fingerprint>", "--confirm"], "Enroll only an out-of-band verified SSH host-key fingerprint.", writes_local=True, args=["target", "fingerprint"], domain="device", output_type="table", safety_class="local-write"),
            CommandSpec("device-trust-forget", "Forget SSH host key", [tool("netrune"), "device", "trust", "forget", "<target>", "--confirm"], "Remove a target from the managed SSH trust store.", writes_local=True, args=["target"], domain="device", output_type="table", safety_class="local-write"),
            CommandSpec("workflow-morning-check", "Morning check", [tool("netrune"), "workflow", "morning-check"], "Health, topology refresh, memory, filtering, and attention summary.", writes_local=True, domain="workflow"),
            CommandSpec("workflow-refresh-inventory", "Refresh inventory", [tool("netrune"), "workflow", "refresh-inventory"], "Health, AP, topology, and memory refresh.", writes_local=True, domain="workflow"),
            CommandSpec("workflow-backup-online", "Backup online workflow", [tool("netrune"), "workflow", "backup-online", "<target>"], "Changed-only backups for online devices.", writes_local=True, args=["target"], domain="workflow"),
            CommandSpec("workflow-site-health", "Site health", [tool("netrune"), "workflow", "site-health", "<target>"], "Latency and filtering checks for a target/site.", writes_local=True, args=["target"], domain="workflow"),
            CommandSpec("workflow-ap-audit", "AP audit", [tool("netrune"), "workflow", "ap-audit"], "Refresh AP records and show AP moves.", writes_local=True, domain="workflow"),
            CommandSpec("vlan-locate", "Locate VLAN", [tool("netrune"), "vlan", "locate", "<target>", "<vlan>"], "Locate one or many VLANs from one or many roots; optional depth traverses LLDP/CDP-confirmed switch links.", args=["target", "vlan", "depth", "max_nodes", "refresh_neighbors"], domain="vlan", safety_class="network-read"),
            CommandSpec("vlan-propagation", "VLAN propagation", [tool("netrune"), "vlan", "propagation", "<target>", "<vlan>"], "Trace a root-by-VLAN matrix with bounded breadth-first switch traversal.", args=["target", "vlan", "depth", "max_nodes", "refresh_neighbors"], domain="vlan", safety_class="network-read"),
            CommandSpec("commands-list", "Commands list", [tool("netrune"), "commands", "list"], "List the structured command registry and safety metadata.", domain="commands", output_type="table"),
            CommandSpec("commands-show", "Command details", [tool("netrune"), "commands", "show", "<action>"], "Show metadata for one registry action.", args=["action"], domain="commands", output_type="table"),
            CommandSpec("commands-run", "Registry command runner", [tool("netrune"), "commands", "run", "<action>", "--preview"], "Meta-action for previewing a registry command. Ask plans the selected action directly.", args=["action"], domain="commands", run_supported=False),
            CommandSpec("device-config", "Device config preview", [tool("netrune"), "device", "config", "<target>", "<commands>"], "Preview/confirmed config command wrapper, one device or a batch (comma list, --target, or --file; --commands-file, --skip-offline, --cisco/--aruba/--ruckus). Confirmed execution stays in the CLI.", read_only=False, writes_local=True, args=["target", "commands"], domain="device", risk_level="config", run_supported=False),
            CommandSpec(
                "vlan-set", "Guarded VLAN change", [tool("netrune"), "vlan", "set", "<target>", "<interface>", "<vlan_mode>", "<vlan>"],
                "Back up, apply, and verify one typed access or trunk VLAN change through the audited core -- one device or (--file) a batch of independent target/interface/vlan lines.",
                read_only=False, writes_local=True, args=["target", "interface", "vlan_mode", "vlan", "native_vlan", "replace"],
                domain="vlan", risk_level="config", run_supported=True, timeout_seconds=600,
                arg_schema=[
                    {"name":"target", "label":"Switch", "type":"text", "required":True, "placeholder":"hostname or IP"},
                    {"name":"interface", "label":"Interface", "type":"text", "required":True, "placeholder":"Gi1/0/7"},
                    {"name":"vlan_mode", "label":"Port mode", "type":"select", "required":True, "options":["access", "trunk"]},
                    {"name":"vlan", "label":"VLAN or allowed list", "type":"text", "required":True, "placeholder":"131 or 10,20,100-120"},
                    {"name":"native_vlan", "label":"Native VLAN", "type":"number", "required":False, "min":1, "max":4094},
                    {"name":"replace", "label":"Replace trunk allowed list", "type":"boolean", "required":False},
                ],
                state_effects=["device-config", "configuration-backup", "post-change-verification", "audit-event"],
            ),
        ]

    def command_aliases(self) -> Dict[str, str]:
        return {
            "db-import": "inventory-import-flat", "db-export": "inventory-export-flat", "discover-update": "inventory-scan",
            "discover-fast-health": "health-check", "discover-aps": "ap-scan", "discover-neighbors": "topology-scan",
            "probe-target": "diagnose-latency", "probe-speed": "diagnose-speed", "filtering-check": "diagnose-filtering",
            "netcheck": "diagnose-filtering", "interface-sample": "diagnose-interface", "backup-online": "backup-run",
            "memory-query": "memory-switch", "discover-activity": "inventory-activity", "db-import-flat": "inventory-import-flat",
            "db-export-flat": "inventory-export-flat", "ap-show": "ap-list", "topology-show-cached": "topology-show",
        }

    def command_spec(self, action: str) -> Optional[CommandSpec]:
        wanted = self.command_aliases().get(str(action or ""), str(action or ""))
        return next((c for c in self.command_registry() if c.id == wanted), None)

    def command_dict(self, spec: CommandSpec) -> Dict[str, Any]:
        payload = spec.as_dict()
        required = set(self.command_required_args(spec))
        for field in payload.get("arg_schema") or []:
            field["required"] = field.get("name") in required
        return payload

    def command_payload(self) -> Dict[str, Any]:
        return {"ok": True, "commands": [self.command_dict(c) for c in self.command_registry()]}

    def parse_registry_args(self, args: Sequence[str]) -> Dict[str, Any]:
        out: Dict[str, Any] = {}; pos: List[str] = []; i = 0
        while i < len(args):
            item = str(args[i])
            if item.startswith("--"):
                key = item[2:].replace("-", "_")
                if i + 1 < len(args) and not str(args[i + 1]).startswith("--"):
                    out[key] = args[i + 1]; i += 2
                else:
                    out[key] = True; i += 1
            else:
                pos.append(item); i += 1
        if pos:
            out.setdefault("target", pos[0])
            out.setdefault("positional", pos)
        if len(pos) > 1:
            out.setdefault("command", " ".join(pos[1:]))
            out.setdefault("mac", pos[-1])
            out.setdefault("interface", pos[1])
        return out

    def command_required_args(self, spec: CommandSpec) -> List[str]:
        optional = {
            "inventory-scan": {"target"}, "inventory-list": {"target"},
            "health-check": {"target"}, "health-status": {"target"}, "health-offline": {"target"}, "health-timeline": {"target"},
            "ap-list": {"target"}, "ap-unjoined": {"target"}, "ap-timeline": {"target"},
            "topology-show": {"target"}, "topology-timeline": {"target"},
            "memory-timeline": {"target"}, "memory-explain": {"target"},
            "diagnose-latency": {"count"}, "diagnose-speed": {"runs", "profile"}, "diagnose-filtering": {"target"},
            "diagnose-core-ping": {"core", "count"}, "diagnose-interface": {"chart"}, "lookup-mac": {"target"},
            "lookup-mac-locate": {"scope"}, "lookup-mac-profile": {"scope"},
            "vlan-locate": {"depth", "max_nodes", "refresh_neighbors"},
            "vlan-propagation": {"depth", "max_nodes", "refresh_neighbors"},
            "device-trust-status": {"target"},
            "profile-show": {"name"}, "profile-migrate-legacy": {"name"},
            "ingest-rejects": {"run_id"}, "ingest-observations": {"channel"},
            "plugin-check": {"group"}, "path-history": {"endpoint", "vlan"}, "path-show": {"vlan"},
            "path-inspect": {"source", "destination", "depth", "max_nodes", "mode", "explain"},
        }.get(spec.id, set())
        return [field["name"] for field in spec.inferred_arg_schema() if field.get("required") and field["name"] not in optional]

    def _template_command(self, spec: CommandSpec, args: Dict[str, Any]) -> List[str]:
        if spec.id == "vlan-set":
            target = str(args.get("target") or "<target>").strip()
            interface = str(args.get("interface") or args.get("port") or "<interface>").strip()
            mode = str(args.get("vlan_mode") or args.get("mode") or "access").strip().lower()
            vlan = str(args.get("vlan") or "<vlan>").strip()
            return [self.paths.tool("netrune"), "vlan", "set", target, interface, f"--{mode}", vlan, "--dry-run"]
        rendered: List[str] = []
        for token in spec.command:
            key_match = re.fullmatch(r"<([^>]+)>", str(token))
            if not key_match:
                rendered.append(str(token))
                continue
            key = key_match.group(1)
            value = args.get(key)
            if key == "device" and not value:
                value = args.get("target")
            if key == "interface" and not value:
                value = args.get("port")
            if value not in (None, "", []):
                rendered.extend(str(item) for item in value) if isinstance(value, (list, tuple)) else rendered.append(str(value))
            else:
                rendered.append(str(token))
        if spec.id == "device-config":
            rendered.append("--dry-run")
        return rendered

    def preview_for_action(self, action: str, args: Dict[str, Any]) -> Dict[str, Any]:
        spec = self.command_spec(action)
        if not spec:
            raise ValueError(f"Unknown action: {action}")
        args = dict(args or {})
        missing = [name for name in self.command_required_args(spec) if args.get(name) in (None, "", []) and not (name == "device" and args.get("target"))]
        validation_error = ""
        try:
            cmd, read_only, writes_local = self.command_for_action(spec.id, args) if not missing and spec.run_supported else (self._template_command(spec, args), spec.read_only, spec.writes_local)
        except PermissionError:
            cmd, read_only, writes_local = self._template_command(spec, args), spec.read_only, spec.writes_local
        except ValueError as exc:
            validation_error = str(exc)
            cmd, read_only, writes_local = self._template_command(spec, args), spec.read_only, spec.writes_local
        blocked = bool(validation_error) or spec.risk_level == "danger" or not spec.run_supported
        if validation_error:
            reason = validation_error
        elif spec.risk_level == "config" and not spec.run_supported:
            reason = "Configuration execution is blocked in Ask/API/WebUI; review the preview and run explicitly in the CLI with --confirm."
        elif spec.output_type == "terminal":
            reason = "Interactive commands must be run from a terminal."
        elif not spec.run_supported:
            reason = "This action is preview-only in the command center."
        else:
            reason = ""
        return {
            "ok": not missing and not validation_error,
            "action": spec.id,
            "command": shlex.join(cmd),
            "args": args,
            "missing_args": missing,
            "read_only": read_only,
            "writes_local": writes_local,
            "blocked": blocked,
            "reason": reason,
            "risk_level": spec.risk_level,
            "safety_class": spec.effective_safety_class(),
            "run_supported": spec.run_supported,
            "validation_error": validation_error,
            "requires_confirmation": spec.effective_safety_class() != "read-only",
        }

    def command_for_action(self, action: str, args: Dict[str, Any]) -> Tuple[List[str], bool, bool]:
        args = args or {}
        action = self.command_aliases().get(str(action or ""), str(action or ""))
        tool = self.paths.tool
        target = normalize_target_literal(str(args.get("target") or args.get("query") or "").strip())
        simple: Dict[str, List[str]] = {
            "db-migrate": ["db", "migrate"], "db-status": ["db", "status"], "db-path": ["db", "path"],
            "db-integrity": ["db", "integrity"], "db-repair": ["db", "repair"], "db-vacuum": ["db", "vacuum"], "db-prune": ["db", "prune"], "db-history": ["db", "history"],
            "health-attention": ["health", "attention"], "ap-moves": ["ap", "moves"],
            "topology-changes": ["topology", "changes"], "memory-export": ["memory", "export", "--json"],
            "ask-patterns": ["ask", "patterns"], "ask-aliases": ["ask", "aliases"],
            "backup-verify": ["backup", "verify"], "commands-list": ["commands", "list"],
            "init-run": ["init"], "profile-list": ["profile", "list"], "profile-paths": ["profile", "paths"],
            "config-show": ["config", "show"], "config-validate": ["config", "validate"], "config-paths": ["config", "paths"],
            "secrets-list": ["secrets", "list"], "secrets-status": ["secrets", "status"],
            "ingest-channels": ["ingest", "channels"], "ingest-validate": ["ingest", "validate"], "ingest-history": ["ingest", "history"],
            "plugin-list": ["plugin", "list"], "plugin-groups": ["plugin", "groups"],
            "support-bundle": ["support", "bundle"], "inventory-merges": ["inventory", "merges"], "ap-merges": ["ap", "merges"],
            "vault-status": ["vault", "status"],
            "lookup-mac-registry": ["lookup", "mac", "registry", "status"],
            "lookup-mac-registry-refresh": ["lookup", "mac", "registry", "refresh"],
        }
        if action in simple:
            return [tool("netrune"), *simple[action]], True, action in {"db-migrate", "db-repair", "db-vacuum", "db-prune", "traffic-poll", "init-run", "ingest-channels", "support-bundle", "lookup-mac-registry-refresh"}
        if action in {"profile-show", "profile-create", "profile-use", "profile-migrate-legacy"}:
            name = str(args.get("name") or "").strip()
            verb = action.removeprefix("profile-")
            command = [tool("netrune"), "profile", verb]
            if name: command.append(name)
            return command, True, action in {"profile-create", "profile-use", "profile-migrate-legacy"}
        if action in {"config-get", "config-set", "config-unset"}:
            key = str(args.get("key") or "").strip()
            if not key: raise ValueError(f"{action} requires key")
            command = [tool("netrune"), "config", action.removeprefix("config-"), key]
            if action == "config-set":
                value = str(args.get("value") or "")
                if not value: raise ValueError("config-set requires value")
                command.append(value)
            return command, True, action != "config-get"
        if action == "ingest-run":
            channel = str(args.get("channel") or "").strip()
            if not channel: raise ValueError("ingest-run requires channel")
            return [tool("netrune"), "ingest", "run", channel], True, True
        if action in {"ingest-rejects", "ingest-observations"}:
            value = str(args.get("run_id") or args.get("channel") or "").strip()
            return [tool("netrune"), "ingest", action.removeprefix("ingest-")] + ([value] if value else []), True, False
        if action in {"plugin-enable", "plugin-disable"}:
            plugin_id = str(args.get("plugin_id") or "").strip()
            if not plugin_id: raise ValueError(f"{action} requires plugin_id")
            return [tool("netrune"), "plugin", action.removeprefix("plugin-"), plugin_id], True, True
        if action == "plugin-check":
            group = str(args.get("group") or "").strip()
            return [tool("netrune"), "plugin", "check"] + ([group] if group else []), True, False
        if action == "traffic-stack":
            return [tool("netrune"), "traffic", "stack", "init"], True, True
        if action == "traffic-backfill":
            return [tool("netrune"), "traffic", "backfill"], True, False
        if action == "traffic-verify":
            return [tool("netrune"), "traffic", "verify"], True, False
        if action == "traffic-export":
            return [tool("netrune"), "traffic", "export"], True, False
        if action == "traffic-remote":
            return [tool("netrune"), "traffic", "remote", "list"], True, False
        if action == "traffic-pull":
            remote = str(args.get("remote") or "").strip()
            if not remote: raise ValueError("traffic-pull requires a remote")
            return [tool("netrune"), "traffic", "pull", "--remote", remote], True, True
        if action in {"traffic-list", "traffic-poll", "traffic-show", "traffic-daemon", "traffic-report",
                      "traffic-exporter", "traffic-health", "traffic-dashboard"}:
            return [tool("netrune"), "traffic", action.removeprefix("traffic-")], True, action in {"traffic-poll", "traffic-daemon", "traffic-report"}
        if action == "traffic-subscribe":
            target = str(args.get("target") or "").strip()
            down = str(args.get("down") or "").strip()
            if not target or not down: raise ValueError("traffic-subscribe requires a target and a rate")
            return [tool("netrune"), "traffic", "subscribe", target, "--down", down], True, True
        if action in {"setup-poller", "setup-local"}:
            community = str(args.get("community") or "").strip()
            if not community: raise ValueError(f"{action} requires a community")
            return [tool("netrune"), "setup", action.removeprefix("setup-"),
                    "--community", community], True, True
        if action == "traffic-push":
            to = str(args.get("to") or "").strip()
            if not to: raise ValueError("traffic-push requires a storage url")
            # Writes to the receiving machine's store, not to this one's.
            return [tool("netrune"), "traffic", "push", "--to", to], True, False
        if action == "traffic-name":
            target = str(args.get("target") or "").strip()
            name = str(args.get("name") or "").strip()
            if not target or not name: raise ValueError("traffic-name requires a target and a name")
            return [tool("netrune"), "traffic", "name", target, name], True, True
        if action == "traffic-interval":
            target = str(args.get("target") or "").strip()
            seconds = str(args.get("seconds") or "").strip()
            if not target or not seconds.isdigit(): raise ValueError("traffic-interval requires target and seconds")
            return [tool("netrune"), "traffic", "interval", target, seconds], True, True
        if action == "traffic-status":
            return [tool("netrune"), "traffic", "status"], True, False
        if action in {"traffic-watch", "traffic-ping", "traffic-unwatch", "traffic-interfaces",
                      "traffic-pause", "traffic-resume"}:
            verb = action.removeprefix("traffic-")
            if verb == "watch":
                device = str(args.get("device") or "").strip()
                interface = str(args.get("interface") or "").strip()
                if not device or not interface: raise ValueError("traffic-watch requires device and interface")
                return [tool("netrune"), "traffic", "watch", device, interface], True, True
            key = {"ping": "target", "unwatch": "target", "interfaces": "device",
                   "pause": "target", "resume": "target"}[verb]
            value = str(args.get(key) or "").strip()
            if not value: raise ValueError(f"{action} requires {key}")
            return [tool("netrune"), "traffic", verb, value], True, verb != "interfaces"
        if action == "inventory-forget":
            target = str(args.get("target") or "").strip()
            if not target: raise ValueError("inventory-forget requires target")
            return [tool("netrune"), "inventory", "forget", target], True, False
        if action == "path-findings":
            return [tool("netrune"), "path", "findings"], True, False
        if action == "path-history":
            endpoint = str(args.get("endpoint") or "").strip()
            vlan = str(args.get("vlan") or "").strip()
            command = [tool("netrune"), "path", "history"] + ([endpoint] if endpoint else [])
            if vlan:
                if not vlan.isdigit() or not 1 <= int(vlan) <= 4094: raise ValueError("vlan must be between 1 and 4094")
                command.extend(("--vlan", vlan))
            return command, True, False
        if action == "path-show":
            reference = str(args.get("reference") or args.get("run_id") or args.get("endpoint") or "").strip()
            if not reference: raise ValueError("path-show requires a run ID, prefix, endpoint, or 'last'")
            command = [tool("netrune"), "path", "show", reference]
            vlan = str(args.get("vlan") or "").strip()
            if vlan:
                if not vlan.isdigit() or not 1 <= int(vlan) <= 4094: raise ValueError("vlan must be between 1 and 4094")
                command.extend(("--vlan", vlan))
            return command, True, False
        if action == "path-inspect":
            endpoint = str(args.get("endpoint") or args.get("target") or "").strip()
            vlan = str(args.get("vlan") or "").strip()
            if not endpoint or not vlan: raise ValueError("path-inspect requires endpoint and vlan")
            if not vlan.isdigit() or not 1 <= int(vlan) <= 4094:
                raise ValueError("vlan must be between 1 and 4094")
            command = [tool("netrune"), "path", "inspect", endpoint, "--vlan", vlan]
            for key, flag, minimum, maximum in (
                ("depth", "--depth", 1, 16),
                ("max_nodes", "--max-nodes", 1, 256),
            ):
                if args.get(key) in (None, ""):
                    continue
                try:
                    value = int(args[key])
                except (TypeError, ValueError) as exc:
                    raise ValueError(f"{key} must be an integer between {minimum} and {maximum}") from exc
                if not minimum <= value <= maximum:
                    raise ValueError(f"{key} must be between {minimum} and {maximum}")
                command += [flag, str(value)]
            for key, flag in (("source", "--from"), ("destination", "--to")):
                if args.get(key) not in (None, ""):
                    command += [flag, str(args[key])]
            mode = str(args.get("mode") or "").strip()
            if mode in {"cached", "live"}: command.append("--" + mode)
            elif mode == "hybrid": command.append("--refresh")
            elif mode:
                raise ValueError("mode must be cached, hybrid, or live")
            if str(args.get("explain") or "").lower() in {"1", "true", "yes", "on"}: command.append("--explain")
            return command, True, True
        if action == "inventory-import-flat": return [tool("netrune"), "inventory", "import-flat"], True, True
        if action == "inventory-export-flat": return [tool("netrune"), "inventory", "export-flat"], True, True
        if action == "inventory-scan": return [tool("netrune"), "inventory", "scan"] + ([target] if target else []), True, True
        if action == "inventory-list":
            return [tool("netrune"), "inventory", "list"] + ([target] if target and not is_all_keyword(target) else []), True, False
        if action in {"inventory-details", "inventory-activity"}:
            if not target: raise ValueError(f"{action} requires target")
            return [tool("netrune"), "inventory", action.removeprefix("inventory-"), target], True, False
        if action == "health-check": return [tool("netrune"), "health", "check"] + ([target] if target else []), True, True
        if action in {"health-status", "health-offline", "health-timeline"}:
            return [tool("netrune"), "health", action.removeprefix("health-")] + ([target] if target else []), True, False
        if action == "ap-scan": return [tool("netrune"), "ap", "scan"], True, True
        if action in {"ap-list", "ap-unjoined", "ap-timeline"}:
            return [tool("netrune"), "ap", action.removeprefix("ap-")] + ([target] if target else []), True, False
        if action == "ap-on-switch":
            if not target: raise ValueError("ap-on-switch requires target")
            return [tool("netrune"), "ap", "on-switch", target], True, False
        if action == "topology-scan": return [tool("netrune"), "topology", "scan"], True, True
        if action == "topology-stp":
            return [tool("netrune"), "topology", "stp"] + ([target] if target and not is_all_keyword(target) else []), True, True
        if action == "topology-links": return [tool("netrune"), "topology", "links"], True, False
        if action in {"topology-show", "topology-timeline"}:
            return [tool("netrune"), "topology", action.removeprefix("topology-")] + ([target] if target else []), True, False
        if action == "memory-refresh": return [tool("netrune"), "memory", "refresh"], True, True
        if action == "ask-query":
            question = str(args.get("question") or args.get("query") or args.get("target") or "").strip()
            if not question: raise ValueError("ask-query requires question")
            return [tool("netrune"), "ask", question], True, False
        if action == "ask-alias-set":
            phrase = str(args.get("phrase") or "").strip(); alias_target = str(args.get("alias_target") or "").strip()
            if not phrase or not alias_target: raise ValueError("ask-alias-set requires phrase and alias_target")
            return [tool("netrune"), "ask", "alias", "set", phrase, alias_target], True, True
        if action == "ask-alias-remove":
            phrase = str(args.get("phrase") or "").strip()
            if not phrase: raise ValueError("ask-alias-remove requires phrase")
            return [tool("netrune"), "ask", "alias", "remove", phrase], True, True
        if action == "memory-switch":
            if not target: raise ValueError("memory-switch requires target")
            return [tool("netrune"), "memory", "switch", target], True, False
        if action == "memory-ip":
            if not target: raise ValueError("memory-ip requires target")
            return [tool("netrune"), "memory", "ip", target], True, False
        if action == "memory-mac":
            if not target: raise ValueError("memory-mac requires target")
            return [tool("netrune"), "memory", "mac", target], True, False
        if action == "memory-port":
            iface = str(args.get("interface") or args.get("port") or "").strip()
            if not target or not iface: raise ValueError("memory-port requires target and interface")
            return [tool("netrune"), "memory", "port", target, iface], True, False
        if action == "memory-device":
            if not target: raise ValueError("memory-device requires target")
            return [tool("netrune"), "memory", "device", target], True, False
        if action in {"memory-timeline", "memory-explain"}:
            return [tool("netrune"), "memory", action.removeprefix("memory-")] + ([target] if target else []), True, False
        if action == "backup-run":
            if not target: raise ValueError("backup-run requires target")
            return [tool("netrune"), "backup", "run", target], True, True
        if action == "backup-history":
            if not target: raise ValueError("backup-history requires target")
            return [tool("netrune"), "backup", "history", target], True, False
        if action == "backup-diff":
            if not target: raise ValueError("backup-diff requires target")
            return [tool("netrune"), "backup", "diff", target], True, False
        if action == "diagnose-latency":
            if not target: raise ValueError("diagnose-latency requires target")
            cmd = [tool("netrune"), "diagnose", "latency", target]
            if args.get("count"): cmd += ["--count", str(args.get("count"))]
            return cmd, True, True
        if action == "diagnose-core-ping":
            if not target: raise ValueError("diagnose-core-ping requires target")
            cmd = [tool("netrune"), "diagnose", "core-ping", target]
            if args.get("core"): cmd += ["--core", str(args.get("core"))]
            if args.get("count"): cmd += ["--count", str(args.get("count"))]
            return cmd, True, True
        if action == "diagnose-speed":
            cmd = [tool("netrune"), "diagnose", "speed"]
            if args.get("profile"): cmd += ["--profile", str(args.get("profile"))]
            if args.get("runs"): cmd += ["--runs", str(args.get("runs"))]
            if args.get("ca_file"): cmd += ["--ca-file", str(args.get("ca_file"))]
            return cmd, True, True
        if action == "diagnose-throughput":
            if not target: raise ValueError("diagnose-throughput requires an iperf3 server")
            cmd = [tool("netrune"), "diagnose", "throughput", target]
            for key, flag in (("port","--port"),("seconds","--seconds"),("parallel","--parallel"),("direction","--direction"),("bind","--bind")):
                if args.get(key) not in (None, ""): cmd += [flag, str(args.get(key))]
            return cmd, True, True
        if action == "diagnose-port-health":
            device = str(args.get("device") or target or "").strip(); iface = str(args.get("interface") or args.get("port_name") or "").strip()
            if not device or not iface: raise ValueError("diagnose-port-health requires device and interface")
            cmd = [tool("netrune"), "diagnose", "port-health", device, "on", iface]
            if args.get("sample_seconds") not in (None, ""): cmd += ["--sample-seconds", str(args.get("sample_seconds"))]
            if args.get("expected_speed") not in (None, ""): cmd += ["--expected-speed", str(args.get("expected_speed"))]
            return cmd, True, True
        if action == "diagnose-cable":
            device = str(args.get("device") or target or "").strip(); iface = str(args.get("interface") or args.get("port") or "").strip()
            if not device or not iface: raise ValueError("diagnose-cable requires device and interface")
            return [tool("netrune"), "diagnose", "cable", device, "on", iface], True, True
        if action == "diagnose-doctor":
            cmd = [tool("netrune"), "diagnose", "doctor"]
            if str(args.get("online") or "").lower() in {"1", "true", "yes", "on"}: cmd.append("--online")
            return cmd, True, True
        if action == "diagnose-filtering": return [tool("netrune"), "diagnose", "filtering"] + ([target] if target else []), True, True
        if action == "diagnose-interface":
            device = str(args.get("device") or target or "").strip(); iface = str(args.get("interface") or args.get("port") or "").strip()
            if not device or not iface: raise ValueError("diagnose-interface requires device and interface")
            cmd = [tool("netrune"), "diagnose", "interface", device, "on", iface]
            if args.get("chart"): cmd += ["--chart", str(args.get("chart"))]
            if str(args.get("once", True)).lower() not in {"0", "false", "no", "off"}: cmd += ["--once"]
            return cmd, True, True
        if action == "lookup-core":
            if not target: raise ValueError("lookup-core requires target")
            return [tool("netrune"), "lookup", "core", target], True, True
        if action == "lookup-mac":
            mac = str(args.get("mac") or "").strip()
            if not mac and target: mac = target; target = ""
            if not mac: raise ValueError("lookup-mac requires mac")
            if str(args.get("all") or "").lower() in {"1", "true", "yes"} or target.lower() == "all":
                return [tool("netrune"), "lookup", "mac", "all", mac], True, True
            return [tool("netrune"), "lookup", "mac"] + ([target] if target else []) + [mac], True, True
        if action in {"lookup-mac-all", "lookup-mac-inspect", "lookup-mac-locate", "lookup-mac-profile", "lookup-mac-history", "lookup-mac-vendor"}:
            mac = str(args.get("mac") or args.get("target") or "").strip()
            if not norm_mac(mac): raise ValueError(f"{action} requires a valid physical unicast MAC")
            subaction = action.removeprefix("lookup-mac-")
            cmd = [tool("netrune"), "lookup", "mac", subaction, mac]
            scope = str(args.get("scope") or "").strip()
            if scope and action in {"lookup-mac-locate", "lookup-mac-profile"}: cmd.append(scope)
            return cmd, True, action in {"lookup-mac-all", "lookup-mac-locate", "lookup-mac-profile"}
        if action == "lookup-mac-online":
            mac = str(args.get("mac") or args.get("target") or "").strip()
            if not norm_mac(mac): raise ValueError("lookup-mac-online requires a valid physical unicast MAC")
            cmd = [tool("netrune"), "lookup", "mac", "online", mac]
            if str(args.get("refresh") or "").lower() in {"1", "true", "yes", "on"}: cmd.append("--refresh")
            if str(args.get("offline") or "").lower() in {"1", "true", "yes", "on"}: cmd.append("--offline")
            return cmd, True, True
        if action == "device-show":
            command = str(args.get("command") or "").strip()
            if not target or not command: raise ValueError("device-show requires target and command")
            if not self.safe_show_command(command): raise ValueError("device-show accepts only policy-approved show/display/get commands")
            return [tool("netrune"), "device", "show", target, command], True, False
        if action == "device-ssh":
            if not target: raise ValueError("device-ssh requires target")
            return [tool("netrune"), "device", "ssh", target], True, False
        if action == "device-inventory":
            if not target: raise ValueError("device-inventory requires target")
            return [tool("netrune"), "device", "inventory", target], True, False
        if action == "device-support":
            if not target: raise ValueError("device-support requires target")
            return [tool("netrune"), "device", "support", target], True, False
        if action == "device-identity":
            target2 = normalize_target_literal(str(args.get("target2") or "").strip())
            if not target or not target2: raise ValueError("device-identity requires target and target2")
            return [tool("netrune"), "device", "identity", target, target2], True, False
        if action == "device-trust-status":
            return [tool("netrune"), "device", "trust", "status"] + ([target] if target else []), True, False
        if action == "device-trust-scan":
            if not target: raise ValueError("device-trust-scan requires target")
            return [tool("netrune"), "device", "trust", "scan", target], True, False
        if action == "device-trust-enroll":
            fingerprint = str(args.get("fingerprint") or "").strip()
            if not target or not fingerprint: raise ValueError("device-trust-enroll requires target and fingerprint")
            return [tool("netrune"), "device", "trust", "enroll", target, "--fingerprint", fingerprint, "--confirm"], True, True
        if action == "device-trust-forget":
            if not target: raise ValueError("device-trust-forget requires target")
            return [tool("netrune"), "device", "trust", "forget", target, "--confirm"], True, True
        if action == "vlan-set":
            request = self.vlan_change_request(args)
            cmd = [tool("netrune"), "vlan", "set", request["target"], request["interface"], f"--{request['vlan_mode']}", request["vlan"]]
            if request.get("native_vlan"):
                cmd += ["--native", str(request["native_vlan"])]
            if request.get("replace"):
                cmd.append("--replace")
            cmd.append("--confirm")
            return cmd, False, True
        if action in {"vlan-locate", "vlan-propagation"}:
            vlan = str(args.get("vlan") or args.get("vlan_id") or "").strip()
            if not target or not vlan: raise ValueError(f"{action} requires target and vlan")
            if not vlan.isdigit() or not 1 <= int(vlan) <= 4094: raise ValueError("vlan must be between 1 and 4094")
            cmd = [tool("netrune"), "vlan", action.removeprefix("vlan-"), target, vlan]
            if args.get("depth") not in (None, ""):
                try: depth = int(args.get("depth"))
                except (TypeError, ValueError): raise ValueError("depth must be an integer between 1 and 10")
                if not 1 <= depth <= 10: raise ValueError("depth must be between 1 and 10")
                cmd += ["--depth", str(depth)]
            if args.get("max_nodes") not in (None, ""):
                try: max_nodes = int(args.get("max_nodes"))
                except (TypeError, ValueError): raise ValueError("max_nodes must be an integer between 1 and 256")
                if not 1 <= max_nodes <= 256: raise ValueError("max_nodes must be between 1 and 256")
                cmd += ["--max-nodes", str(max_nodes)]
            if str(args.get("refresh_neighbors") or "").lower() in {"1", "true", "yes", "on"}: cmd.append("--refresh-neighbors")
            return cmd, True, False
        if action in {"excel-inspect", "excel-sync", "excel-export"}:
            workbook = str(args.get("workbook") or "").strip()
            if not workbook: raise ValueError(f"{action} requires workbook")
            verb = action.removeprefix("excel-")
            return [tool("netrune"), "excel", verb, workbook] + (["--dry-run"] if verb == "sync" else []), True, verb != "inspect"
        if action == "commands-show":
            command_id = str(args.get("action") or args.get("command_id") or target or "").strip()
            if not command_id: raise ValueError("commands-show requires action")
            return [tool("netrune"), "commands", "show", command_id], True, False
        if action.startswith("workflow-"):
            name = action.removeprefix("workflow-")
            return [tool("netrune"), "workflow", name] + ([target] if target else []), True, True
        if action in {"device-config", "memory-prune", "serve-run", "ask-chat", "commands-run"}:
            raise PermissionError("Config-changing WebUI/API execution is blocked. Preview in UI, then run explicitly in the CLI with --confirm.")
        raise ValueError(f"Unknown action: {action}")

    def cmd_commands(self,args:List[str],opts:GlobalOptions)->int:
        if self.handle_help("commands", args, opts): return SUCCESS
        verb=args[0] if args else "list"; rest=args[1:]
        if verb=="list":
            rows=[self.command_dict(c) for c in self.command_registry()]
            self.emit({"ok":True,"commands":rows},opts,self.render_table(rows,["id","domain","risk_level","read_only","writes_local","description"])); return SUCCESS
        if verb=="show":
            if not rest: return self.usage_error("commands","show",opts,"Missing command id.","netrune commands show backup-run")
            spec=self.command_spec(rest[0])
            if not spec: return self.usage_error("commands","show",opts,f"Unknown command id: {rest[0]}","netrune commands list",VALIDATION)
            payload=self.command_dict(spec); self.emit({"ok":True,"command":payload},opts,self.render_plain(payload)); return SUCCESS
        if verb=="run":
            if not rest: return self.usage_error("commands","run",opts,"Missing command id.","netrune commands run health-check --preview")
            action=rest[0]; raw=[x for x in rest[1:] if x != "--preview"]; preview=("--preview" in rest) or opts.dry_run
            parsed=self.parse_registry_args(raw); spec=self.command_spec(action)
            if opts.depth: parsed.setdefault("depth", str(opts.depth))
            if opts.max_nodes != 64: parsed.setdefault("max_nodes", str(opts.max_nodes))
            if opts.refresh_neighbors: parsed.setdefault("refresh_neighbors", True)
            if opts.site and action in {"lookup-mac-locate","lookup-mac-profile"}: parsed.setdefault("scope", opts.site)
            if not spec: return self.usage_error("commands","run",opts,f"Unknown command id: {action}","netrune commands list",VALIDATION)
            if not spec.run_supported and not preview:
                return self.usage_error("commands","run",opts,"This registry action is preview-only. Run its public CLI form directly if the documented policy permits it.",f"netrune commands run {action} --preview",CONFIRM_REQUIRED)
            if spec.risk_level=="config" and not preview and not opts.confirm:
                return self.usage_error("commands","run",opts,"Config-changing command requires --dry-run/--preview or --confirm.",f"netrune commands run {action} --preview",CONFIRM_REQUIRED)
            try: cmd,ro,wl=self.command_for_action(action,parsed)
            except PermissionError as exc: return self.usage_error("commands","run",opts,str(exc),f"netrune commands run {action} --preview",CONFIRM_REQUIRED)
            except ValueError as exc: return self.usage_error("commands","run",opts,str(exc),f"netrune commands show {action}",VALIDATION)
            if preview:
                self.emit({"ok":True,"preview":True,"command":shlex.join(cmd),"read_only":ro,"writes_local":wl},opts,shlex.join(cmd)); return SUCCESS
            return self.run_subprocess(cmd,opts)
        return self.unknown_action("commands", verb, opts)

    def workflow_manifest(self, name: str, target: str = "") -> Dict[str, Any]:
        tool = self.paths.tool
        def step(step_id: str, label: str, command: List[str], on_failure: str = "continue") -> Dict[str, Any]:
            return {"id": step_id, "label": label, "command": command, "on_failure": on_failure}
        manifests: Dict[str, Dict[str, Any]] = {
            # Reachability runs before the topology scan so the scan has a fresh
            # status to skip offline devices by, and the review of changes runs
            # after it so the morning reads this morning's picture rather than
            # yesterday's.
            "morning-check": {"description": "Refresh local state and surface operational attention.", "steps": [
                step("import", "Import legacy caches", [tool("netrune"), "inventory", "import-flat"]),
                step("health", "Check reachability", [tool("netrune"), "health", "check"]),
                step("topology-scan", "Refresh LLDP/CDP topology", [tool("netrune"), "topology", "scan"]),
                step("memory", "Refresh relationships", [tool("netrune"), "memory", "refresh"]),
                step("topology", "Review topology changes", [tool("netrune"), "topology", "changes"]),
                step("filtering", "Check Internet filtering", [tool("netrune"), "diagnose", "filtering", "google.com"]),
                step("attention", "Build attention queue", [tool("netrune"), "health", "attention"]),
            ]},
            "refresh-inventory": {"description": "Refresh health, wireless, topology, and relationship state.", "steps": [
                step("health", "Check reachability", [tool("netrune"), "health", "check"]),
                step("aps", "Scan access points", [tool("netrune"), "ap", "scan"]),
                step("topology", "Scan LLDP/CDP topology", [tool("netrune"), "topology", "scan"]),
                step("memory", "Refresh relationships", [tool("netrune"), "memory", "refresh"]),
                step("attention", "Build attention queue", [tool("netrune"), "health", "attention"]),
            ]},
            "ap-audit": {"description": "Refresh AP evidence and surface movement or health findings.", "steps": [
                step("aps", "Scan access points", [tool("netrune"), "ap", "scan"]),
                step("memory", "Refresh relationships", [tool("netrune"), "memory", "refresh"]),
                step("moves", "Review AP moves", [tool("netrune"), "ap", "moves"]),
                step("attention", "Build attention queue", [tool("netrune"), "health", "attention"]),
            ]},
        }
        if name == "backup-online":
            if not target: raise ValueError("backup-online requires target")
            return {"name": name, "description": "Back up the selected online scope.", "steps": [step("backup", "Back up changed configurations", [tool("netrune"), "backup", "run", target], "stop")]}
        if name == "site-health":
            if not target: raise ValueError("site-health requires target")
            return {"name": name, "description": "Measure latency, filtering, and recorded health for a target.", "steps": [
                step("latency", "Measure latency", [tool("netrune"), "diagnose", "latency", target, "--count", "5"]),
                step("filtering", "Check filtering", [tool("netrune"), "diagnose", "filtering", target]),
                step("health", "Read health state", [tool("netrune"), "health", "status", target]),
            ]}
        if name not in manifests:
            raise ValueError(f"Unknown workflow: {name}")
        return {"name": name, **manifests[name]}

    def workflow_steps(self, name: str, target: str = "") -> List[List[str]]:
        return [list(item["command"]) for item in self.workflow_manifest(name, target)["steps"]]

    def cmd_workflow(self,args:List[str],opts:GlobalOptions)->int:
        if self.handle_help("workflow", args, opts): return SUCCESS
        if not args or args[0] in {"list","show"}:
            rows=self.workflows_payload(); self.emit({"ok":True,"workflows":rows},opts,self.render_table(rows,["id","label","description"])); return SUCCESS
        name=args[0]; target=" ".join(args[1:]).strip()
        try: manifest=self.workflow_manifest(name,target)
        except ValueError as exc: return self.usage_error("workflow",name,opts,str(exc),"netrune workflow morning-check",VALIDATION)
        steps = manifest["steps"]
        if opts.dry_run:
            rows=[{"step":i+1,"id":item["id"],"label":item["label"],"on_failure":item["on_failure"],"command":shlex.join(item["command"])} for i,item in enumerate(steps)]
            self.emit({"ok":True,"workflow":name,"description":manifest["description"],"dry_run":True,"steps":rows},opts,self.render_table(rows,["step","id","label","on_failure","command"])); return SUCCESS
        started = now()
        results: List[Dict[str, Any]] = []
        stopped = False
        for index,item in enumerate(steps,1):
            command = list(item["command"])
            child_command = command + (["--json"] if "--json" not in command else [])
            self.live_log("workflow", f"{index}/{len(steps)} {item['label']}")
            step_started = time.monotonic()
            rc, stdout, stderr = self.capture_streamed(child_command, opts.timeout or 1800, opts)
            duration_ms = max(0, int((time.monotonic() - step_started) * 1000))
            result_payload: Any = None
            with contextlib.suppress(json.JSONDecodeError):
                result_payload = json.loads(stdout.strip())
            summary = ""
            if isinstance(result_payload, dict):
                summary = str(result_payload.get("summary") or result_payload.get("status") or result_payload.get("answer") or "")
            if not summary:
                summary = " ".join(clean_network_output(stdout or stderr).split())[:500]
            # A step that reports findings has not failed. `health attention`
            # exits PARTIAL precisely when it has something to show, which is
            # the point of running it; calling that FAILED taught operators to
            # ignore a red row that appears on every healthy morning.
            step_status = "SUCCESS" if rc == 0 else ("ATTENTION" if rc == PARTIAL else "FAILED")
            result = {"step":index,"id":item["id"],"label":item["label"],"status":step_status,"exit_code":rc,"duration_ms":duration_ms,"on_failure":item["on_failure"],"summary":summary,"result":redact_for_api(result_payload) if isinstance(result_payload, dict) else None}
            results.append(result)
            if not opts.json:
                print(f"\n[{index}/{len(steps)}] {item['label']} ({result['status']})")
                if stdout.strip(): print(stdout.rstrip())
            if step_status == "FAILED" and item["on_failure"] == "stop":
                stopped = True
                self.live_log("workflow", f"stopped after {item['id']} exited {rc}")
                break
        failed = [item for item in results if item["status"] == "FAILED"]
        attention = [item for item in results if item["status"] == "ATTENTION"]
        finished = now()
        status = "FAILED" if stopped else "PARTIAL" if failed else "ATTENTION" if attention else "SUCCESS"
        payload = {"ok":not failed,"workflow":name,"description":manifest["description"],"status":status,"steps":results,"completed_steps":len(results),"total_steps":len(steps),"failed_steps":len(failed),"attention_steps":len(attention),"stopped":stopped,"started_at":started,"started_at_iso":fmt_time(started),"finished_at":finished,"finished_at_iso":fmt_time(finished)}
        headline = f"Workflow {name}: {status} | completed={len(results)}/{len(steps)} | failed={len(failed)}"
        if attention:
            headline += f" | needing attention={len(attention)}"
        summary_text = headline + f" | recorded={payload['finished_at_iso']}\n" + self.render_table(results,["step","label","status","exit_code","duration_ms","on_failure","summary"])
        self.emit(payload,opts,summary_text)
        return SUCCESS if not failed and not attention else PARTIAL

    def cmd_backup(self,args:List[str],opts:GlobalOptions)->int:
        if self.handle_help("backup", args, opts): return SUCCESS
        verb=args[0] if args else "run"; rest=args[1:]
        if verb=="run":
            # --all is a recognized global flag (opts.all), already stripped
            # from `rest` by parse_global() before this method ever sees it
            # -- `netrune backup run --all` used to land here with `rest`
            # empty and no way to tell "the operator asked for everything"
            # apart from "the operator forgot a target", always reporting
            # the latter. A literal all/*/any target reads the same way.
            force=("--force" in rest); skip_recent_flag=("--skip-recent" in rest)
            rest=[x for x in rest if x not in {"--force","--skip-recent"}]
            is_all=bool(opts.all or (rest and is_all_keyword(rest[0])))
            if is_all:
                pattern=""
                rest = rest[1:] if rest and is_all_keyword(rest[0]) else rest
            elif not rest:
                return self.usage_error("backup","run",opts,"Missing backup target.","netrune backup run ZONE34 (or --all for every device)")
            else:
                pattern=rest[0]; rest=rest[1:]
            extra=[x for x in rest if x not in {"--online-only","--changed-only","--summary"}]
            # A bulk --all run is exactly the case where re-touching devices
            # already backed up earlier the same day (an earlier partial run,
            # a retry) is pure waste, so it skips those by default; a
            # targeted single/pattern run only skips when asked (--skip-recent)
            # since a specific backup request is usually wanted right now
            # regardless of age. --force always wins either way.
            skip_recent=(skip_recent_flag or is_all) and not force
            if is_all or skip_recent:
                return self.apply_backup_batch(pattern,extra,opts,skip_recent=skip_recent)
            cmd=self.legacy_cmd("netrune-control","backup",pattern,"--online-only","--changed-only","--summary",*extra)
            id_before=(self.state.one("SELECT COALESCE(MAX(id),0) AS id FROM backup_history") or {"id":0})["id"]
            rc=self.run_subprocess(cmd,opts)
            self._emit_backup_run_report(id_before,rc,opts)
            return rc
        if verb=="history":
            if not rest: return self.usage_error("backup","history",opts,"Missing target.","netrune backup history ZONE34")
            return self.run_subprocess(self.legacy_cmd("netrune-control","backup-history",rest[0]),opts)
        if verb=="diff":
            if not rest: return self.usage_error("backup","diff",opts,"Missing target.","netrune backup diff ZONE34")
            return self.run_subprocess(self.legacy_cmd("netrune-control","diff",rest[0]),opts)
        if verb=="verify":
            rows=self.state.rows("SELECT * FROM backup_history ORDER BY created_at DESC,id DESC LIMIT ?",(opts.limit,))
            self.emit({"ok":True,"rows":rows},opts,self.render_table(rows,["created_at","device_ip","hostname","status","changed","sha256","path","message"])); return SUCCESS
        return self.unknown_action("backup", verb, opts)

    def _emit_backup_run_report(self, id_before: int, rc: int, opts: GlobalOptions) -> None:
        """After the legacy `netops-control backup <pattern>` fan-out
        finishes, report every backup_history row it just wrote. Bash
        records those rows directly (control_backup_record), so an id
        watermark taken right before the subprocess runs is the only way
        Python can see per-device results for this path -- same reporting
        shape apply_backup_batch below produces natively for --all/
        --skip-recent runs. A device that fails outright (SSH never
        reaches a prompt) gets no backup_history row at all -- bash only
        records successes -- so a nonzero exit with zero new rows still
        gets one explicit line rather than the report silently saying
        nothing happened."""
        rows=self.state.rows("SELECT device_ip,hostname,status,changed,message FROM backup_history WHERE id > ? ORDER BY id",(id_before,))
        if not rows:
            if rc != 0:
                self.emit({"ok":False,"rows":[]},opts,f"Backup run exited with errors (code {rc}); no backup_history rows were written -- see the output above for detail.")
            return
        self.emit({"ok":rc==0,"rows":rows},opts,self.render_table(rows,["hostname","device_ip","status","changed","message"]))

    def apply_backup_batch(self, pattern: str, extra_flags: List[str], opts: GlobalOptions, *, skip_recent: bool = False) -> int:
        """`backup run --all` (or any pattern combined with --skip-recent):
        resolve every matching device straight from inventory -- netrune's
        own reconciled `devices` table, not the bash-side ingest cache
        `resolve_targets` greps -- run one backup per device so each
        device's own outcome is individually visible, and report a table
        of what happened. `skip_recent` excludes, before ever connecting,
        any device that already has a 'saved' or 'unchanged' backup_history
        row from today; those still show up in the table as SKIPPED rather
        than silently vanishing. Devices are touched one at a time inside
        one vault session, matching apply_device_config_batch's precedent
        (no existing concurrent-device precedent in this codebase)."""
        needle=str(pattern or "").strip().lower()
        fields=("ip","hostname","platform","model","serial","mac")
        # --online-only is always implied here (the old passthrough path
        # hardcodes it too), so OFFLINE devices are excluded unconditionally.
        devices=[
            row for row in self.state.rows("SELECT ip,hostname,platform,model,serial,mac,status FROM devices ORDER BY hostname,ip")
            if str(row.get("status") or "").upper() != "OFFLINE"
            and (not needle or needle in " ".join(str(row.get(f) or "") for f in fields).lower())
        ]
        if not devices:
            return self.usage_error("backup","run",opts,f"No online devices matched {pattern or 'all'!r}.","netrune inventory list",VALIDATION)

        skipped: List[Dict[str, Any]] = []
        runnable=devices
        if skip_recent:
            fresh_ips={row["device_ip"] for row in self.state.rows(
                "SELECT DISTINCT device_ip FROM backup_history WHERE status IN ('saved','unchanged') AND date(created_at,'unixepoch')=date('now')"
            )}
            runnable=[d for d in devices if d["ip"] not in fresh_ips]
            skipped=[{"target":d.get("hostname") or d["ip"],"status":"SKIPPED","changed":"","message":"already backed up today"} for d in devices if d["ip"] in fresh_ips]

        if not runnable:
            text=f"All {len(devices)} matched device(s) already have a backup from today; nothing to do.\n"+self.render_table(skipped,["target","status","changed","message"])
            self.emit({"ok":True,"devices":[],"skipped_devices":skipped},opts,text)
            return SUCCESS

        if opts.dry_run:
            preview_rows=[{"target":d.get("hostname") or d["ip"],"ip":d["ip"]} for d in runnable]
            text=f"Would back up {len(runnable)} device(s):\n"+self.render_table(preview_rows,["target","ip"])
            if skipped:
                text+=f"\n\nSkipping {len(skipped)} device(s) with a backup from today:\n"+self.render_table(skipped,["target","status","changed","message"])
            self.emit({"ok":True,"dry_run":True,"devices":preview_rows,"skipped_devices":skipped},opts,text)
            return SUCCESS

        started=now()
        results: List[Dict[str, Any]] = []
        with self.vault_session_scope(opts, minutes=30):
            for index, device in enumerate(runnable, 1):
                ip=device["ip"]; name=device.get("hostname") or ip
                self.live_log("backup", f"device {index}/{len(runnable)}: {name}")
                id_before=(self.state.one("SELECT COALESCE(MAX(id),0) AS id FROM backup_history") or {"id":0})["id"]
                cmd=self.legacy_cmd("netrune-control","backup",ip,"--online-only","--changed-only","--summary",*extra_flags)
                rc,out,err=self.capture(cmd, opts.timeout or 300, opts)
                row=self.state.one("SELECT * FROM backup_history WHERE device_ip=? ORDER BY id DESC LIMIT 1",(ip,))
                if row and row["id"] > id_before:
                    results.append({"target":name,"status":str(row["status"]).upper(),"changed":bool(row["changed"]),"message":row.get("message") or ""})
                else:
                    detail=" ".join(clean_network_output((out or "")+(err or "")).split())[:400]
                    results.append({"target":name,"status":"FAILED","changed":False,"message":detail or f"exit {rc}"})
        finished=now()

        counts={"total":len(results),"saved":0,"unchanged":0,"failed":0,"skipped":len(skipped)}
        for r in results:
            key=r["status"].lower()
            counts[key]=counts.get(key,0)+1
        ok_count=counts.get("saved",0)+counts.get("unchanged",0)
        all_succeeded=ok_count == counts["total"]
        summary_rows=results+skipped
        payload={
            "ok":all_succeeded,"devices":results,"skipped_devices":skipped,"counts":counts,
            "started_at":started,"started_at_iso":fmt_time(started),
            "finished_at":finished,"finished_at_iso":fmt_time(finished),
        }
        headline=f"Backup run: {ok_count}/{counts['total']} attempted succeeded"
        if counts["failed"] or skipped:
            headline+=f" ({counts['failed']} failed, {counts['skipped']} skipped)"
        text=headline+"\n"+self.render_table(summary_rows,["target","status","changed","message"])
        self.emit(payload,opts,text)
        return SUCCESS if all_succeeded else PARTIAL

    @staticmethod
    def _host_key_fingerprint(key_data: str) -> str:
        try:
            padding = "=" * (-len(key_data) % 4)
            decoded = base64.b64decode(key_data + padding, validate=True)
        except (ValueError, TypeError):
            return ""
        digest = base64.b64encode(hashlib.sha256(decoded).digest()).decode("ascii").rstrip("=")
        return f"SHA256:{digest}"

    @staticmethod
    def _known_host_alias_matches(alias: str, target: str) -> bool:
        if alias == target or alias == f"[{target}]:22":
            return True
        if not alias.startswith("|1|"):
            return False
        try:
            _, _, salt_text, digest_text = alias.split("|", 3)
            salt = base64.b64decode(salt_text)
            expected = base64.b64decode(digest_text)
        except (ValueError, TypeError):
            return False
        actual = hmac.new(salt, target.encode("utf-8"), hashlib.sha1).digest()
        return hmac.compare_digest(actual, expected)

    def _known_host_rows(self, targets: Sequence[str] = ()) -> List[Dict[str, Any]]:
        path = self.paths.ssh_known_hosts_file
        if not path.is_file():
            return []
        wanted = {target for target in targets if target}
        rows: List[Dict[str, Any]] = []
        for line_number, raw in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            fields = line.split()
            offset = 1 if fields and fields[0].startswith("@") else 0
            if len(fields) < offset + 3:
                continue
            aliases = fields[offset].split(",")
            if wanted and not any(self._known_host_alias_matches(alias, target) for alias in aliases for target in wanted):
                continue
            fingerprint = self._host_key_fingerprint(fields[offset + 2])
            if not fingerprint:
                continue
            rows.append({
                "host": fields[offset],
                "key_type": fields[offset + 1],
                "fingerprint": fingerprint,
                "line": line_number,
                "managed_file": str(path),
            })
        return rows

    def vault_session_payload(self) -> Dict[str, Any]:
        """Report whether a vault session is open, without prompting for anything.

        Reads only the expiry marker; the cached key itself is never opened here.
        """
        base = environment_value("NETRUNE_VAULT_SESSION_DIR", "NETOPS_VAULT_SESSION_DIR", os.environ.get("XDG_RUNTIME_DIR", ""))
        payload: Dict[str, Any] = {"supported": bool(base), "active": False, "expires_at": 0, "expires_at_iso": "", "seconds_remaining": 0, "path": ""}
        if not base:
            return payload
        directory = Path(base) / "netrune-vault"
        payload["path"] = str(directory)
        try:
            expires = int(Path(directory / "expires-at").read_text(encoding="utf-8").strip())
        except (OSError, ValueError):
            return payload
        remaining = expires - now()
        if remaining <= 0 or not (directory / "key").is_file():
            return payload
        payload.update({"active": True, "expires_at": expires, "expires_at_iso": fmt_time(expires), "seconds_remaining": remaining})
        return payload

    def named_secret_recorded_at(self, name: str) -> int:
        """Read the rotation timestamp recorded for a named secret.

        `vault set` stores the SSH password as a named secret and writes its
        rotation time to the metadata file. Reading that same file is what keeps
        status honest; a file modification time would describe the wrong object.
        """
        encoded = base64.b64encode(str(name or "").encode("utf-8")).decode("ascii")
        recorded = 0
        try:
            content = self.paths.secrets_meta_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return 0
        for line in content.splitlines():
            key, _, value = line.partition("|")
            if key == encoded and value.strip().isdigit():
                recorded = int(value.strip())
        return recorded

    def vault_status_payload(self) -> Dict[str, Any]:
        legacy_vault = Path(environment_value("NETRUNE_PASSWORD_FILE", "NETOPS_PASSWORD_FILE", str(self.paths.home / ".ssh" / "sshpass_cache.gpg")))
        secret_name = "ssh/default/password"
        secret_recorded = self.named_secret_recorded_at(secret_name)
        # The named-secret store is where `vault set` writes and where
        # get_password_from_store reads first, so it is the live credential
        # whenever it exists. The legacy file is only a fallback.
        use_named_secret = bool(secret_recorded and self.paths.secrets_file.is_file())
        vault = self.paths.secrets_file if use_named_secret else legacy_vault
        credential_store = f"named-secret {secret_name}" if use_named_secret else "legacy-ssh-vault"
        exists = vault.is_file()
        mode = "missing"
        permissions = ""
        modified_at = 0
        if exists:
            try:
                with vault.open("rb") as handle:
                    marker = handle.readline(64).rstrip(b"\r\n")
                if use_named_secret:
                    mode = "sudo-gpg-v1" if marker == b"NETOPS-NAMED-SECRETS-GPG-V1" else "unreadable"
                    modified_at = secret_recorded
                else:
                    mode = "sudo-gpg-v1" if marker == b"NETOPS-SUDO-GPG-V1" else "legacy-gpg"
                    modified_at = int(vault.stat().st_mtime)
                permissions = f"{vault.stat().st_mode & 0o777:04o}"
            except OSError:
                mode = "unreadable"
        sudo_session = "not-applicable"
        root_key = "not-applicable"
        sudo_authenticator = "password"
        try:
            if "pam_wsl_hello.so" in Path("/etc/pam.d/sudo").read_text(encoding="utf-8"):
                sudo_authenticator = "windows-hello"
        except OSError:
            pass
        if mode == "sudo-gpg-v1":
            sudo_session = "locked"
            root_key = "not-checked"
            sudo_bin = "/usr/bin/sudo"
            if environment_value("NETRUNE_TEST_MODE", "NETOPS_TEST_MODE").lower() in {"1", "true", "yes"}:
                sudo_bin = shutil.which("sudo") or sudo_bin
            if Path(sudo_bin).is_file():
                try:
                    cached = subprocess.run(
                        [sudo_bin, "-n", "-v"],
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=2,
                        check=False,
                    ).returncode == 0
                except (OSError, subprocess.TimeoutExpired):
                    cached = False
                if cached:
                    sudo_session = "unlocked"
                    key_dir = "/etc/netops/vault-keys"
                    if environment_value("NETRUNE_TEST_MODE", "NETOPS_TEST_MODE").lower() in {"1", "true", "yes"}:
                        key_dir = environment_value("NETRUNE_SUDO_VAULT_KEY_DIR", "NETOPS_SUDO_VAULT_KEY_DIR", key_dir)
                    key_file = str(Path(key_dir) / f"{os.getuid()}.key")
                    fixture_sudo = environment_value("NETRUNE_TEST_MODE", "NETOPS_TEST_MODE").lower() in {"1", "true", "yes"} and sudo_bin != "/usr/bin/sudo"
                    owner_anchor = key_dir if fixture_sudo else "/etc"
                    try:
                        key_check = subprocess.run(
                            [sudo_bin, "-n", "/usr/bin/stat", "--printf", "%u:%a:%F", key_file],
                            stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL,
                            timeout=2,
                            text=True,
                            check=False,
                        )
                        key_dir_check = subprocess.run(
                            [sudo_bin, "-n", "/usr/bin/stat", "--printf", "%u:%a:%F", key_dir],
                            stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL,
                            timeout=2,
                            text=True,
                            check=False,
                        )
                        anchor_check = subprocess.run(
                            [sudo_bin, "-n", "/usr/bin/stat", "--printf", "%u:%a:%F", owner_anchor],
                            stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL,
                            timeout=2,
                            text=True,
                            check=False,
                        )
                    except (OSError, subprocess.TimeoutExpired):
                        key_check = None
                        key_dir_check = None
                        anchor_check = None
                    if key_check is None or key_check.returncode != 0:
                        root_key = "missing"
                    else:
                        key_parts = key_check.stdout.strip().split(":", 2)
                        dir_parts = key_dir_check.stdout.strip().split(":", 2) if key_dir_check is not None and key_dir_check.returncode == 0 else []
                        anchor_parts = anchor_check.stdout.strip().split(":", 2) if anchor_check is not None and anchor_check.returncode == 0 else []
                        secure = (
                            len(key_parts) == 3
                            and len(dir_parts) == 3
                            and len(anchor_parts) == 3
                            and key_parts[0] == dir_parts[0]
                            and dir_parts[0] == anchor_parts[0]
                            and key_parts[1] in {"400", "600"}
                            and key_parts[2] == "regular file"
                            and dir_parts[1] == "700"
                            and dir_parts[2] == "directory"
                            and anchor_parts[2] == "directory"
                        )
                        root_key = "available" if secure else "insecure"
        def policy_int(key: str, default: int, minimum: int, maximum: int) -> int:
            try:
                return max(minimum, min(int(self.config.public.get(key) or default), maximum))
            except (TypeError, ValueError):
                return default

        session = self.vault_session_payload()
        ttl_hours = policy_int("vault_password_ttl_hours", 72, 1, 8760)
        window_minutes = policy_int("vault_expiry_window_minutes", 20, 0, 720)
        warning_hours = policy_int("vault_expiry_warning_hours", 12, 0, 720)
        expected_expiry = modified_at + ttl_hours * 3600 if modified_at else 0
        window_start = expected_expiry - window_minutes * 60 if expected_expiry else 0
        window_end = expected_expiry + window_minutes * 60 if expected_expiry else 0
        current = now()
        if not expected_expiry:
            credential_state = "UNKNOWN"
        elif current >= window_end:
            credential_state = "EXPIRED"
        elif current >= window_start:
            credential_state = "EXPIRY_WINDOW"
        elif expected_expiry - current <= warning_hours * 3600:
            credential_state = "DUE_SOON"
        else:
            credential_state = "ACTIVE"
        return {
            "ok": exists and mode in {"legacy-gpg", "sudo-gpg-v1"} and permissions == "0600",
            "configured": exists,
            "path": str(vault),
            "credential_store": credential_store,
            "legacy_vault_path": str(legacy_vault),
            "legacy_vault_present": legacy_vault.is_file(),
            "mode": mode,
            "permissions": permissions,
            "modified_at": modified_at,
            "modified_at_iso": fmt_time(modified_at),
            "password_recorded_at": modified_at,
            "password_recorded_at_iso": fmt_time(modified_at),
            "expected_expiry_at": expected_expiry,
            "expected_expiry_at_iso": fmt_time(expected_expiry),
            "expiry_window_start": window_start,
            "expiry_window_start_iso": fmt_time(window_start),
            "expiry_window_end": window_end,
            "expiry_window_end_iso": fmt_time(window_end),
            "credential_state": credential_state,
            "seconds_to_expected_expiry": expected_expiry - current if expected_expiry else None,
            "password_ttl_hours": ttl_hours,
            "expiry_window_minutes": window_minutes,
            "sudo_session": sudo_session,
            "sudo_authenticator": sudo_authenticator,
            "root_key": root_key,
            "session": session,
            "graphical_pinentry": False if mode in {"legacy-gpg", "sudo-gpg-v1"} else None,
        }

    def cmd_vault(self, args: List[str], opts: GlobalOptions) -> int:
        if self.handle_help("vault", args, opts):
            return SUCCESS
        verb = args[0].lower() if args else "status"
        rest = args[1:]
        if verb == "status":
            if rest:
                return self.usage_error("vault", "status", opts, f"Unknown vault status option: {rest[0]}", "netrune vault status", VALIDATION)
            payload = self.vault_status_payload()
            text = "\n".join(
                [
                    f"SSH vault: {payload['path']}",
                    f"Credential store: {payload['credential_store']}",
                    f"Mode: {payload['mode']}",
                    f"Permissions: {payload['permissions'] or 'not available'}",
                    f"Password recorded: {payload['modified_at_iso'] or 'never'}"
                    + (" (recorded by vault set)" if payload["credential_store"].startswith("named-secret") else " (file modification time)"),
                    f"Rotation reminder: {payload['credential_state']} | due {payload['expected_expiry_at_iso'] or 'unknown'}"
                    f" (recorded + {payload['password_ttl_hours']}h policy)",
                    # The state above is arithmetic on a timestamp, not a test
                    # of the password. Saying so prevents reading EXPIRED as
                    # "the vault will not work".
                    "  This is a local reminder only. It does not check the password against any device;"
                    " a password past this date may still work, and one before it may already have been changed.",
                    f"Authentication: {'Windows Hello via sudo/PAM' if payload['sudo_authenticator'] == 'windows-hello' else 'sudo password/PAM'}",
                    f"Sudo session: {payload['sudo_session']}",
                    f"Root key: {payload['root_key']}",
                ] + ([
                    # A stale legacy file next to a live named secret is exactly
                    # what made this status misleading before.
                    f"Note: an unused legacy vault file remains at {payload['legacy_vault_path']}; it is not the credential in use.",
                ] if payload["credential_store"].startswith("named-secret") and payload["legacy_vault_present"] else []) + [
                    (
                        f"Vault session: open until {payload['session']['expires_at_iso']} "
                        f"({payload['session']['seconds_remaining'] // 60}m left, key cached at {payload['session']['path']})"
                        if payload["session"]["active"]
                        else "Vault session: closed (each command authenticates; 'netrune vault unlock' holds it open)"
                    ),
                ]
            )
            self.emit(payload, opts, text)
            return SUCCESS
        if verb not in {"set", "migrate", "unlock", "lock"}:
            return self.unknown_action("vault", verb, opts)
        if opts.json:
            return self.usage_error("vault", verb, opts, "Interactive vault actions do not emit JSON.", f"netrune vault {verb}", VALIDATION)
        helper_args: List[str]
        ttl_minutes = 0
        if verb == "set":
            invalid = [item for item in rest if item != "--legacy-vault"]
            if invalid or rest.count("--legacy-vault") > 1:
                bad = invalid[0] if invalid else "duplicate --legacy-vault"
                return self.usage_error("vault", "set", opts, f"Unknown vault set option: {bad}", "netrune vault set [--legacy-vault]", VALIDATION)
            helper_args = ["--set-password"]
            if "--legacy-vault" in rest:
                helper_args.append("--legacy-vault")
        elif verb == "unlock":
            usage = "netrune vault unlock [--ttl MINUTES]"
            helper_args = ["--unlock-vault"]
            index = 0
            while index < len(rest):
                if rest[index] == "--ttl":
                    if index + 1 >= len(rest):
                        return self.usage_error("vault", "unlock", opts, "--ttl requires a whole number of minutes.", usage, VALIDATION)
                    raw = str(rest[index + 1]).strip()
                    if not raw.isdigit() or not 1 <= int(raw) <= 480:
                        return self.usage_error("vault", "unlock", opts, f"--ttl must be between 1 and 480 minutes, not {raw!r}.", usage, VALIDATION)
                    ttl_minutes = int(raw)
                    helper_args += ["--ttl", raw]
                    index += 2
                    continue
                return self.usage_error("vault", "unlock", opts, f"Unknown vault unlock option: {rest[index]}", usage, VALIDATION)
        else:
            if rest:
                return self.usage_error("vault", verb, opts, f"Vault {verb} does not accept arguments.", f"netrune vault {verb}", VALIDATION)
            helper_args = ["--migrate-vault" if verb == "migrate" else "--lock-vault"]
        code = self.run_vault_interactive(self.legacy_cmd("netrune-connect", *helper_args), opts)
        if code == SUCCESS and not opts.dry_run:
            actor = os.environ.get("SUDO_USER") or os.environ.get("USER") or str(os.getuid())
            event = {"set": "vault_password_set", "migrate": "vault_migrated", "unlock": "vault_unlocked", "lock": "vault_locked"}[verb]
            detail: Dict[str, Any] = {"vault": str(self.vault_status_payload().get("path") or "")}
            if verb == "unlock":
                # An unlock widens who can read the key for a window, so the
                # window itself belongs in the audit trail.
                detail["session_ttl_minutes"] = ttl_minutes or "configured default"
            self.state.record_audit_event(event, f"vault-{verb}", actor=actor, actor_uid=os.getuid(), result="success", detail=detail)
        return code


    def locate_endpoint_live(self, mac: str, vlan: int, opts: GlobalOptions, jobs: int = 0) -> Dict[str, Any]:
        """Find the switch a MAC is attached to by asking every switch at once.

        A hop-by-hop walk follows one branch and stops when a forwarding table
        does not name a next hop. An exhaustive search does not: every switch
        along the path reports the address, and the hit that is not on a known
        uplink is the access port.
        """
        clean = norm_mac(mac)
        result: Dict[str, Any] = {"found": False, "attached": [], "transit": [], "searched": 0}
        if not clean:
            return result
        targets = self.current_switch_targets(opts)
        if not targets:
            return result
        dotted = self.canonical_mac(clean, "dotted")
        uplinks = self.known_uplink_ports()
        workers = max(1, min(int(jobs or self._default_stp_jobs()), 32, len(targets)))

        def probe(row: Dict[str, Any]) -> Tuple[str, str, List[Dict[str, Any]]]:
            ip = str(row.get("ip") or "").strip()
            name = clean_display_name(row.get("hostname") or ip)
            _, out, err = self.capture(self.legacy_cmd("netrune-control", "mac-lookup", ip, dotted), opts.timeout or 90)
            return ip, name, parse_mac_table_output((out or "") + (err or ""), clean)

        attached: List[Dict[str, Any]] = []
        transit: List[Dict[str, Any]] = []
        completed = 0
        lock = threading.Lock()
        # Without this the parallel probes each authenticate separately, which
        # on a Windows Hello stack means one prompt per worker.
        with self.vault_session_scope(opts, minutes=30):
          try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers, thread_name_prefix="maclocate") as pool:
                for future in concurrent.futures.as_completed([pool.submit(probe, row) for row in targets]):
                    ip, name, parsed = future.result()
                    with lock:
                        completed += 1
                        self._progress_step("locate endpoint", name, completed, len(targets), opts)
                    for row in parsed:
                        if vlan and str(row.get("vlan") or "") and str(row.get("vlan")) != str(vlan):
                            continue
                        port = str(row.get("port") or "")
                        entry = {
                            "switch_ip": ip, "switch_name": name, "port": port,
                            "vlan": str(row.get("vlan") or ""), "entry_type": str(row.get("entry_type") or ""),
                        }
                        (transit if normalize_interface(port) in uplinks.get(ip, set()) else attached).append(entry)
          finally:
            self._progress_clear(opts)

        result.update({
            "found": bool(attached or transit),
            "attached": attached, "transit": transit,
            "searched": len(targets), "uplink_data_available": bool(uplinks),
        })
        return result



    def workflows_payload(self)->List[Dict[str,Any]]: return [{"id":"morning-check","action":"workflow-morning-check","label":"Morning check","description":"Health, memory, topology, filtering, and attention summary."},{"id":"refresh-inventory","action":"workflow-refresh-inventory","label":"Refresh inventory","description":"Fast health, AP discovery, topology, and memory refresh."},{"id":"backup-online","action":"workflow-backup-online","label":"Backup online","description":"Changed-only backups for online devices."},{"id":"ap-audit","action":"workflow-ap-audit","label":"AP audit","description":"Refresh AP records and surface AP moves."}]
    def diagnostics_payload(self,limit:int=80)->Dict[str,Any]:
        probes=timestamp_rows(self.state.rows("SELECT id,target,mode,created_at,packet_loss_pct,min_ms,avg_ms,max_ms,jitter_ms FROM probe_results ORDER BY created_at DESC,id DESC LIMIT ?",(limit,)))
        speeds=timestamp_rows(self.state.rows("SELECT id,created_at,interface,download_mbps,upload_mbps,idle_latency_ms,loaded_down_ms,loaded_up_ms,packet_loss_pct,reliability FROM speed_tests ORDER BY created_at DESC,id DESC LIMIT ?",(limit,)))
        checks=timestamp_rows(self.state.rows("SELECT id,created_at,target,result FROM filtering_checks ORDER BY created_at DESC,id DESC LIMIT ?",(limit,)))
        samples=timestamp_rows(self.state.rows("SELECT id,created_at,device_ip,interface_name,in_bps,out_bps,utilization_pct,oper_status FROM interface_samples ORDER BY created_at DESC,id DESC LIMIT ?",(limit,)))
        runs=timestamp_rows(self.state.rows("SELECT id,created_at,kind,target,source,status,summary FROM diagnostic_runs ORDER BY created_at DESC,id DESC LIMIT ?",(limit,)))
        latest_by_kind: Dict[str,Any]={}
        for row in runs:
            latest_by_kind.setdefault(str(row.get("kind") or ""),row)
        return {
            "summary":{
                "latest_probe":probes[0] if probes else None,
                "latest_speed":speeds[0] if speeds else None,
                "latest_filtering":checks[0] if checks else None,
                "latest_interface":samples[0] if samples else None,
                "latest_throughput":latest_by_kind.get("throughput"),
                "latest_port_health":latest_by_kind.get("port-health"),
                "latest_cable":latest_by_kind.get("cable"),
                "latest_doctor":latest_by_kind.get("doctor"),
                "counts":{"probes":len(probes),"speed_tests":len(speeds),"filtering_checks":len(checks),"interface_samples":len(samples),"diagnostic_runs":len(runs)},
            },
            "probes":list(reversed(probes)),
            "speed_tests":list(reversed(speeds)),
            "filtering_checks":checks,
            "interface_samples":list(reversed(samples)),
            "diagnostic_runs":runs,
        }

def main(argv: Optional[List[str]] = None) -> int:
    synchronize_environment_aliases()
    raw_args = list(argv if argv is not None else sys.argv[1:])
    try:
        opts, args = parse_global(raw_args)
        if not args or args[0] in {"-h", "--help", "help", "--version", "version"}:
            if args and args[0] in {"--version", "version"}:
                if opts.json:
                    print(json_dumps({"name": "Netrune", "version": VERSION, "schema_version": SCHEMA_VERSION}))
                else:
                    print(f"Netrune {VERSION}")
                return SUCCESS
            helper = App.__new__(App)
            if args and args[0] == "help":
                helper.cmd_help(args[1] if len(args) > 1 else "", args[2] if len(args) > 2 else "", opts)
            else:
                helper.cmd_help(opts=opts)
            return SUCCESS
        app = App(installation_root(), profile=opts.profile)
        return app.dispatch(raw_args)
    except KeyboardInterrupt:
        eprint("Interrupted.")
        return 130
    except Exception as exc:
        eprint(f"Netrune startup failed: {exc}")
        return INTERNAL


if __name__ == "__main__":
    raise SystemExit(main())
