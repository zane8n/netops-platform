#!/usr/bin/env python3
"""NetOps Python core.

This is the noun-first NetOps platform entrypoint. It keeps the existing shell
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
import ipaddress
from importlib.metadata import PackageNotFoundError, version as distribution_version
import json
import mimetypes
import os
import queue
import re
import shlex
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import threading
import textwrap
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import parse_qs, urlparse

from netops_platform.ask import NaturalAskEngine, QUESTION_PATTERNS
from netops_platform.devices import REGISTRY as DEVICE_DRIVERS
from netops_platform.devices import DeviceDetection, DeviceDriver, UnsupportedDeviceAction
from netops_platform.identity import (
    ap_rows_match,
    identity_match_evidence,
    normalize_mac,
    reconcile_ap_rows,
    reconcile_device_rows,
)
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
    parse_interface_health_output,
    parse_iperf3_output,
    parse_neighbor_detail_output,
    parse_ping_output,
    parse_vlan_control_output,
)
from netops_platform.profiles import (
    NEUTRAL_PROFILE,
    ProfileLayout,
    ProfileStore,
    flatten_profile,
    profile_environment,
    read_kv,
)
from netops_platform.contracts import PathRequestV1
from netops_platform.ingest import IngestManager, SecretResolver
from netops_platform.path_inspector import PathInspector
from netops_platform.plugins import PLUGIN_GROUPS, PluginManager
from netops_platform.support import create_support_bundle

def resolved_version() -> str:
    try:
        return Path(__file__).resolve().parents[1].joinpath("VERSION").read_text(encoding="ascii").strip()
    except OSError:
        try:
            return distribution_version("netops-platform")
        except PackageNotFoundError:
            return "0.0.0+unknown"


def installation_root() -> Path:
    source_root = Path(__file__).resolve().parents[1]
    if (source_root / "netops-connect").is_file():
        return source_root
    return Path(sys.executable).resolve().parent


VERSION = resolved_version()
SCHEMA_VERSION = "13"
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

def normalize_target_literal(value: Any) -> str:
    """Normalize an optional profile-defined IPv4 abbreviation."""
    text = str(value or "").strip()
    if not text:
        return ""
    if IP_RE.fullmatch(text):
        with contextlib.suppress(ValueError):
            return str(ipaddress.ip_address(text))
        return text
    prefix = os.environ.get("NETOPS_TARGET_ABBREVIATION_PREFIX", "").strip().strip(".")
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


def redact_for_api(value: Any) -> Any:
    if isinstance(value, dict):
        out: Dict[str, Any] = {}
        for key, item in value.items():
            out[key] = "configured" if SECRET_KEY_RE.search(str(key)) and item else redact_for_api(item)
        return out
    if isinstance(value, list):
        return [redact_for_api(item) for item in value]
    return value


@dataclass
class GlobalOptions:
    json: bool = False
    plain: bool = False
    no_tui: bool = False
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
        elif arg == "--plain": opts.plain = True; i += 1
        elif arg == "--no-tui": opts.no_tui = True; i += 1
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
            # the one-shot NetOps state-profile selector.
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
    webui_dist_dir: Path = field(init=False)

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
        self.sqlite_db = Path(os.environ.get("NETOPS_SQLITE_DB", str(self.state_dir / "netops.sqlite3")))
        self.backup_dir = Path(os.environ.get("NETOPS_BACKUP_DIR", str(self.data_dir / "backups")))
        self.ssh_known_hosts_file = Path(os.environ.get("NETOPS_SSH_KNOWN_HOSTS_FILE", str(self.config_dir / "known_hosts")))
        self.mac_registry_dir = Path(os.environ.get("NETOPS_MAC_REGISTRY_DIR", str(self.cache_dir / "mac-registry")))
        self.secrets_file = Path(os.environ.get("NETOPS_SECRETS_FILE", str(self.data_dir / "secrets.gpg")))
        source_webui = self.install_dir / "webui" / "dist"
        installed_webui = Path(sys.prefix) / "share" / "netops-platform" / "webui" / "dist"
        self.webui_dist_dir = source_webui if source_webui.is_dir() else installed_webui
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.config_dir.mkdir(parents=True, exist_ok=True)

    def tool(self, name: str) -> str:
        local = self.install_dir / name
        if local.exists():
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
            environment_key = "NETOPS_" + key.upper()
            if key == "strip_prefixes":
                environment_key = "NETOPS_IDENTITY_STRIP_PREFIXES"
            if environment_key in os.environ:
                values[key] = os.environ[environment_key]
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
CREATE TABLE IF NOT EXISTS plugin_state(name TEXT NOT NULL,entry_point_group TEXT NOT NULL,enabled INTEGER NOT NULL DEFAULT 0,distribution TEXT,version TEXT,source TEXT,api_version TEXT,last_status TEXT,last_error TEXT,updated_at INTEGER NOT NULL,PRIMARY KEY(name,entry_point_group));
CREATE TABLE IF NOT EXISTS secret_metadata(name TEXT PRIMARY KEY,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL,last_used_at INTEGER,source TEXT NOT NULL);
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
CREATE INDEX IF NOT EXISTS idx_capability_evidence_device ON capability_evidence(device_id,capability,observed_at);
CREATE INDEX IF NOT EXISTS idx_path_runs_endpoint ON path_runs(endpoint,vlan,started_at);
CREATE INDEX IF NOT EXISTS idx_path_findings_run ON path_findings(run_id,severity);
"""

class State:
    def __init__(self, paths: Paths):
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
            con.execute(
                "INSERT OR REPLACE INTO schema_meta(key,value,updated_at) VALUES('schema_version',?,?)",
                (SCHEMA_VERSION, now()),
            )

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
            "counts": self.counts(),
            "files": {
                "sqlite_bytes": self.paths.sqlite_db.stat().st_size if self.paths.sqlite_db.exists() else 0,
                "wal_bytes": wal.stat().st_size if wal.exists() else 0,
                "shm_bytes": shm.stat().st_size if shm.exists() else 0,
            },
        }

    def mark_stale_jobs(self) -> int:
        with self.connect() as con:
            cur = con.execute("UPDATE jobs SET status='stale',finished_at=?,exit_code=? WHERE status IN ('queued','running')", (now(), INTERNAL))
            return int(cur.rowcount or 0)

    def rows(self, sql: str, args: Sequence[Any] = ()) -> List[Dict[str, Any]]:
        with self.connect() as con:
            return [dict(r) for r in con.execute(sql, tuple(args)).fetchall()]

    def one(self, sql: str, args: Sequence[Any] = ()) -> Optional[Dict[str, Any]]:
        with self.connect() as con:
            row = con.execute(sql, tuple(args)).fetchone()
            return dict(row) if row else None

    def execute(self, sql: str, args: Sequence[Any] = ()) -> None:
        with self.connect() as con:
            con.execute(sql, tuple(args))

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

    def _dedupe_ap_pipe_rows(self, rows: List[List[str]]) -> List[List[str]]:
        best: Dict[str, List[str]] = {}
        scores: Dict[str, Tuple[int, int, int, int, int, int]] = {}
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
        if int(reconciliation.get("manual_merges", {}).get("suppressed") or 0):
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
            return {"origin": origin, "timestamp": ts, "manual_merges": merge_application, "suppressed_structural_events": suppressed}

    def _current_inventory_rows(self, con: sqlite3.Connection) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        raw_devices = [dict(row) for row in con.execute("SELECT ip,hostname,hostname AS name,mac,platform,model,serial,NULL AS switch_ip,NULL AS switch_name,NULL AS switch_port,source,status,last_seen FROM devices WHERE COALESCE(ip,'')!=''")]
        devices = reconcile_device_rows(raw_devices)
        self._overlay_manual_device_merges(con, devices)
        for item in devices:
            item["entity_type"] = "device"
            rows.append(item)
        raw_aps = [dict(row) for row in con.execute("SELECT * FROM aps WHERE COALESCE(ip,'')!='' OR COALESCE(name,'')!='' OR COALESCE(mac,'')!=''")]
        for item in reconcile_ap_rows(raw_aps):
            item.update({
                "entity_type": "ap",
                "model": item.get("model") or "",
                "serial": item.get("serial") or "",
                "source": item.get("source") or "AP",
            })
            rows.append(item)
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
    def _device_merge_key(row: Dict[str, Any]) -> str:
        mac = norm_mac(row.get("mac"))
        if mac:
            return "mac:" + mac
        serial = re.sub(r"[^A-Z0-9]", "", str(row.get("serial") or "").upper())
        if serial not in {"", "NA", "NONE", "NULL", "UNKNOWN", "NOTAVAILABLE"}:
            return "serial:" + serial.lower()
        ip = str(row.get("ip") or "").strip()
        if is_ipv4_literal(ip):
            return "ip:" + ip
        name = compact_name(row.get("hostname") or row.get("name")).lower()
        return "name:" + name if name else ""

    @staticmethod
    def _merge_snapshot(row: Dict[str, Any], field: str) -> Dict[str, Any]:
        try:
            payload = json.loads(str(row.get(field) or "{}"))
        except (TypeError, json.JSONDecodeError):
            payload = {}
        return payload if isinstance(payload, dict) else {}

    @classmethod
    def _device_matches_snapshot(cls, row: Dict[str, Any], snapshot: Dict[str, Any]) -> bool:
        row_key = cls._device_merge_key(row)
        snapshot_key = cls._device_merge_key(snapshot)
        if row_key and snapshot_key and row_key == snapshot_key:
            return True
        assessment = identity_match_evidence(row, snapshot, "switch")
        return bool(assessment.get("same_device"))

    @staticmethod
    def _active_device_merges(con: sqlite3.Connection) -> List[Dict[str, Any]]:
        return [
            dict(row)
            for row in con.execute(
                "SELECT * FROM inventory_merges WHERE entity_type='device' AND revoked_at IS NULL ORDER BY created_at,merge_id"
            )
        ]

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

    def list_device_merges(self, include_revoked: bool = False) -> List[Dict[str, Any]]:
        where = "" if include_revoked else " WHERE revoked_at IS NULL"
        return self.rows(
            "SELECT merge_id,entity_type,source_key,target_key,source_name,source_ip,target_name,target_ip,reason,actor,created_at,last_applied_at,suppressed_observations,revoked_at,revoked_by,revoke_reason "
            f"FROM inventory_merges{where} ORDER BY created_at DESC,merge_id DESC"
        )

    def create_device_merge(self, source_row: Dict[str, Any], target_row: Dict[str, Any], reason: str, actor: str) -> Dict[str, Any]:
        source = self._device_snapshot(source_row)
        target = self._device_snapshot(target_row)
        source_key = self._device_merge_key(source)
        target_key = self._device_merge_key(target)
        if not source_key or not target_key:
            raise ValueError("both devices require a stable MAC, serial, IP, or hostname identity")
        if source_key == target_key or source.get("ip") == target.get("ip"):
            raise ValueError("source and target resolve to the same active device")
        reason = str(reason or "").strip()
        if not reason or len(reason) > 500 or any(value in reason for value in "\r\n\x00"):
            raise ValueError("a one-line merge reason of 1-500 characters is required")
        actor = str(actor or "local")[:128]
        merge_id = "mrg-" + uuid.uuid4().hex[:20]
        ts = now()
        source_json = json.dumps(source, sort_keys=True, separators=(",", ":"))
        target_json = json.dumps(target, sort_keys=True, separators=(",", ":"))
        with self.connect() as con:
            active = self._active_device_merges(con)
            edges = {str(row["source_key"]): str(row["target_key"]) for row in active}
            if source_key in edges:
                raise ValueError(f"source device already has an active manual merge: {source_key}")
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
                (merge_id, "device", source_key, target_key, source["hostname"], source["ip"], target["hostname"], target["ip"], source_json, target_json, reason, actor, ts),
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
                    (ts, "device", kind, value, "manually_merged", source_json, json.dumps({"merge_id": merge_id, "target": target}, sort_keys=True, separators=(",", ":")), source["ip"], source["mac"], source["hostname"], source["platform"], source["model"], source["serial"], source["source"], "HISTORICAL"),
                )
                existing = con.execute(
                    "SELECT first_seen FROM inventory_identity_state WHERE identity_kind=? AND identity_value=? AND entity_type='device'",
                    (kind, value),
                ).fetchone()
                first_seen = int(existing[0]) if existing and existing[0] else int(source.get("last_seen") or ts)
                con.execute(
                    "INSERT OR REPLACE INTO inventory_identity_state(identity_kind,identity_value,entity_type,ip,mac,name,platform,model,serial,switch_ip,switch_name,switch_port,source,status,first_seen,last_seen,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (kind, value, "device", source["ip"], source["mac"], source["hostname"], source["platform"], source["model"], source["serial"], "", "", "", source["source"], "HISTORICAL", first_seen, int(source.get("last_seen") or ts), ts),
                )
        return {
            "merge_id": merge_id,
            "entity_type": "device",
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

    def revoke_device_merge(self, merge_id: str, reason: str, actor: str) -> Dict[str, Any]:
        merge_id = str(merge_id or "").strip()
        reason = str(reason or "").strip()
        if not merge_id:
            raise ValueError("merge id is required")
        if not reason or len(reason) > 500 or any(value in reason for value in "\r\n\x00"):
            raise ValueError("a one-line revocation reason of 1-500 characters is required")
        ts = now()
        with self.connect() as con:
            stored = con.execute(
                "SELECT * FROM inventory_merges WHERE merge_id=? AND entity_type='device' AND revoked_at IS NULL",
                (merge_id,),
            ).fetchone()
            if not stored:
                raise ValueError(f"active manual merge not found: {merge_id}")
            merge = dict(stored)
            source = self._merge_snapshot(merge, "source_snapshot_json")
            source_ip = str(source.get("ip") or "")
            if not is_ipv4_literal(source_ip):
                raise ValueError("historical source has no restorable IP address")
            existing = con.execute("SELECT * FROM devices WHERE ip=?", (source_ip,)).fetchone()
            if existing and not self._device_matches_snapshot(dict(existing), source):
                raise ValueError(f"source IP is now owned by a different active device: {source_ip}")
            if not existing:
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
                (ts, "device", "merge", merge_id, "manual_merge_revoked", merge["target_snapshot_json"], merge["source_snapshot_json"], source["ip"], source["mac"], source["hostname"], source["platform"], source["model"], source["serial"], source["source"], source["status"]),
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
        desired = self._relationship_desired(con, inventory_rows); existing = {r["rel_key"]: dict(r) for r in con.execute("SELECT * FROM relationships_current")}; managed = {"identity_ip","identity_mac","identity_alias","device_alias","manual_identity_merge","ap_attachment","neighbor_link","port_occupancy"}
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

    def record_core_lookup(self, target: str, output: str, exit_code: int) -> None:
        ts = now()
        with self.connect() as con:
            con.execute("INSERT INTO core_lookup_cache(created_at,target,exit_code,output) VALUES(?,?,?,?)", (ts,target,exit_code,output[-8000:]))
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


HELP_TOPICS: Dict[str, Dict[str, Any]] = {
    "tui": {
        "summary": "Open the command-first local operator console. The `netop tui` and `netops tui` forms are equivalent.",
        "usage": "netop tui [--view VIEW] [--target TARGET]",
        "actions": {
            "open": {"usage": "netop tui [--view VIEW] [--target TARGET]", "about": "Launch the terminal console on its searchable action hub. `netops tui` remains supported.", "examples": ["netop tui", "netop tui --view diagnostics", "netops tui --view inventory --target ZONE34"]},
        },
    },
    "inventory": {
        "summary": "Switch/router inventory, flat-file migration, details, and bulk activity checks.",
        "usage": "netops inventory <action> [arguments] [global flags]",
        "actions": {
            "scan": {"usage": "netops inventory scan [target|CIDR|range]", "about": "Refresh switch/router inventory. Imports refreshed flat cache data into SQLite when the scan completes.", "args": [{"name":"target", "text":"Optional hostname, IP, CIDR, range, or site token to scan."}], "examples": ["netops inventory scan", "netops inventory scan 203.0.113.0/24", "netops inventory scan ZONE10 --dry-run"]},
            "list": {"usage": "netops inventory list [pattern] [--status ONLINE|OFFLINE] [--site SITE]", "about": "Search devices and APs from canonical SQLite inventory.", "args": [{"name":"pattern", "text":"Optional text matched against IP, hostname, platform, AP name, or switch name."}], "examples": ["netops inventory list ZONE10", "netops inventory list --status OFFLINE", "netops inventory list 192.0.2 --json"]},
            "show": {"usage": "netops inventory show [pattern]", "about": "Alias of inventory list for quick lookup.", "args": [{"name":"pattern", "text":"Optional search text."}], "examples": ["netops inventory show sq34"]},
            "details": {"usage": "netops inventory details <target>", "about": "Show deeper information for one device or AP. Plain output delegates to the legacy details view; JSON uses canonical state.", "args": [{"name":"target", "text":"Hostname, AP name, IP, or partial match."}], "examples": ["netops inventory details sq34", "netops inventory details 198.51.100.92 --json"]},
            "activity": {"usage": "netops inventory activity --file devices.txt", "about": "Ping a list of switches/APs and print offline records first, then online records.", "args": [{"name":"--file", "text":"Text file with one hostname or IP per line. Blank lines and # comments are ignored."}, {"name":"targets", "text":"You can also provide targets directly after the action."}], "examples": ["netops inventory activity --file ./devices.txt", "netops inventory activity sq34 sq35 ap-sq10"]},
            "merge": {"usage": "netops inventory merge <old-device> <current-device> --reason TEXT [--dry-run|--confirm]", "about": "Retire an old device into the current device's chronological identity. The old record leaves active inventory but remains searchable historical memory.", "args": [{"name":"old-device", "text":"Exact hostname or IP of the active record to retire."}, {"name":"current-device", "text":"Exact hostname or IP of the active record that remains current."}, {"name":"--reason", "text":"Required one-line audit reason."}], "examples": ["netops inventory merge SITE-A-OLD-SW01 SITE-A-ACCESS-01 --reason 'approved hardware replacement' --dry-run", "netops inventory merge 192.0.2.11 192.0.2.21 --reason 'verified replacement' --confirm"]},
            "merges": {"usage": "netops inventory merges [--all]", "about": "List active manual identity merges newest first; --all includes revoked merges.", "examples": ["netops inventory merges", "netops inventory merges --all --json"]},
            "unmerge": {"usage": "netops inventory unmerge <merge-id> --reason TEXT --confirm", "about": "Revoke a manual merge and restore its source snapshot when the old IP has not been reassigned.", "args": [{"name":"merge-id", "text":"Identifier from inventory merges."}, {"name":"--reason", "text":"Required one-line revocation reason."}], "examples": ["netops inventory unmerge mrg-example --reason 'association was incorrect' --confirm"]},
            "import-flat": {"usage": "netops inventory import-flat", "about": "Import devices.db, ap_devices.db, and neighbor.db into SQLite.", "examples": ["netops inventory import-flat", "netops inventory import-flat --json"]},
            "export-flat": {"usage": "netops inventory export-flat", "about": "Export SQLite inventory back to the legacy pipe-delimited files.", "examples": ["netops inventory export-flat"]},
        },
    },
    "ap": {
        "summary": "Wireless AP inventory, AP-on-switch lookup, AP move history, unjoined WLC records, and AP timelines.",
        "usage": "netops ap <action> [arguments] [global flags]",
        "actions": {
            "scan": {"usage": "netops ap scan", "about": "Refresh AP inventory from wireless/controller sources.", "examples": ["netops ap scan"]},
            "list": {"usage": "netops ap list [pattern] [--status ONLINE|OFFLINE]", "about": "Search AP inventory.", "args": [{"name":"pattern", "text":"Optional AP name, IP, platform, switch, or port pattern."}], "examples": ["netops ap list ZONE10", "netops ap list --status OFFLINE"]},
            "unjoined": {"usage": "netops ap unjoined [pattern] [--limit N]", "about": "Show Cisco WLC APs seen in join statistics but not currently joined.", "args": [{"name":"pattern", "text":"Optional AP name/MAC/site filter."}], "examples": ["netops ap unjoined", "netops ap unjoined SITE-A --json"]},
            "show": {"usage": "netops ap show [pattern]", "about": "Alias of ap list for quick lookup.", "examples": ["netops ap show SITEA"]},
            "on-switch": {"usage": "netops ap on-switch <switch>", "about": "Show APs currently attached to a switch, using controller and memory state.", "args": [{"name":"switch", "text":"Switch hostname, short name, site token, or IP."}], "examples": ["netops ap on-switch ZONE10", "netops ap on-switch SITEAZONE34SW01"]},
            "moves": {"usage": "netops ap moves [--limit N]", "about": "Show recorded AP switch/port movement events.", "examples": ["netops ap moves", "netops ap moves --limit 50"]},
            "timeline": {"usage": "netops ap timeline [target]", "about": "Show AP attachment timeline events.", "args": [{"name":"target", "text":"Optional AP name/IP/MAC or relationship search term."}], "examples": ["netops ap timeline", "netops ap timeline AP-ZONE10-01"]},
        },
    },
    "topology": {
        "summary": "LLDP/CDP neighbor scans, topology display, topology changes, and link timelines.",
        "usage": "netops topology <action> [arguments] [global flags]",
        "actions": {
            "scan": {"usage": "netops topology scan", "about": "Refresh LLDP/CDP neighbor data.", "examples": ["netops topology scan"]},
            "show": {"usage": "netops topology show [target]", "about": "Show topology links. With a target in plain mode, opens the legacy topology view for that target.", "args": [{"name":"target", "text":"Optional switch/site/IP."}], "examples": ["netops topology show", "netops topology show ZONE10"]},
            "neighbors": {"usage": "netops topology neighbors [target]", "about": "List cached neighbor rows.", "examples": ["netops topology neighbors --json"]},
            "changes": {"usage": "netops topology changes [--limit N]", "about": "Show topology change events.", "examples": ["netops topology changes"]},
            "timeline": {"usage": "netops topology timeline [target]", "about": "Show neighbor relationship timeline.", "examples": ["netops topology timeline ZONE10"]},
        },
    },
    "memory": {
        "summary": "Relationship memory: AP attachments, IP/MAC ownership, switch ports, topology, and source confidence.",
        "usage": "netops memory <action> [arguments] [global flags]",
        "actions": {
            "refresh": {"usage": "netops memory refresh", "about": "Recompute relationship memory from inventory, APs, topology, and lookup observations.", "examples": ["netops memory refresh"]},
            "switch": {"usage": "netops memory switch <switch>", "about": "Show APs, neighbors, current relationships, and timeline for a switch/site.", "args": [{"name":"switch", "text":"Switch hostname, short name, IP, or site token."}], "examples": ["netops memory switch ZONE10", "netops memory switch SITEAZONE34SW01 --json"]},
            "device": {"usage": "netops memory device <name|ip>", "about": "Show relationships involving a device or AP.", "examples": ["netops memory device 198.51.100.92"]},
            "ip": {"usage": "netops memory ip <ip>", "about": "Show historical ownership and relationship events for an IP address.", "examples": ["netops memory ip 198.51.100.92"]},
            "mac": {"usage": "netops memory mac <mac>", "about": "Show identity and movement history for a MAC address.", "examples": ["netops memory mac 0200.0000.0025"]},
            "port": {"usage": "netops memory port <switch> <port>", "about": "Show current and historical occupancy for one switch port.", "args": [{"name":"switch", "text":"Switch name/IP/site token."}, {"name":"port", "text":"Interface name, for example Gi1/0/7."}], "examples": ["netops memory port ZONE34 Gi1/0/7"]},
            "timeline": {"usage": "netops memory timeline [target]", "about": "Search the full relationship event timeline.", "examples": ["netops memory timeline 192.0.2", "netops memory timeline --limit 200"]},
            "explain": {"usage": "netops memory explain [target]", "about": "Summarize relationship sources and average confidence.", "examples": ["netops memory explain ZONE10"]},
            "export": {"usage": "netops memory export [--json]", "about": "Export current relationships.", "examples": ["netops memory export --json"]},
            "prune": {"usage": "netops memory prune", "about": "Reserved for future pruning. Relationship history is retained forever by default.", "examples": ["netops memory prune"]},
        },
    },
    "health": {
        "summary": "Reachability, stale state, offline lists, attention queue, and health timeline.",
        "usage": "netops health <action> [arguments] [global flags]",
        "actions": {
            "check": {"usage": "netops health check [target]", "about": "Run fast reachability checks and refresh health state.", "examples": ["netops health check", "netops health check ZONE10"]},
            "status": {"usage": "netops health status [--limit N]", "about": "Show current health state for devices and APs.", "examples": ["netops health status"]},
            "offline": {"usage": "netops health offline [--limit N]", "about": "List current offline devices/APs.", "examples": ["netops health offline"]},
            "attention": {"usage": "netops health attention [--limit N]", "about": "Show items needing operator review: offline, flapping, topology changes, AP moves, backup issues.", "examples": ["netops health attention"]},
            "timeline": {"usage": "netops health timeline [--limit N]", "about": "Show health events over time.", "examples": ["netops health timeline"]},
        },
    },
    "backup": {
        "summary": "Online-only, changed-only config backups plus backup history and diffs.",
        "usage": "netops backup <action> [arguments] [global flags]",
        "actions": {
            "run": {"usage": "netops backup run <target> [--redact-secrets]", "about": "Back up online devices only, skip unchanged configs, and print a summary.", "args": [{"name":"target", "text":"Hostname, IP, site token, or pattern supported by netops-control."}], "examples": ["netops backup run ZONE34", "netops backup run 198.51.100.92 --redact-secrets"]},
            "history": {"usage": "netops backup history <target>", "about": "Show backup history for one target.", "examples": ["netops backup history ZONE34"]},
            "diff": {"usage": "netops backup diff <target>", "about": "Diff the latest backup against the previous backup.", "examples": ["netops backup diff ZONE34"]},
            "verify": {"usage": "netops backup verify [--limit N]", "about": "Show backup metadata recorded in SQLite.", "examples": ["netops backup verify"]},
        },
    },
    "device": {
        "summary": "SSH, read-only show commands, config previews/confirmed changes, and inventory enrichment.",
        "usage": "netops device <action> [arguments] [global flags]",
        "actions": {
            "ssh": {"usage": "netops device ssh [-l|--legacy] <target>", "about": "Open an interactive SSH session using netops-connect. If SSH negotiation reports legacy algorithms, retry with -l/--legacy.", "examples": ["netops device ssh ZONE34", "netops device ssh -l ZONE34", "netops device ssh 198.51.100.92"]},
            "show": {"usage": "netops device show <target> <show-command>", "about": "Run a read-only show command through netops-control.", "args": [{"name":"target", "text":"Hostname, IP, or inventory match."}, {"name":"show-command", "text":"Command text after the target, for example show interface status."}], "examples": ["netops device show ZONE34 show version", "netops device show 198.51.100.92 show interface status"]},
            "config": {"usage": "netops device config <target> <commands...> --dry-run|--confirm", "about": "Run configuration commands. Requires --dry-run or --confirm.", "examples": ["netops device config ZONE34 'interface Gi1/0/7' 'description AP' --dry-run"]},
            "inventory": {"usage": "netops device inventory [target|--view]", "about": "View or enrich device inventory through netops-control.", "examples": ["netops device inventory --view", "netops device inventory ZONE34"]},
            "support": {"usage": "netops device support [target]", "about": "Show registered Cisco, Aruba, and Ruckus driver capabilities, or classify one inventory target.", "examples": ["netops device support", "netops device support ZONE34 --json"]},
            "identity": {"usage": "netops device identity <first> <second>", "about": "Explain name, IP, MAC, serial, model, and attachment evidence used to assess two switch records.", "examples": ["netops device identity SITE-A-PLNT-PLN-SW01 SITEAPLNTPLANSW01"]},
            "trust-status": {"usage": "netops device trust status [target]", "about": "Inspect the private managed known-hosts store without touching the network.", "examples": ["netops device trust status", "netops device trust status ZONE34 --json"]},
            "trust-scan": {"usage": "netops device trust scan <target>", "about": "Retrieve current SSH host keys and print SHA-256 fingerprints without trusting them.", "examples": ["netops device trust scan ZONE34"]},
            "trust-enroll": {"usage": "netops device trust enroll <target> --fingerprint SHA256:... --confirm", "about": "Store only host keys whose out-of-band verified fingerprints match the scan.", "examples": ["netops device trust enroll ZONE34 --fingerprint SHA256:abc... --confirm"]},
            "trust-forget": {"usage": "netops device trust forget <target> --confirm", "about": "Remove a target from the managed trust store after explicit confirmation.", "examples": ["netops device trust forget ZONE34 --confirm"]},
        },
    },
    "vault": {
        "summary": "Local SSH-password vault lifecycle with terminal sudo authentication and no graphical pinentry.",
        "usage": "netops vault <status|set|migrate|unlock>",
        "actions": {
            "status": {"usage": "netops vault status [--json]", "about": "Show vault security plus password-recorded time, expected three-day expiry window, and current lifecycle state without prompting.", "examples": ["netops vault status", "netops vault status --json"]},
            "set": {"usage": "netops vault set [--legacy-vault]", "about": "Save a new SSH password. The default sudo-gated mode asks for terminal sudo authentication and never stores the sudo password.", "options": [{"name":"--legacy-vault", "text":"Use a terminal-passphrase GPG vault when sudo-backed storage is unavailable."}], "examples": ["netops vault set"]},
            "migrate": {"usage": "netops vault migrate", "about": "Decrypt the existing legacy vault once in the terminal, then atomically replace it with the sudo-gated GPG format.", "examples": ["netops vault migrate"]},
            "unlock": {"usage": "netops vault unlock", "about": "Authenticate with sudo and verify that the vault decrypts; later commands reuse sudo's configured authentication timeout.", "examples": ["netops vault unlock"]},
        },
    },
    "vlan": {
        "summary": "Read-only VLAN lookup/propagation plus guarded VLAN changes.",
        "usage": "netops vlan <action> [arguments] [global flags]",
        "actions": {
            "locate": {"usage": "netops vlan locate <target[,target...]> <vlan[,vlan|range...]> [--depth N] [--max-nodes N]", "about": "Find one or many VLANs from one or many roots. Depth zero inspects roots; positive depth traverses LLDP/CDP-confirmed switch links breadth-first.", "examples": ["netops vlan locate ZONE34 120", "netops vlan locate SW1,SW2 10,20-22 --depth 2", "netops vlan locate --target SW1 --target SW2 --vlan 10,20 --depth 5"]},
            "propagation": {"usage": "netops vlan propagation <target[,target...]> <vlan[,vlan|range...]> [--depth N] [--max-nodes N]", "about": "Build a root-by-VLAN propagation matrix, traversing every reachable switch layer within the depth/node bounds.", "examples": ["netops vlan propagation ZONE34 120", "netops vlan propagation site-a-core 131 --depth 5", "netops vlan propagation SW1,SW2 10,20 --depth 3"]},
            "set": {"usage": "netops vlan set <target> <interface> [--access N|--trunk LIST] --dry-run|--confirm", "about": "Guarded VLAN change wrapper. Requires --dry-run or --confirm.", "examples": ["netops vlan set ZONE34 Gi1/0/7 --access 120 --dry-run"]},
        },
    },
    "lookup": {
        "summary": "Core and MAC lookups. Results are cached into relationship memory.",
        "usage": "netops lookup <action> [arguments] [global flags]",
        "actions": {
            "core": {"usage": "netops lookup core <ip|mac>", "about": "Run core lookup and cache observations into memory.", "examples": ["netops lookup core 198.51.100.92", "netops lookup core 0200.0000.0025"]},
            "mac": {"usage": "netops lookup mac <inspect|locate|profile|history|vendor|online|registry> ...", "about": "Inspect local evidence, search forwarding tables, profile an edge port, show movement history, or query cached authoritative IEEE MA-L/MA-M/MA-S assignments.", "examples": ["netops lookup mac online 00:00:5e:00:53:01", "netops lookup mac inspect 0200.0000.0025", "netops lookup mac locate 0200.0000.0025 ZONE34", "netops lookup mac registry refresh"]},
            "mac-online": {"usage": "netops lookup mac online <mac> [--refresh|--offline]", "about": "Resolve the longest matching IEEE MA-L, MA-M, or MA-S assignment with organization details, cache time, and source provenance.", "examples": ["netops lookup mac online 00:00:5e:00:53:01", "netops lookup mac online 00:00:5e:00:53:01 --refresh"]},
            "mac-registry": {"usage": "netops lookup mac registry <status|refresh>", "about": "Inspect or refresh the private cache of all three IEEE public MAC assignment registries.", "examples": ["netops lookup mac registry status", "netops lookup mac registry refresh"]},
            "mac-inspect": {"usage": "netops lookup mac inspect <mac>", "about": "Correlate cached identity, L2 location, IP, vendor, inventory, and movement evidence without touching devices.", "examples": ["netops lookup mac inspect 0200.0000.0025"]},
            "mac-locate": {"usage": "netops lookup mac locate <mac> [--site SITE] [--limit N]", "about": "Search switch forwarding tables directly, independent of whether the endpoint has an IP address.", "examples": ["netops lookup mac locate 0200.0000.0025", "netops lookup mac locate 0200.0000.0025 --site ZONE34"]},
            "mac-profile": {"usage": "netops lookup mac profile <mac> [--site SITE]", "about": "Locate a MAC, then gather best-effort interface, LLDP/CDP, PoE, device-tracking, OUI, and core ARP evidence at likely edge ports.", "examples": ["netops lookup mac profile 0200.0000.0025"]},
            "mac-history": {"usage": "netops lookup mac history <mac>", "about": "Show newest-first MAC location and identity events.", "examples": ["netops lookup mac history 0200.0000.0025"]},
            "mac-vendor": {"usage": "netops lookup mac vendor <mac>", "about": "Resolve the locally installed OUI prefix. This identifies an organization, not an exact model.", "examples": ["netops lookup mac vendor 00:00:5e:00:53:01"]},
        },
    },
    "diagnose": {
        "summary": "Local/core latency, verified Internet speed, controlled throughput, port health, and guarded copper cable diagnostics.",
        "usage": "netops diagnose <action> [arguments] [global flags]",
        "actions": {
            "latency": {"usage": "netops diagnose latency <target> [--count N]", "about": "Run a continuous latency probe by default. Add --count N for a finite run; JSON output is finite and defaults to 5 samples.", "examples": ["netops diagnose latency 1.1.1.1", "netops diagnose latency ZONE34 --count 10"]},
            "core-ping": {"usage": "netops diagnose core-ping <target> [--core SWITCH] [--count N]", "about": "Point-of-truth ICMP probe issued by the configured core switch, with parsed loss and min/average/max latency stored in diagnostics history.", "examples": ["netops diagnose core-ping 192.0.2.50 --count 5", "netops diagnose core-ping ZONE34 --core CORE01"]},
            "speed": {"usage": "netops diagnose speed [--profile quick|balanced|thorough] [--runs N] [--ca-file PEM]", "about": "Measure this NetOps host's routed Internet path with verified TLS, loaded latency, jitter, loss, and profile-specific confidence/runtime tradeoffs.", "examples": ["netops diagnose speed", "netops diagnose speed --profile quick", "netops diagnose speed --profile thorough --runs 5"]},
            "throughput": {"usage": "netops diagnose throughput <iperf3-server> [--direction both|upload|download] [--port 5201] [--seconds 10] [--parallel 1]", "about": "Measure TCP receiver goodput between this client and a controlled iperf3 server. Run it on the endpoint attached to a switch port for endpoint-to-core results.", "examples": ["netops diagnose throughput 203.0.113.20", "netops diagnose throughput core --direction both --parallel 2"]},
            "port-health": {"usage": "netops diagnose port-health <device> on <interface> [--sample-seconds 5] [--expected-speed 1000]", "about": "Read link negotiation and switch counters twice, then distinguish cumulative history from errors increasing during the sample.", "examples": ["netops diagnose port-health ZONE34 on Gi1/0/7", "netops diagnose port-health 203.0.113.39 on Gi1/0/12 --sample-seconds 10"]},
            "cable": {"usage": "netops diagnose cable <device> on <interface> [--test --dry-run|--confirm] [--wait N]", "about": "Read the previous copper TDR result by default. Starting a new potentially disruptive TDR requires an explicit preview or confirmation.", "examples": ["netops diagnose cable ZONE34 on Gi1/0/7", "netops diagnose cable ZONE34 on Gi1/0/7 --test --dry-run"]},
            "doctor": {"usage": "netops diagnose doctor [--online]", "about": "Audit local dependencies, route, WSL limitations, secure speed backend, core settings, and optional iperf/cable tooling.", "examples": ["netops diagnose doctor", "netops diagnose doctor --online"]},
            "filtering": {"usage": "netops diagnose filtering [domain]", "about": "Check DNS, 443/tcp, TLS issuer, and filtering/MITM indicators.", "examples": ["netops diagnose filtering google.com"]},
            "interface": {"usage": "netops diagnose interface <device> on <interface> [--chart classic|histogram]", "about": "Launch interface monitoring. Histogram mode mirrors the gateprober rate chart style.", "examples": ["netops diagnose interface ZONE34 on Gi1/0/7", "netops diagnose interface ZONE34 on Gi1/0/7 --chart histogram"]},
        },
    },
    "workflow": {
        "summary": "Safe multi-step operator workflows.",
        "usage": "netops workflow <name> [arguments] [global flags]",
        "actions": {
            "morning-check": {"usage": "netops workflow morning-check", "about": "Import cache, run health, refresh memory, review topology changes, filtering, and attention state.", "examples": ["netops workflow morning-check --dry-run"]},
            "refresh-inventory": {"usage": "netops workflow refresh-inventory", "about": "Health check, AP scan, topology scan, memory refresh, and attention summary.", "examples": ["netops workflow refresh-inventory"]},
            "backup-online": {"usage": "netops workflow backup-online [target]", "about": "Run changed-only backups for online devices.", "examples": ["netops workflow backup-online ZONE10"]},
            "site-health": {"usage": "netops workflow site-health <target>", "about": "Latency and filtering checks for a target/site.", "examples": ["netops workflow site-health google.com"]},
            "ap-audit": {"usage": "netops workflow ap-audit", "about": "Refresh AP data, recompute memory, show AP moves and attention.", "examples": ["netops workflow ap-audit"]},
        },
    },
    "jobs": {
        "summary": "Job queue, job details, logs, and server-side cancellation status.",
        "usage": "netops jobs <action> [arguments] [global flags]",
        "actions": {
            "list": {"usage": "netops jobs list [--limit N]", "about": "List recent jobs recorded in SQLite.", "examples": ["netops jobs list"]},
            "show": {"usage": "netops jobs show <id>", "about": "Show job metadata and logs.", "examples": ["netops jobs show abc123def456"]},
            "logs": {"usage": "netops jobs logs <id>", "about": "Alias of jobs show focused on captured output.", "examples": ["netops jobs logs abc123def456"]},
            "cancel": {"usage": "netops jobs cancel <id>", "about": "Cancellation is available for jobs running inside the current serve process.", "examples": ["netops jobs cancel abc123def456"]},
        },
    },
    "commands": {
        "summary": "Canonical command registry used by CLI, API, jobs, previews, workflows, and WebUI.",
        "usage": "netops commands <action> [arguments] [global flags]",
        "actions": {
            "list": {"usage": "netops commands list", "about": "List registered command IDs and risk metadata.", "examples": ["netops commands list"]},
            "show": {"usage": "netops commands show <id>", "about": "Show registry metadata for one command ID.", "examples": ["netops commands show backup-run --json"]},
            "run": {"usage": "netops commands run <id> [args] [--preview]", "about": "Run or preview a registry command. Required args depend on the command ID.", "examples": ["netops commands run backup-run ZONE34 --preview", "netops commands run diagnose-latency --target 1.1.1.1 --count 10"]},
        },
    },
    "db": {
        "summary": "SQLite lifecycle and flat-file compatibility shortcuts.",
        "usage": "netops db <action> [arguments] [global flags]",
        "actions": {
            "migrate": {"usage": "netops db migrate", "about": "Create or update the SQLite schema.", "examples": ["netops db migrate"]},
            "status": {"usage": "netops db status [--json]", "about": "Show SQLite path and table counts.", "examples": ["netops db status --json"]},
            "import-flat": {"usage": "netops db import-flat", "about": "Alias for inventory import-flat.", "examples": ["netops db import-flat"]},
            "export-flat": {"usage": "netops db export-flat", "about": "Alias for inventory export-flat.", "examples": ["netops db export-flat"]},
            "path": {"usage": "netops db path", "about": "Print the SQLite database path.", "examples": ["netops db path"]},
            "integrity": {"usage": "netops db integrity [--json]", "about": "Run SQLite integrity and quick checks without changing data.", "examples": ["netops db integrity", "netops db integrity --json"]},
            "repair": {"usage": "netops db repair", "about": "Run schema migration, derived-state sync, WAL checkpoint, ANALYZE, optimize, and integrity checks.", "examples": ["netops db repair"]},
            "vacuum": {"usage": "netops db vacuum", "about": "Checkpoint WAL and compact the SQLite database.", "examples": ["netops db vacuum"]},
        },
    },
    "serve": {
        "summary": "Start the localhost WebUI/API server.",
        "usage": "netops serve [--host 127.0.0.1] [--port 8787]",
        "actions": {"run": {"usage": "netops serve [--host 127.0.0.1] [--port 8787]", "about": "Serve the built WebUI and local API on localhost.", "examples": ["netops serve", "netops serve --port 8788"]}},
    },
    "ask": {
        "summary": "Deterministic state retrieval and registry-backed command planning from natural language.",
        "usage": 'netops ask ["question"] [global flags]',
        "actions": {
            "chat": {"usage": "netops ask", "about": "Open a continuous retrieval/command-planning prompt with result, target, and plan context.", "examples": ["netops ask"]},
            "question": {"usage": 'netops ask "question" [--execute [--confirm]]', "about": "Answer from current state or return a validated command plan. Planning never executes; --execute is a separate boundary, and active operations also require --confirm.", "examples": ['netops ask "How many APs are on the building9 switch at ZONE10?"', 'netops ask "Run a fast health check for ZONE34"', 'netops ask --execute --confirm "Run a fast health check for ZONE34"']},
            "patterns": {"usage": "netops ask patterns", "about": "List supported retrieval and command-center families with example wording.", "examples": ["netops ask patterns", "netops ask patterns --json"]},
            "aliases": {"usage": "netops ask aliases", "about": "List deterministic profile-specific phrase aliases.", "examples": ["netops ask aliases"]},
            "alias": {"usage": "netops ask alias set '<phrase>' '<target>' | remove '<phrase>'", "about": "Add or remove a durable local phrase alias. Natural alias plans are local-write actions and require explicit execution confirmation.", "examples": ["netops ask alias set 'engineering office' 'engg ofc'", "netops ask alias remove 'engineering office'"]},
        },
    },
}

HELP_TOPICS.update({
    "init": {
        "summary": "Initialize an isolated profile and check host capabilities.",
        "usage": "netops init [--profile NAME] [--migrate-legacy]",
        "actions": {
            "run": {"usage": "netops init [--profile NAME] [--migrate-legacy]", "about": "Create neutral XDG profile state and report required and optional system tools.", "examples": ["netops init", "netops init --profile lab", "netops init --migrate-legacy"]},
        },
    },
    "profile": {
        "summary": "Create, select, inspect, and migrate isolated operator profiles.",
        "usage": "netops profile <list|show|create|use|paths|migrate-legacy>",
        "actions": {
            "list": {"usage": "netops profile list", "about": "List profiles and show which one is active.", "examples": ["netops profile list"]},
            "show": {"usage": "netops profile show [name]", "about": "Show one profile's paths and effective non-secret settings.", "examples": ["netops profile show default"]},
            "create": {"usage": "netops profile create <name>", "about": "Create a neutral, private profile without changing the active profile.", "examples": ["netops profile create lab"]},
            "use": {"usage": "netops profile use <name>", "about": "Select the profile used by future commands.", "examples": ["netops profile use lab"]},
            "paths": {"usage": "netops profile paths", "about": "Show the active profile's XDG-owned directories.", "examples": ["netops profile paths --json"]},
            "migrate-legacy": {"usage": "netops profile migrate-legacy [legacy-local]", "about": "Copy legacy netsnmp state into a private profile, recording a manifest and leaving originals untouched.", "examples": ["netops profile migrate-legacy legacy-local"]},
        },
    },
    "config": {
        "summary": "Inspect and change non-secret profile configuration.",
        "usage": "netops config <show|get|set|unset|validate|paths>",
        "actions": {
            "show": {"usage": "netops config show", "about": "Show effective redacted settings and precedence.", "examples": ["netops config show --json"]},
            "get": {"usage": "netops config get <key>", "about": "Read one effective non-secret setting.", "examples": ["netops config get core_switch_ip"]},
            "set": {"usage": "netops config set <key> <value>", "about": "Set a profile override. Secret-looking keys are rejected.", "examples": ["netops config set core_switch_ip 192.0.2.10"]},
            "unset": {"usage": "netops config unset <key>", "about": "Remove a profile compatibility override.", "examples": ["netops config unset target_abbreviation_prefix"]},
            "validate": {"usage": "netops config validate", "about": "Validate effective configuration and flag legacy plaintext credentials.", "examples": ["netops config validate"]},
            "paths": {"usage": "netops config paths", "about": "Show global, profile, and compatibility config files.", "examples": ["netops config paths"]},
        },
    },
    "secrets": {
        "summary": "Manage named sudo-gated encrypted secrets without putting values in arguments or config.",
        "usage": "netops secrets <list|status|set|delete|import-ssh>",
        "actions": {
            "list": {"usage": "netops secrets list", "about": "List secret names and recording dates; values are never displayed.", "examples": ["netops secrets list"]},
            "status": {"usage": "netops secrets status", "about": "Show encrypted store security and lock state.", "examples": ["netops secrets status"]},
            "set": {"usage": "netops secrets set <name>", "about": "Prompt twice for a value and atomically encrypt it.", "examples": ["netops secrets set snmp/site-a/auth"]},
            "delete": {"usage": "netops secrets delete <name> --confirm", "about": "Delete one named secret after explicit confirmation.", "examples": ["netops secrets delete snmp/site-a/auth --confirm"]},
            "import-ssh": {"usage": "netops secrets import-ssh", "about": "Import the legacy SSH password into ssh/default/password without deleting the original vault.", "examples": ["netops secrets import-ssh"]},
        },
    },
    "ingest": {
        "summary": "Validate and run declarative, provenance-preserving data channels.",
        "usage": "netops ingest <channels|validate|run|history|rejects|observations>",
        "actions": {
            "channels": {"usage": "netops ingest channels", "about": "List TOML channels in the active profile.", "examples": ["netops ingest channels"]},
            "validate": {"usage": "netops ingest validate", "about": "Validate every channel manifest without fetching data.", "examples": ["netops ingest validate"]},
            "run": {"usage": "netops ingest run <channel>", "about": "Run one enabled channel with duplicate suppression and reject quarantine.", "examples": ["netops ingest run inventory-csv"]},
            "history": {"usage": "netops ingest history [--limit N]", "about": "Show ingest runs newest first.", "examples": ["netops ingest history"]},
            "rejects": {"usage": "netops ingest rejects [run-id]", "about": "Show redacted rejected-record metadata.", "examples": ["netops ingest rejects"]},
            "observations": {"usage": "netops ingest observations [channel]", "about": "Show append-only observations and evidence times.", "examples": ["netops ingest observations inventory-csv"]},
        },
    },
    "plugin": {
        "summary": "Discover and explicitly enable trusted Python entry-point plugins.",
        "usage": "netops plugin <list|enable|disable|check|groups>",
        "actions": {
            "list": {"usage": "netops plugin list", "about": "Discover plugins without importing disabled code.", "examples": ["netops plugin list"]},
            "enable": {"usage": "netops plugin enable <group:name>", "about": "Enable one unambiguous installed plugin for this profile.", "examples": ["netops plugin enable netops.parsers:example"]},
            "disable": {"usage": "netops plugin disable <group:name>", "about": "Disable one plugin for this profile.", "examples": ["netops plugin disable netops.parsers:example"]},
            "check": {"usage": "netops plugin check [group]", "about": "Load enabled plugins in isolation and report API or policy failures.", "examples": ["netops plugin check"]},
            "groups": {"usage": "netops plugin groups", "about": "List stable entry-point groups and their trust policy.", "examples": ["netops plugin groups"]},
        },
    },
    "path": {
        "summary": "Inspect a bounded endpoint path across cached topology and live read-only forwarding evidence.",
        "usage": "netops path <inspect|history|show>",
        "actions": {
            "inspect": {"usage": "netops path inspect <endpoint> --vlan <id> [--from SWITCH] [--to SWITCH] [--depth N] [--max-nodes N] [--cached|--live|--refresh] [--explain]", "about": "Plan from cached topology, then validate VLAN, trunk, STP, LAG, SVI, VRF, route, ARP/ND, and policy evidence where supported. `netops ghoster` is an alias.", "examples": ["netops path inspect 02:00:00:00:00:25 --vlan 120", "netops ghoster 192.0.2.25 --vlan 120 --from SITE-A-CORE-01 --explain", "netops path inspect endpoint-25 --vlan 120 --cached"]},
            "history": {"usage": "netops path history [endpoint]", "about": "Show chronological path runs newest first.", "examples": ["netops path history", "netops path history 192.0.2.25"]},
            "show": {"usage": "netops path show <run-id>", "about": "Reopen one persisted hop path and its findings.", "examples": ["netops path show path-0123456789abcdef"]},
        },
    },
    "support": {
        "summary": "Create privacy-redacted diagnostics for support and bug reports.",
        "usage": "netops support bundle [output.tar.gz]",
        "actions": {
            "bundle": {"usage": "netops support bundle [output.tar.gz]", "about": "Package version, redacted settings, integrity, drivers, plugins, and recent run summaries. Inventory and raw evidence are excluded.", "examples": ["netops support bundle", "netops support bundle ./netops-support.tar.gz"]},
        },
    },
})

LEGACY_NOUN_HINTS: Dict[str, str] = {
    "discover": "netops inventory scan",
    "discovery": "netops inventory scan",
    "control": "netops device <ssh|show|config|inventory>",
    "connect": "netops device ssh <target>",
    "probe": "netops diagnose latency <target>",
    "check": "netops diagnose filtering [domain]",
    "netcheck": "netops diagnose filtering [domain]",
    "gateprober": "netops diagnose interface <device> on <interface>",
    "interface": "netops diagnose interface <device> on <interface>",
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
    "jobs": {"log":"logs"},
    "commands": {"registry":"list", "preview":"run"},
    "db": {"import":"import-flat", "export":"export-flat", "init":"migrate"},
}

GLOBAL_FLAG_HELP = [
    ("--json", "Emit JSON for commands that support structured output."),
    ("--plain", "Prefer plain terminal output when both formats exist."),
    ("--no-tui", "Keep the no-argument CLI help behavior in an interactive terminal."),
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

class App:
    def __init__(self, install_dir: Path, profile: str = ""):
        os.environ["NETOPS_CORE_MANAGED"] = "1"
        self.paths = Paths(install_dir, profile=profile)
        self.config = Config(self.paths)
        for key, value in self.config.public.items():
            environment_key = "NETOPS_IDENTITY_STRIP_PREFIXES" if key == "strip_prefixes" else "NETOPS_" + key.upper()
            os.environ[environment_key] = value
        self.state = State(self.paths)
        self.natural_ask = NaturalAskEngine(self)
        self.jobs: Dict[str, Dict[str, Any]] = {}
        self.log_queues: Dict[str, queue.Queue] = {}
        self.lock = threading.RLock()
        self.sem = threading.Semaphore(bounded_int(os.environ.get("NETOPS_JOB_CONCURRENCY", "3"), 3, 1, 32))
        self.stopping = threading.Event()
        self.profile_store = ProfileStore(self.paths.home)
        self.plugin_manager = PluginManager(self.paths.config_dir)
        self.loaded_plugins = self.plugin_manager.load_enabled()
        self.plugin_ingest_providers = {
            item.descriptor.name: item.implementation
            for item in self.loaded_plugins
            if item.descriptor.group == "netops.ingest" and item.descriptor.load_status == "loaded" and item.implementation is not None
        }
        self.plugin_provider_sources = {
            item.descriptor.name: item.descriptor.source
            for item in self.loaded_plugins
            if item.descriptor.group == "netops.ingest" and item.descriptor.load_status == "loaded"
        }
        self.plugin_parsers = {
            item.descriptor.name: item.implementation
            for item in self.loaded_plugins
            if item.descriptor.group == "netops.parsers" and item.descriptor.load_status == "loaded" and item.implementation is not None
        }
        self.plugin_exporters = {
            item.descriptor.name: item.implementation
            for item in self.loaded_plugins
            if item.descriptor.group == "netops.exporters" and item.descriptor.load_status == "loaded" and item.implementation is not None
        }
        self.device_drivers = DEVICE_DRIVERS.clone()
        self.driver_manifest_report = self.device_drivers.load_declarative(self.paths.config_dir / "drivers")
        self.driver_manifest_report.extend(self.device_drivers.load_python_plugins(
            item for item in self.loaded_plugins if item.descriptor.group == "netops.device_drivers"
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
            self.legacy_cmd("netops-connect", "--secret-get", name),
            text=True,
            stdout=subprocess.PIPE,
            env=env,
            check=False,
        )
        if process.returncode != 0:
            raise RuntimeError(f"named secret could not be unlocked: {name}")
        return process.stdout.rstrip("\r\n")
    def emit(self, data: Any, opts: GlobalOptions, text: Optional[str] = None) -> None: print(json_dumps(data) if opts.json else (text if text is not None else self.render_plain(data)))
    def render_plain(self, data: Any) -> str:
        if isinstance(data, list): return self.render_table(data) if data and isinstance(data[0], dict) else "\n".join(map(str, data))
        if isinstance(data, dict) and "rows" in data: return self.render_table(data["rows"])
        if isinstance(data, dict): return "\n".join(f"{k}: {v}" for k, v in data.items() if not isinstance(v, (list, dict)))
        return str(data)
    def render_table(self, rows: List[Dict[str, Any]], columns: Optional[List[str]] = None) -> str:
        if not rows: return "No records."
        columns = columns or list(rows[0].keys())[:8]
        def display_value(row: Dict[str, Any], column: str) -> str:
            value = row.get(column, "")
            if is_timestamp_field(column):
                value = fmt_time(value) or value
            return str(value if value is not None else "")
        widths = {c: min(32, max(len(c), *(len(display_value(r, c)) for r in rows))) for c in columns}
        lines = ["  ".join(c.upper().ljust(widths[c]) for c in columns), "  ".join("-"*widths[c] for c in columns)]
        for row in rows:
            vals=[]
            for c in columns:
                s=display_value(row,c); raw=s[:max(0,widths[c]-3)]+"..." if len(s)>widths[c] else s; cell=raw.ljust(widths[c])
                if c.lower() == "status" and sys.stdout.isatty() and not os.environ.get("NO_COLOR"):
                    up=raw.strip().upper()
                    if up == "ONLINE": cell=f"\033[32m{cell}\033[0m"
                    elif up == "OFFLINE": cell=f"\033[31m{cell}\033[0m"
                    elif up in {"FAILED","ERROR","ATTENTION"}: cell=f"\033[33m{cell}\033[0m"
                vals.append(cell)
            lines.append("  ".join(vals))
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
        env = os.environ.copy()
        env.update(profile_environment(self.paths.profile_layout))
        for key, value in self.config.public.items():
            env["NETOPS_" + key.upper()] = value
        if opts.confirm:
            env["NETOPS_CORE_WRITE_REQUEST"] = "audited-confirmation"
        if opts.first:
            env["NETOPS_RESOLVE_MODE"] = "first"
        elif opts.all:
            env["NETOPS_RESOLVE_MODE"] = "all"
        elif opts.interactive:
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

    def _progress_enabled(self, opts: GlobalOptions) -> bool:
        return not opts.json and not os.environ.get("NO_COLOR") and os.environ.get("NETOPS_PROGRESS", "1") != "0" and sys.stderr.isatty()

    def _progress_update(self, message: str, opts: Optional[GlobalOptions] = None) -> None:
        if opts and opts.json:
            return
        if os.environ.get("NETOPS_PROGRESS", "1") == "0" or not sys.stderr.isatty():
            return
        text = strip_ansi(str(message)).replace("\n", " ")[:132]
        if not text.startswith("["):
            text = "[STATUS] " + text
        sys.stderr.write("\r\033[2K" + text)
        sys.stderr.flush()

    def _progress_clear(self, opts: Optional[GlobalOptions] = None) -> None:
        if opts and opts.json:
            return
        if os.environ.get("NETOPS_PROGRESS", "1") != "0" and sys.stderr.isatty():
            sys.stderr.write("\r\033[2K")
            sys.stderr.flush()

    def run_subprocess(self, cmd: List[str], opts: GlobalOptions, input_text: Optional[str]=None) -> int:
        if opts.dry_run: self.emit({"dry_run":True,"command":shlex.join(cmd)}, opts, shlex.join(cmd)); return SUCCESS
        proc = None; started = time.monotonic(); progress = self._progress_enabled(opts)
        if Path(cmd[0]).name in {"netops-probe", "netops-connect", "gateprober"}:
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
            # The terminal sends SIGINT to both NetOps and its foreground helper.
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
            return self._actions_for(noun).get(action, {}).get("usage", HELP_TOPICS.get(noun, {}).get("usage", "netops <domain> <action> [arguments]"))
        if noun:
            return HELP_TOPICS.get(noun, {}).get("usage", f"netops {noun} <action> [arguments]")
        return "netops <domain> <action> [arguments] [global flags]"

    def _examples_for(self, noun: str = "", action: str = "") -> List[str]:
        if noun and action:
            return list(self._actions_for(noun).get(action, {}).get("examples", []))[:4]
        if noun:
            out: List[str] = []
            for doc in self._actions_for(noun).values():
                out.extend(doc.get("examples", [])[:1])
            return out[:4]
        return ["netops inventory list ZONE10", "netops health offline", "netops memory switch ZONE10", "netops help diagnose interface"]

    def _legacy_suggestion(self, noun: str, args: Sequence[str]) -> str:
        if noun in {"discover", "discovery"}:
            if "--details" in args or "details" in args:
                key = "--details" if "--details" in args else "details"
                idx = list(args).index(key)
                target = args[idx + 1] if idx + 1 < len(args) else "<target>"
                return f"netops inventory details {target}"
            if "--aps" in args or "aps" in args:
                return "netops ap scan"
            if "--topology" in args or "topology" in args:
                key = "--topology" if "--topology" in args else "topology"
                idx = list(args).index(key)
                target = args[idx + 1] if idx + 1 < len(args) else "<target>"
                return f"netops topology show {target}"
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
                return f"netops {alias}"
            return f"netops {noun} {alias}"
        close = self._suggest(verb, self._actions_for(noun).keys())
        return f"netops {noun} {close}" if close else f"netops help {noun}"

    def usage_error(self, noun: str, action: str, opts: GlobalOptions, message: str, suggestion: str = "", code: int = USAGE) -> int:
        usage = self._usage_line(noun, action)
        examples = self._examples_for(noun, action)
        payload = {"ok": False, "error": message, "usage": usage, "suggestion": suggestion, "examples": examples, "exit_code": code}
        if opts.json:
            print(json_dumps(payload))
        else:
            eprint(f"Error: {message}")
            if suggestion:
                eprint(f"Try: {suggestion}")
            eprint(f"Usage: {usage}")
            if examples:
                eprint("Examples:")
                for ex in examples[:3]:
                    eprint(f"  {ex}")
            if noun:
                eprint(f"Help: netops help {noun}" + (f" {action}" if action else ""))
            else:
                eprint("Help: netops help")
        return code

    def unknown_action(self, noun: str, verb: str, opts: GlobalOptions) -> int:
        return self.usage_error(noun, "", opts, f"Unknown {noun} action: {verb}", self._verb_suggestion(noun, verb))

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
                print(f"`netops {noun}` is legacy. Use: {LEGACY_NOUN_HINTS[noun]}")
            return
        if noun and noun not in HELP_TOPICS:
            suggestion = self._suggest(noun, HELP_TOPICS.keys())
            payload = {"ok": False, "error": f"Unknown help topic: {noun}", "suggestion": f"netops help {suggestion}" if suggestion else "netops help"}
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
        if not noun:
            print(f"NetOps Platform v{VERSION}")
            print("")
            print("Usage:")
            print("  netops <domain> <action> [arguments] [global flags]")
            print("  netops help <domain> [action]")
            print("  netops <domain> <action> --help")
            print("")
            print("Domains:")
            for key, topic in HELP_TOPICS.items():
                actions = ", ".join(topic.get("actions", {}).keys())
                print(f"  {key:<11} {topic['summary']}")
                print(f"              actions: {actions}")
            print("")
            print("Common examples:")
            for ex in self._examples_for():
                print(f"  {ex}")
            print("")
            print("Global flags:")
            for flag, desc in GLOBAL_FLAG_HELP:
                print(f"  {flag:<16} {desc}")
            print("")
            print("Exit codes: " + ", ".join(f"{code} {name}" for code, name in EXIT_CODE_HELP))
            return
        topic = HELP_TOPICS[noun]
        actions = topic.get("actions", {})
        if action:
            if action not in actions:
                suggestion = self._verb_suggestion(noun, action)
                print(f"Unknown {noun} action: {action}")
                print(f"Try: {suggestion}")
                print(f"Help: netops help {noun}")
                return
            doc = actions[action]
            print(f"netops {noun} {action}")
            print("")
            print("Usage:")
            print(f"  {doc.get('usage', self._usage_line(noun, action))}")
            print("")
            print("Purpose:")
            for line in self._wrap(doc.get("about", "")):
                print(line)
            if doc.get("args"):
                print("")
                print("Arguments:")
                for arg in doc["args"]:
                    print(f"  {arg['name']:<16} {arg['text']}")
            if doc.get("options"):
                print("")
                print("Options:")
                for opt in doc["options"]:
                    print(f"  {opt['name']:<16} {opt['text']}")
            if doc.get("examples"):
                print("")
                print("Examples:")
                for ex in doc["examples"]:
                    print(f"  {ex}")
            print("")
            print("Global help: netops help")
            return
        print(f"netops {noun}")
        print("")
        print(topic["summary"])
        print("")
        print("Usage:")
        print(f"  {topic.get('usage', self._usage_line(noun))}")
        print("")
        print("Actions:")
        for name, doc in actions.items():
            print(f"  {name:<15} {doc.get('about', '')}")
        print("")
        print("Examples:")
        for ex in self._examples_for(noun):
            print(f"  {ex}")
        print("")
        print(f"Action help: netops help {noun} <action>")

    def dispatch(self, argv: List[str]) -> int:
        opts,args=parse_global(argv)
        if not args:
            self.cmd_help(opts=opts); return SUCCESS
        if args[0] in {"--version", "version"}:
            if opts.json:
                print(json_dumps({"name": "NetOps", "version": VERSION, "schema_version": SCHEMA_VERSION}))
            else:
                print(f"NetOps {VERSION}")
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
            table={"init":self.cmd_init,"profile":self.cmd_profile,"config":self.cmd_config,"secrets":self.cmd_secrets,"ingest":self.cmd_ingest,"plugin":self.cmd_plugin,"path":self.cmd_path,"support":self.cmd_support,"inventory":self.cmd_inventory,"ap":self.cmd_ap,"topology":self.cmd_topology,"memory":self.cmd_memory,"health":self.cmd_health,"backup":self.cmd_backup,"device":self.cmd_device,"vault":self.cmd_vault,"vlan":self.cmd_vlan,"lookup":self.cmd_lookup,"diagnose":self.cmd_diagnose,"workflow":self.cmd_workflow,"jobs":self.cmd_jobs,"commands":self.cmd_commands,"serve":self.cmd_serve,"ask":self.cmd_ask,"db":self.cmd_db}
            if noun not in table:
                legacy = self._legacy_suggestion(noun, args)
                if legacy:
                    return self.usage_error("", "", opts, f"`netops {noun}` is legacy or not a current domain.", legacy)
                close = self._suggest(noun, table.keys())
                suggestion = f"netops {close}" if close else "netops help"
                return self.usage_error("", "", opts, f"Unknown NetOps domain: {noun}", suggestion)
            return table[noun](args, opts)
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
        next_commands = ["netops config show"]
        if not valid_ssh_username(self.config.public.get("ssh_user") or self.config.secret.get("ssh_user")):
            next_commands.append("netops config set ssh_user <username>")
        next_commands.extend(["netops ingest channels", "netops diagnose doctor"])
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
            f"NetOps profile initialized: {profile}\n"
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
            if not rest: return self.usage_error("profile", "create", opts, "Missing profile name.", "netops profile create lab", VALIDATION)
            layout = self.profile_store.ensure(rest[0])
            payload = {"ok": True, "created": layout.name, "layout": layout.to_dict()}
            self.emit(payload, opts, f"Profile ready: {layout.name}\nConfig: {layout.config_dir}")
            return SUCCESS
        if verb == "use":
            if not rest: return self.usage_error("profile", "use", opts, "Missing profile name.", "netops profile use default", VALIDATION)
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
            raise ValueError("secret values must be stored with 'netops secrets set'")
        if value is not None and any(character in value for character in "\r\n\x00"):
            raise ValueError("configuration values cannot contain control lines")
        current = read_kv(self.paths.config_file)
        if value is None:
            current.pop(key, None)
        else:
            current[key] = value
        lines = ["# NetOps profile compatibility configuration"] + [f"{name}={current[name]}" for name in sorted(current)]
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
            if not rest: return self.usage_error("config", "get", opts, "Missing key.", "netops config get core_switch_ip", VALIDATION)
            key = rest[0]
            if key not in self.config.public: return self.usage_error("config", "get", opts, f"Unknown configuration key: {key}", "netops config show", VALIDATION)
            self.emit({"ok": True, "key": key, "value": self.config.public_safe().get(key)}, opts, str(self.config.public_safe().get(key, "")))
            return SUCCESS
        if verb == "set":
            if len(rest) < 2: return self.usage_error("config", "set", opts, "Provide a key and value.", "netops config set core_switch_ip 192.0.2.10", VALIDATION)
            self._write_profile_config_value(rest[0], " ".join(rest[1:]))
            self.emit({"ok": True, "profile": self.paths.profile, "key": rest[0], "updated": True}, opts, f"Updated {rest[0]} in profile {self.paths.profile}.")
            return SUCCESS
        if verb == "unset":
            if not rest: return self.usage_error("config", "unset", opts, "Missing key.", "netops config unset target_abbreviation_prefix", VALIDATION)
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
                findings.append({"severity": "warning", "key": "ssh_user", "detail": "required for device SSH; set with 'netops config set ssh_user <username>'"})
            elif not valid_ssh_username(ssh_user):
                findings.append({"severity": "error", "key": "ssh_user", "detail": "must be 1-255 characters without whitespace"})
            payload = {"ok": not any(row["severity"] == "error" for row in findings), "profile": self.paths.profile, "findings": findings}
            self.emit(payload, opts, self.render_table(findings, ["severity", "key", "detail"]) if findings else "Configuration is valid.")
            return SUCCESS if payload["ok"] else VALIDATION
        return self.unknown_action("config", verb, opts)

    def cmd_secrets(self, args: List[str], opts: GlobalOptions) -> int:
        if self.handle_help("secrets", args, opts): return SUCCESS
        verb = args[0] if args else "list"
        rest = args[1:]
        helper = self.paths.tool("netops-connect")
        mapping = {
            "list": [helper, "--secret-list"],
            "status": [helper, "--secret-status"],
            "import-ssh": [helper, "--secret-import-ssh"],
        }
        if verb == "set":
            if not rest: return self.usage_error("secrets", "set", opts, "Missing secret name.", "netops secrets set snmp/site-a/auth", VALIDATION)
            mapping[verb] = [helper, "--secret-set", rest[0]]
        elif verb in {"delete", "remove"}:
            if not rest: return self.usage_error("secrets", "delete", opts, "Missing secret name.", "netops secrets delete snmp/site-a/auth", VALIDATION)
            if not opts.confirm:
                return self.usage_error("secrets", "delete", opts, "Deleting a secret requires --confirm.", f"netops secrets delete {rest[0]} --confirm", CONFIRM_REQUIRED)
            mapping[verb] = [helper, "--secret-delete", rest[0]]
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
            if not rest: return self.usage_error("ingest", "run", opts, "Missing channel name.", "netops ingest run inventory-csv", VALIDATION)
            try:
                result = self.ingest_manager.run(rest[0], stdin=sys.stdin if not sys.stdin.isatty() else None)
            except ValueError as exc:
                return self.usage_error("ingest", "run", opts, str(exc), "netops ingest validate", VALIDATION)
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
            self.emit({"ok": True, "rows": rows, "chronology": CHRONOLOGY}, opts, self.render_table(rows, ["observed_at", "entity_kind", "stable_source_id", "channel", "completeness", "status", "confidence"]))
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
            if not rest: return self.usage_error("plugin", verb, opts, "Missing plugin id (<group>:<name>).", "netops plugin list", VALIDATION)
            try:
                if opts.dry_run:
                    descriptor = self.plugin_manager.descriptor(rest[0])
                    payload = {"ok": True, "dry_run": True, "plugin": descriptor.to_dict(), "would_enable": verb == "enable"}
                    self.emit(payload, opts, f"Dry run: plugin {rest[0]} would be {'enabled' if verb == 'enable' else 'disabled'}.")
                    return SUCCESS
                descriptor = self.plugin_manager.set_enabled(rest[0], verb == "enable")
            except ValueError as exc:
                return self.usage_error("plugin", verb, opts, str(exc), "netops plugin list", VALIDATION)
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

    def cmd_path(self, args: List[str], opts: GlobalOptions) -> int:
        if self.handle_help("path", args, opts): return SUCCESS
        verb = args[0] if args else "history"
        rest = args[1:]
        if verb == "history":
            endpoint = rest[0] if rest and not rest[0].startswith("-") else ""
            rows = timestamp_rows(self.path_inspector.history(endpoint, opts.limit))
            self.emit({"ok": True, "rows": rows, "chronology": CHRONOLOGY, "time_format": TIME_FORMAT}, opts, self.render_table(rows, ["started_at", "status", "endpoint", "vlan", "source", "destination", "mode", "confidence", "run_id"]))
            return SUCCESS
        if verb == "show":
            if not rest: return self.usage_error("path", "show", opts, "Missing path run id.", "netops path history", VALIDATION)
            payload = self.path_inspector.show(rest[0])
            if payload is None: return self.usage_error("path", "show", opts, f"Path run not found: {rest[0]}", "netops path history", VALIDATION)
            hops = payload.get("hops") or []; findings = payload.get("findings") or []
            text = f"{payload.get('status')}: {payload.get('summary')}\n" + self.render_table(hops, ["sequence", "device_name", "management_ip", "ingress_interface", "egress_interface", "layer", "vlan_state", "forwarding_state", "confidence"]) + "\n\nFindings\n" + (self.render_table(findings, ["severity", "code", "device_id", "interface", "message"]) if findings else "No findings.")
            self.emit({"ok": True, **payload}, opts, text)
            return SUCCESS
        if verb != "inspect": return self.unknown_action("path", verb, opts)
        endpoint = ""; vlan = 0; source = ""; destination = ""; mode = "hybrid"; explain = False; refresh = False
        index = 0
        while index < len(rest):
            value = rest[index]
            if value == "--vlan" and index + 1 < len(rest): vlan = int(rest[index + 1]); index += 2
            elif value == "--from" and index + 1 < len(rest): source = rest[index + 1]; index += 2
            elif value == "--to" and index + 1 < len(rest): destination = rest[index + 1]; index += 2
            elif value == "--cached": mode = "cached"; index += 1
            elif value == "--refresh": mode = "hybrid"; refresh = True; index += 1
            elif value == "--hybrid": mode = "hybrid"; index += 1
            elif value == "--live": mode = "live"; index += 1
            elif value == "--explain": explain = True; index += 1
            elif value.startswith("-"): return self.usage_error("path", "inspect", opts, f"Unknown path option: {value}", "netops help path inspect", VALIDATION)
            elif not endpoint: endpoint = value; index += 1
            elif not vlan and value.isdigit(): vlan = int(value); index += 1
            else: return self.usage_error("path", "inspect", opts, f"Unexpected argument: {value}", "netops help path inspect", VALIDATION)
        if not endpoint or not vlan:
            return self.usage_error("path", "inspect", opts, "Endpoint and --vlan are required.", "netops path inspect 02:00:00:00:00:25 --vlan 120", VALIDATION)
        if opts.dry_run: mode = "cached"
        if refresh and mode != "cached": opts.refresh_neighbors = True
        try:
            request = PathRequestV1(endpoint, vlan, source, destination, opts.depth or 8, opts.max_nodes, mode, explain, now())
        except ValueError as exc:
            return self.usage_error("path", "inspect", opts, str(exc), "netops help path inspect", VALIDATION)
        result = self.path_inspector.inspect(request, opts)
        payload = result.to_dict()
        hops = payload["hops"]; findings = payload["findings"]
        text = (
            f"{result.status}: {result.summary}\n"
            f"Confidence: {result.confidence}% | VLAN: {vlan} | Mode: {mode} | Recorded: {fmt_time(result.finished_at)} | Run: {result.run_id}\n\n"
            "Hop path\n" + self.render_table(hops, ["sequence", "device_name", "management_ip", "ingress_interface", "egress_interface", "layer", "vlan_state", "forwarding_state", "confidence"])
            + "\n\nFindings\n" + (self.render_table(findings, ["severity", "code", "device_id", "interface", "message"]) if findings else "No blockers or evidence warnings found.")
        )
        if explain:
            text += "\n\nEvidence\nCached topology plans the path; hybrid mode then validates VLAN and forwarding evidence on each bounded hop. Unsupported policy semantics remain unknown."
        self.emit({"ok": result.status in {"COMPLETE", "PARTIAL"}, **payload}, opts, text)
        return SUCCESS if result.status == "COMPLETE" else (UNREACHABLE if result.status == "BLOCKED" else PARTIAL)

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
            text="\n".join([f"SQLite: {payload['db_path']}", f"Schema: {payload['schema_version']} (expected {payload['expected_schema_version']})", f"Cache: {payload['cache_dir']}"]+[f"{k}: {v}" for k,v in payload["counts"].items()]+[f"sqlite_bytes: {payload['files']['sqlite_bytes']}", f"wal_bytes: {payload['files']['wal_bytes']}"])
            self.emit(payload,opts,text); return SUCCESS
        if verb=="integrity":
            payload=self.state.integrity_check(); self.emit(payload,opts,"SQLite integrity: "+("ok" if payload.get("ok") else "failed: "+", ".join(payload.get("integrity_check") or []))); return SUCCESS if payload.get("ok") else INTERNAL
        if verb=="repair":
            payload=self.state.repair(); self.emit(payload,opts,"SQLite repair complete: "+("ok" if payload.get("ok") else "integrity check failed")); return SUCCESS if payload.get("ok") else INTERNAL
        if verb=="vacuum":
            payload=self.state.vacuum(); self.emit(payload,opts,f"SQLite vacuum complete: {payload.get('bytes', 0)} bytes"); return SUCCESS
        return self.unknown_action("db", verb, opts)

    def resolve_raw_device_record(self, target: str) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]]]:
        raw = self.natural_ask.apply_aliases(str(target or "").strip())
        normalized = normalize_target_literal(raw)
        if not normalized:
            return None, []
        rows = self.state.rows(
            "SELECT ip,hostname,hostname AS name,platform,model,serial,mac,source,last_seen,status FROM devices ORDER BY hostname,ip"
        )
        exact = [
            row for row in rows
            if str(row.get("ip") or "").lower() == normalized.lower()
            or str(row.get("hostname") or "").lower() == raw.lower()
            or str(row.get("hostname") or "").split(".", 1)[0].lower() == raw.lower()
        ]
        if len(exact) == 1:
            return exact[0], exact
        if len(exact) > 1:
            return None, exact[:20]
        needle = re.sub(r"[^a-z0-9.]", "", raw.lower())
        candidates = [
            row for row in rows
            if needle and needle in re.sub(r"[^a-z0-9.]", "", f"{row.get('hostname') or ''} {row.get('ip') or ''}".lower())
        ]
        return (candidates[0], candidates) if len(candidates) == 1 else (None, candidates[:20])

    @staticmethod
    def _manual_merge_arguments(args: Sequence[str], *, expected: int) -> Tuple[List[str], str, str]:
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

    def cmd_inventory_merge(self, args: List[str], opts: GlobalOptions) -> int:
        positional, reason, error = self._manual_merge_arguments(args, expected=2)
        usage = "netops inventory merge <old-device> <current-device> --reason 'hardware replacement' --dry-run"
        if error:
            return self.usage_error("inventory", "merge", opts, error, usage, VALIDATION)
        if not reason:
            return self.usage_error("inventory", "merge", opts, "A merge reason is required for chronology and audit.", usage, VALIDATION)
        source, source_choices = self.resolve_raw_device_record(positional[0])
        target, target_choices = self.resolve_raw_device_record(positional[1])
        if not source or not target:
            choices = source_choices if not source else target_choices
            labels = ", ".join(str(row.get("hostname") or row.get("ip")) for row in choices[:8])
            detail = f"Device must resolve unambiguously." + (f" Candidates: {labels}" if labels else "")
            return self.usage_error("inventory", "merge", opts, detail, "netops inventory list <target>", VALIDATION)
        assessment = identity_match_evidence(source, target, "switch")
        preview = {
            "ok": True,
            "operation": "manual-device-merge",
            "source": self.state._device_snapshot(source),
            "target": self.state._device_snapshot(target),
            "assessment": assessment,
            "reason": reason,
            "effects": [
                "source removed from active inventory",
                "source identities and observations retained in chronological memory",
                "source hostname and address resolve to the current target",
                "future matching source observations are suppressed until merge revocation",
            ],
            "requires_confirmation": True,
        }
        text = (
            f"Manual device merge preview\n"
            f"Historical source: {source.get('hostname') or source.get('ip')} ({source.get('ip')})\n"
            f"Current target: {target.get('hostname') or target.get('ip')} ({target.get('ip')})\n"
            f"Automatic assessment: {'same device' if assessment['same_device'] else 'manual override'} | Confidence: {assessment['confidence']}%\n"
            f"Conflicts retained as evidence: {', '.join(assessment['conflicts']) or 'none'}\n"
            f"Reason: {reason}"
        )
        if opts.dry_run:
            self.emit(preview, opts, text)
            return SUCCESS
        if not opts.confirm:
            return self.usage_error("inventory", "merge", opts, "Manual merge requires --dry-run for review or --confirm to apply.", usage, CONFIRM_REQUIRED)
        actor = os.environ.get("SUDO_USER") or os.environ.get("USER") or str(os.getuid())
        try:
            merge = self.state.create_device_merge(source, target, reason, actor)
            reconciliation = self.state.sync_derived_state()
            compatibility = self.state.export_flat_files()
        except ValueError as exc:
            return self.usage_error("inventory", "merge", opts, str(exc), usage, VALIDATION)
        self.state.record_audit_event(
            "inventory_device_merged", "inventory-merge", actor=actor, actor_uid=os.getuid(),
            target=f"{merge['source_key']}->{merge['target_key']}", result="success", reason=reason,
            detail={"merge_id": merge["merge_id"], "source_ip": merge["source_ip"], "target_ip": merge["target_ip"]},
        )
        payload = {**preview, "merge": timestamp_row(merge), "reconciliation": reconciliation, "compatibility_export": compatibility, "applied": True}
        self.emit(payload, opts, text + f"\nMerge: {merge['merge_id']} | Recorded: {fmt_time(merge['created_at'])}")
        return SUCCESS

    def cmd_inventory_unmerge(self, args: List[str], opts: GlobalOptions) -> int:
        positional, reason, error = self._manual_merge_arguments(args, expected=1)
        usage = "netops inventory unmerge <merge-id> --reason 'incorrect association' --confirm"
        if error:
            return self.usage_error("inventory", "unmerge", opts, error, usage, VALIDATION)
        if not reason:
            return self.usage_error("inventory", "unmerge", opts, "A revocation reason is required.", usage, VALIDATION)
        if not opts.confirm:
            return self.usage_error("inventory", "unmerge", opts, "Restoring a retired device requires --confirm.", usage, CONFIRM_REQUIRED)
        actor = os.environ.get("SUDO_USER") or os.environ.get("USER") or str(os.getuid())
        try:
            merge = self.state.revoke_device_merge(positional[0], reason, actor)
            reconciliation = self.state.sync_derived_state()
            compatibility = self.state.export_flat_files()
        except ValueError as exc:
            return self.usage_error("inventory", "unmerge", opts, str(exc), usage, VALIDATION)
        self.state.record_audit_event(
            "inventory_device_merge_revoked", "inventory-unmerge", actor=actor, actor_uid=os.getuid(),
            target=str(merge.get("merge_id") or positional[0]), result="success", reason=reason,
            detail={"source_ip": merge.get("source_ip"), "target_ip": merge.get("target_ip")},
        )
        payload = {"ok": True, "merge": timestamp_row(merge), "reconciliation": reconciliation, "compatibility_export": compatibility}
        self.emit(payload, opts, f"Manual merge revoked: {merge['merge_id']}\nHistorical device restored: {merge.get('source_name') or merge.get('source_ip')}\nRecorded: {fmt_time(merge['revoked_at'])}")
        return SUCCESS

    def inventory_rows(self,pattern:str,opts:GlobalOptions)->List[Dict[str,Any]]:
        pattern = pattern_or_all(pattern)
        with self.state.connect() as con:
            device_observations = [dict(r) for r in con.execute(
                "SELECT ip,hostname,hostname AS name,platform,model,serial,mac,NULL AS switch_ip,NULL AS switch_name,NULL AS switch_port,source,last_seen,status FROM devices"
            )]
            canonical_devices = reconcile_device_rows(device_observations)
            self.state._overlay_manual_device_merges(con, canonical_devices)
        rows = []
        needle = pattern.lower()
        for item in canonical_devices:
            if opts.status and norm_status(item.get("status")) != opts.status:
                continue
            if needle and needle not in json.dumps(item, default=str).lower():
                continue
            item["kind"] = "device"
            rows.append(item)
        ap_opts = GlobalOptions(limit=100000, status=opts.status, site=opts.site)
        for ap in self.reconciled_ap_rows(pattern, ap_opts):
            row = dict(ap)
            row.update({
                "kind": "ap",
                "model": row.get("model") or "",
                "serial": row.get("serial") or "",
                "source": row.get("source") or "AP",
            })
            rows.append(row)
        if opts.site:
            rows=[r for r in rows if opts.site.lower() in json.dumps(r, default=str).lower()]
        rows.sort(key=lambda row: (0 if norm_status(row.get("status")) == "OFFLINE" else 1, str(row.get("kind") or ""), str(row.get("name") or row.get("ip") or "").lower()))
        return rows[:opts.limit]

    def cmd_inventory(self,args:List[str],opts:GlobalOptions)->int:
        if self.handle_help("inventory", args, opts): return SUCCESS
        verb=args[0] if args else "list"; rest=args[1:]
        if verb in {"import-flat","import"}:
            refresh = self.import_flat_state(("device", "ap", "topology"), "flat-import")
            c = refresh["imported"]
            self.emit({"ok":True, **refresh, "db":str(self.paths.sqlite_db)},opts,f"Imported flat caches: devices={c['devices']} aps={c['aps']} neighbors={c['neighbors']}; observation runs={len(refresh['ingest_runs'])}")
            return SUCCESS
        if verb in {"export-flat","export"}: c=self.state.export_flat_files(); self.emit({"ok":True,"exported":c},opts,f"Exported flat caches: devices={c['devices']} aps={c['aps']} neighbors={c['neighbors']}"); return SUCCESS
        if verb=="scan":
            rc=self.run_subprocess(self.legacy_cmd("netops-discovery","--update",*(rest[:1])),opts)
            if rc==0 and not opts.dry_run:
                try: self.import_flat_state(("device",), "ssh-scan")
                except Exception as exc: eprint(f"Observation recording failed: {exc}"); return PARTIAL
            return rc
        if verb=="activity": return self.inventory_activity(rest,opts)
        if verb=="merge": return self.cmd_inventory_merge(rest,opts)
        if verb in {"unmerge","merge-revoke"}: return self.cmd_inventory_unmerge(rest,opts)
        if verb in {"merges","merge-history"}:
            rows=timestamp_rows(self.state.list_device_merges(include_revoked=opts.all)); self.emit({"ok":True,"rows":rows,"count":len(rows),"chronology":CHRONOLOGY},opts,self.render_table(rows,["created_at","merge_id","source_name","source_ip","target_name","target_ip","reason","suppressed_observations","revoked_at"])); return SUCCESS
        if verb in {"list","show","details"}:
            pattern=pattern_or_all(" ".join(rest).strip())
            if verb=="details" and pattern and not opts.json:
                resolved, choices = self.resolve_device_record(pattern)
                detail_target = str(resolved.get("ip") or pattern) if resolved and len(choices) == 1 else pattern
                return self.run_subprocess(self.legacy_cmd("netops-discovery","--details",detail_target),opts)
            rows=self.inventory_rows(pattern,opts); self.emit({"ok":True,"rows":rows,"count":len(rows)},opts,self.render_table(rows,["kind","ip","name","platform","status","last_seen"])); return SUCCESS
        return self.unknown_action("inventory", verb, opts)
    def resolve_one(self,target:str)->str:
        target = normalize_target_literal(target)
        if IP_RE.fullmatch(target.strip()): return target.strip()
        device, choices = self.resolve_device_record(target)
        if device and len(choices) == 1:
            return str(device.get("ip") or "")
        row=self.state.one("SELECT ip FROM aps WHERE lower(name)=lower(?) OR lower(name) LIKE lower(?) ORDER BY name LIMIT 1",(target,f"%{target}%"))
        if row: return row["ip"]
        with contextlib.suppress(Exception): return socket.gethostbyname(target)
        return ""
    def ping(self,target:str,timeout:int)->bool:
        target = normalize_target_literal(target)
        return subprocess.run(["ping","-c","1","-W",str(max(1,min(timeout,10))),target],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0
    def inventory_activity(self,args:List[str],opts:GlobalOptions)->int:
        file_path=""; targets=[]; i=0
        while i<len(args):
            if args[i]=="--file" and i+1<len(args): file_path=args[i+1]; i+=2
            else: targets.append(args[i]); i+=1
        if file_path:
            p=Path(file_path).expanduser()
            if not p.exists(): return self.usage_error("inventory","activity",opts,f"List file not found: {p}","netops inventory activity --file devices.txt",VALIDATION)
            targets.extend([l.strip() for l in p.read_text(encoding="utf-8",errors="ignore").splitlines() if l.strip() and not l.strip().startswith("#")])
        if not targets: return self.usage_error("inventory","activity",opts,"Missing target list. Provide --file or one or more targets.","netops inventory activity --file devices.txt")
        inventory = self.inventory_rows("", GlobalOptions(limit=100000))

        def record_for(target: str) -> Dict[str, Any]:
            normalized = normalize_target_literal(target)
            exact = next(
                (
                    row for row in inventory
                    if normalized.lower() in {
                        str(value or "").lower()
                        for value in (
                            row.get("ip"), row.get("name") or row.get("hostname"),
                            *(row.get("aliases") or []), *(row.get("historical_addresses") or []),
                        )
                    }
                    or str(row.get("name") or row.get("hostname") or "").split(".", 1)[0].lower() == target.lower()
                ),
                None,
            )
            row = exact or {}
            ip = str(row.get("ip") or normalized or target)
            if not is_ipv4_literal(ip):
                with contextlib.suppress(OSError):
                    ip = socket.gethostbyname(ip)
            status = "ONLINE" if self.ping(ip, opts.timeout) else "OFFLINE"
            return {"target":target,"ip":ip,"kind":row.get("kind","unknown"),"name":row.get("name") or row.get("hostname") or "","platform":row.get("platform",""),"status":status,"checked_at":now()}

        workers = min(len(targets), bounded_int(opts.workers, 20, 1, 64))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers, thread_name_prefix="netops-activity") as executor:
            results = list(executor.map(record_for, targets))
        results.sort(key=lambda r:(0 if r["status"]=="OFFLINE" else 1,r.get("name") or r.get("ip")))
        self.emit({"ok":True,"rows":results,"count":len(results)},opts,self.render_table(results,["status","target","ip","kind","name","platform","checked_at"])); return SUCCESS if all(r["status"]=="ONLINE" for r in results) else PARTIAL
    def ap_rows(self,pattern:str,opts:GlobalOptions)->List[Dict[str,Any]]:
        return self.reconciled_ap_rows(pattern_or_all(pattern), opts)

    def cmd_ap(self,args:List[str],opts:GlobalOptions)->int:
        if self.handle_help("ap", args, opts): return SUCCESS
        verb=args[0] if args else "list"; rest=args[1:]
        if verb=="scan":
            rc=self.run_subprocess(self.legacy_cmd("netops-discovery","--discover-aps"),opts)
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
            if not rest: return self.usage_error("ap","on-switch",opts,"Missing switch target.","netops ap on-switch ZONE10")
            return self.memory_switch(" ".join(rest),opts,aps_only=True)
        if verb=="moves": rows=self.state.rows("SELECT * FROM ap_move_events ORDER BY created_at DESC,id DESC LIMIT ?",(opts.limit,)); self.emit({"ok":True,"rows":rows},opts,self.render_table(rows,["created_at","ap_ip","ap_name","previous_switch_ip","previous_switch_port","current_switch_ip","current_switch_port"])); return SUCCESS
        if verb=="timeline": return self.relationship_timeline(rest[0] if rest else "ap_attachment",opts,rel_type="ap_attachment")
        return self.unknown_action("ap", verb, opts)
    def cmd_topology(self,args:List[str],opts:GlobalOptions)->int:
        if self.handle_help("topology", args, opts): return SUCCESS
        verb=args[0] if args else "show"; rest=args[1:]
        if verb=="scan":
            rc=self.run_subprocess(self.legacy_cmd("netops-discovery","--discover-neighbors"),opts)
            if rc==0 and not opts.dry_run:
                try: self.import_flat_state(("topology",), "lldp-cdp-scan")
                except Exception as exc: eprint(f"Observation recording failed: {exc}"); return PARTIAL
            return rc
        if verb in {"show","neighbors"}:
            if rest and not is_all_keyword(rest[0]) and not opts.json: return self.run_subprocess(self.legacy_cmd("netops-discovery","--topology",rest[0]),opts)
            rows=self.state.rows("SELECT * FROM neighbors ORDER BY local_name,local_port LIMIT ?",(opts.limit,)); self.emit({"ok":True,"rows":rows},opts,self.render_table(rows,["local_ip","local_name","local_port","remote_name","remote_port","remote_ip"])); return SUCCESS
        if verb=="changes": rows=self.state.rows("SELECT * FROM topology_events ORDER BY created_at DESC,id DESC LIMIT ?",(opts.limit,)); self.emit({"ok":True,"rows":rows},opts,self.render_table(rows,["created_at","event_type","local_ip","local_port","remote_name","remote_port","detail"])); return SUCCESS
        if verb=="timeline": return self.relationship_timeline(rest[0] if rest else "neighbor_link",opts,rel_type="neighbor_link")
        return self.unknown_action("topology", verb, opts)
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
            if not rest: return self.usage_error("memory","switch",opts,"Missing switch target.","netops memory switch ZONE10")
            return self.memory_switch(" ".join(rest),opts)
        if verb=="device":
            if not rest: return self.usage_error("memory","device",opts,"Missing device name or IP.","netops memory device ZONE34")
            payload=self.memory_device_payload(rest[0],opts.limit); rows=payload["current"]; self.emit(payload,opts,self.render_table(rows,["rel_type","subject_kind","subject_id","object_kind","object_id","status","first_seen","last_seen"])); return SUCCESS
        if verb in {"ip","mac"}:
            if not rest: return self.usage_error("memory",verb,opts,f"Missing {verb} value.",f"netops memory {verb} <value>")
            return self.relationship_timeline(norm_mac(rest[0]) if verb=="mac" else rest[0],opts,subject_kind=verb)
        if verb=="port":
            if len(rest)<2: return self.usage_error("memory","port",opts,"Missing switch and/or port.","netops memory port ZONE34 Gi1/0/7")
            payload=self.memory_port_payload(rest[0],rest[1],opts.limit); rows=payload["current"]; events=payload["timeline"]; self.emit(payload,opts,"Current port occupancy (newest recorded first)\n"+self.render_table(rows,["subject_id","object_kind","object_id","source","confidence","status","first_seen","last_seen"])+"\n\nTimeline (newest first)\n"+self.render_table(events,["created_at","event_type","subject_id","object_id","source","detail"])); return SUCCESS
        if verb=="timeline": return self.relationship_timeline(rest[0] if rest else "",opts)
        if verb=="explain": target=rest[0] if rest else ""; payload=self.memory_explain_payload(target); self.emit(payload,opts,self.render_table(payload["rows"],["rel_type","source","count","avg_confidence","last_seen"])); return SUCCESS
        if verb=="export": rows=timestamp_rows(self.state.rows("SELECT * FROM relationships_current ORDER BY COALESCE(last_seen,updated_at,first_seen,0) DESC,rel_type,subject_id,object_id")); self.emit({"ok":True,"rows":rows,"chronology":CHRONOLOGY,"time_format":TIME_FORMAT},opts); return SUCCESS
        if verb=="prune": return self.usage_error("memory","prune",opts,"Relationship history is retained forever by default. Pruning is not enabled yet.","netops memory export --json",CONFIRM_REQUIRED)
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
            cmd=self.legacy_cmd("netops-discovery","--fast-health",target) if target else self.legacy_cmd("netops-discovery","--fast-health")
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

    def inventory_detail_payload(self, kind: str, target: str, limit: int = 80) -> Dict[str, Any]:
        kind = (kind or "device").lower()
        target = (target or "").strip()
        if kind == "ap":
            matches = self.reconciled_ap_rows(target, GlobalOptions(limit=20))
            row = matches[0] if matches else None
            entity_type = "ap"
            name = row.get("name") if row else target
        else:
            row = self.state.one("SELECT * FROM devices WHERE ip=? OR lower(hostname)=lower(?) OR lower(hostname) LIKE lower(?) LIMIT 1", (target, target, f"%{target.lower()}%"))
            entity_type = "device"
            name = row.get("hostname") if row else target
        ip = row.get("ip") if row else target
        terms = list(dict.fromkeys([target, ip, name, *((row or {}).get("aliases") or []), *((row or {}).get("addresses") or [])]))
        history: List[Dict[str, Any]] = []
        seen = set()
        for term in [value for value in terms if value]:
            like = f"%{term}%"
            for item in self.state.rows("SELECT * FROM inventory_history WHERE ip LIKE ? OR name LIKE ? OR identity_value LIKE ? OR previous_value LIKE ? OR current_value LIKE ? ORDER BY created_at DESC,id DESC LIMIT ?", (like, like, like, like, like, limit)):
                if item.get("id") not in seen:
                    seen.add(item.get("id"))
                    history.append(item)
        history.sort(key=lambda item: (int(item.get("created_at") or 0), int(item.get("id") or 0)), reverse=True)
        relationships = timestamp_rows(self.state.rows("SELECT * FROM relationships_current WHERE status!='disappeared' AND (subject_id LIKE ? OR object_id LIKE ? OR attrs_json LIKE ?) ORDER BY COALESCE(last_seen,updated_at,first_seen,0) DESC,rel_type,confidence DESC LIMIT ?", (f"%{target}%", f"%{target}%", f"%{target}%", limit)))
        health_id = (row or {}).get("canonical_id") or ip
        health = self.state.one("SELECT * FROM health_state WHERE entity_type=? AND (entity_id=? OR name LIKE ?) LIMIT 1", (entity_type, health_id, f"%{name or target}%"))
        backups = self.state.rows("SELECT * FROM backup_history WHERE device_ip=? OR hostname LIKE ? ORDER BY created_at DESC,id DESC LIMIT ?", (ip, f"%{name or target}%", limit)) if kind != "ap" else []
        return {"ok": bool(row), "kind": kind, "target": target, "record": timestamp_row(row) if row else None, "health": timestamp_row(health) if health else None, "history": self.version_rows(history[:limit]), "relationships": relationships, "backups": timestamp_rows(backups), "chronology": CHRONOLOGY, "time_format": TIME_FORMAT}

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

    def memory_query_payload(self, mode: str, target: str, port: str = "", limit: int = 100) -> Dict[str, Any]:
        mode = (mode or "switch").lower()
        target = (target or "").strip()
        if mode == "switch": return self.memory_switch_payload(target, GlobalOptions(limit=limit))
        if mode == "device": return self.memory_device_payload(target, limit)
        if mode == "ip": return self.relationship_timeline_payload(target, limit, subject_kind="ip")
        if mode == "mac": return self.relationship_timeline_payload(norm_mac(target), limit, subject_kind="mac")
        if mode == "port": return self.memory_port_payload(target, port, limit)
        if mode == "timeline": return self.relationship_timeline_payload(target, limit)
        if mode == "explain": return self.memory_explain_payload(target)
        return {"ok": False, "error": f"unsupported memory mode: {mode}"}

    def topology_graph_payload(self, limit: int = 500) -> Dict[str, Any]:
        edges = self.state.rows("SELECT * FROM neighbors ORDER BY local_name,local_port LIMIT ?", (limit,))
        nodes: Dict[str, Dict[str, Any]] = {}
        def add_node(node_id: str, label: str, kind: str) -> None:
            if not node_id or node_id == "?.?.?.?": return
            nodes.setdefault(node_id, {"id": node_id, "label": label or node_id, "kind": kind})
        for edge in edges:
            local = edge.get("local_ip") or edge.get("local_name")
            remote = edge.get("remote_ip") if edge.get("remote_ip") and edge.get("remote_ip") != "?.?.?.?" else edge.get("remote_name")
            add_node(local, edge.get("local_name") or local, "switch")
            add_node(remote, edge.get("remote_name") or remote, "neighbor")
        graph_edges = []
        for edge in edges:
            source = edge.get("local_ip") or edge.get("local_name")
            target = edge.get("remote_ip") if edge.get("remote_ip") and edge.get("remote_ip") != "?.?.?.?" else edge.get("remote_name")
            if source and target:
                graph_edges.append({"id": f"{source}|{edge.get('local_port')}|{target}|{edge.get('remote_port')}", "source": source, "target": target, "local_port": edge.get("local_port"), "remote_port": edge.get("remote_port"), "remote_ip": edge.get("remote_ip")})
        return {"ok": True, "nodes": list(nodes.values()), "edges": graph_edges, "raw_edges": edges}

    def automation_payload(self) -> Dict[str, Any]:
        schedules = [
            {"id": "health-every-30", "label": "Fast health", "action": "health-check", "cadence": "30 min", "enabled": False},
            {"id": "inventory-daily", "label": "Inventory refresh", "action": "workflow-refresh-inventory", "cadence": "daily", "enabled": False},
            {"id": "ap-audit-daily", "label": "AP audit", "action": "workflow-ap-audit", "cadence": "daily", "enabled": False},
            {"id": "backup-weekly", "label": "Online backup", "action": "workflow-backup-online", "cadence": "weekly", "enabled": False},
        ]
        retention = {"jobs_days": 30, "diagnostics_days": 30, "relationship_history": "forever", "logs_days": 14}
        rules = ["offline transition", "stale inventory", "topology change", "AP move", "backup failure", "diagnostic attention"]
        return {"ok": True, "enabled": False, "schedules": schedules, "retention": retention, "attention_rules": rules}

    def webui_status_payload(self) -> Dict[str, Any]:
        missing = []
        if not self.paths.sqlite_db.exists(): missing.append("sqlite")
        if not self.paths.devices_file.exists(): missing.append("devices flat cache")
        if not self.paths.aps_file.exists(): missing.append("AP flat cache")
        safe_config = self.config.public_safe()
        credential_status = {k:v for k,v in safe_config.items() if SECRET_KEY_RE.search(k)}
        return {"ok": not missing, "missing": missing, "paths": {"db": str(self.paths.sqlite_db), "cache_dir": str(self.paths.cache_dir), "config_file": str(self.paths.config_file), "ssh_known_hosts": str(self.paths.ssh_known_hosts_file)}, "credential_status": credential_status, "ssh_host_key_mode": self.config.public.get("ssh_host_key_mode") or "accept-new", "counts": self.state.counts()}

    def canonical_mac(self, value: Any, style: str = "dotted") -> str:
        clean = norm_mac(value)
        if len(clean) != 12:
            return ""
        if style == "plain":
            return clean
        if style == "colon":
            return ":".join(clean[index:index + 2] for index in range(0, 12, 2))
        return ".".join(clean[index:index + 4] for index in range(0, 12, 4))

    def live_log(self, area: str, message: str) -> None:
        """Emit concise progress on stderr so job SSE and final output stay distinct."""
        print(f"[{area.upper()}] {strip_ansi(str(message)).replace(chr(10), ' ')[:240]}", file=sys.stderr, flush=True)

    def resolve_device_record(self, target: str) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]]]:
        raw = self.natural_ask.apply_aliases(str(target or "").strip())
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
        exact: List[Dict[str, Any]] = []
        for row in rows:
            names = [row.get("hostname"), row.get("name"), *(row.get("aliases") or [])]
            addresses = [row.get("ip"), *(row.get("addresses") or []), *(row.get("historical_addresses") or [])]
            if any(str(value or "").lower() == normalized.lower() for value in addresses) or any(
                str(value or "").lower() == raw.lower()
                or str(value or "").split(".", 1)[0].lower() == raw.lower()
                for value in names
            ):
                exact.append(row)
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

    def _neighbor_device(self, neighbor: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        remote_ip = str(neighbor.get("remote_ip") or "").strip()
        remote_name = clean_display_name(neighbor.get("remote_name") or "")
        if IP_RE.fullmatch(remote_ip) and remote_ip != "?.?.?.?":
            inventory = self.state.one("SELECT ip,hostname,platform,model,status,last_seen FROM devices WHERE ip=?", (remote_ip,))
            if inventory:
                return inventory
            return {
                "ip": remote_ip,
                "hostname": remote_name or remote_ip,
                "platform": neighbor.get("platform") or "Unknown",
                "model": "",
                "status": "UNKNOWN",
                "last_seen": 0,
            }
        if remote_name:
            row, choices = self.resolve_device_record(remote_name)
            if row and len(choices) == 1:
                return row
        return None

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

    def live_switch_neighbors(self, device: Dict[str, Any], timeout: int = 90) -> List[Dict[str, Any]]:
        target = str(device.get("ip") or "")
        driver = self.driver_for(
            platform=device.get("platform"),
            model=device.get("model"),
            hostname=device.get("hostname"),
        )
        commands = list(driver.command_templates.get("neighbors") or ())
        if not commands:
            commands = ["show lldp neighbors detail", "show cdp neighbors detail"]
        output: List[Dict[str, Any]] = []
        for command in commands:
            rc, stdout, stderr = self.capture(self.legacy_cmd("netops-control", "show", target, command), timeout)
            if rc != 0:
                continue
            for parsed in parse_neighbor_detail_output((stdout or "") + (stderr or "")):
                row = {
                    "local_ip": target,
                    "local_name": device.get("hostname") or target,
                    "local_port": parsed.get("local_port"),
                    "remote_name": parsed.get("remote_name"),
                    "remote_port": parsed.get("remote_port"),
                    "remote_ip": parsed.get("remote_ip"),
                    "platform": parsed.get("platform"),
                    "capabilities": parsed.get("capabilities"),
                    "source": f"{parsed.get('protocol') or 'neighbor'}-live",
                    "driver_family": driver.family,
                }
                if self._switch_neighbor_evidence(row):
                    output.append(row)
        unique: Dict[Tuple[str, str], Dict[str, Any]] = {}
        for row in output:
            remote_identity = str(row.get("remote_ip") or "").strip() or compact_name(clean_display_name(row.get("remote_name") or "")).lower()
            key = (normalize_interface(row.get("local_port")), remote_identity)
            if key[0]:
                unique[key] = row
        return list(unique.values())

    def _neighbor_on_port(self, rows: List[Dict[str, Any]], port: str) -> Optional[Dict[str, Any]]:
        return next((row for row in rows if interface_matches(row.get("local_port"), port)), None)

    def inspect_vlan_node(self, device: Dict[str, Any], vlan: int, mode: str, opts: GlobalOptions) -> Dict[str, Any]:
        target = str(device.get("ip") or "")
        display_name = clean_display_name(device.get("hostname") or target)
        helper_mode = "propagated" if mode == "propagation" else "locate-vlan"
        command = self.legacy_cmd("netops-control", helper_mode, target, str(vlan))
        if mode == "propagation":
            command.append("--deep")
        rc, stdout, stderr = self.capture(command, opts.timeout or 180)
        raw = (stdout or "") + (stderr or "")
        parsed = parse_vlan_control_output(raw, mode)
        cached = self.cached_switch_neighbors(device)
        missing_cached = any(not self._neighbor_on_port(cached, trunk.get("port", "")) for trunk in parsed.get("trunks") or [])
        live: List[Dict[str, Any]] = []
        if opts.refresh_neighbors or not cached or missing_cached:
            self.live_log("vlan", f"{display_name}: refreshing switch neighbors with LLDP/CDP")
            live = self.live_switch_neighbors(device, min(opts.timeout or 90, 180))
        neighbors = cached + [row for row in live if not self._neighbor_on_port(cached, str(row.get("local_port") or ""))]

        trunks = [dict(row) for row in parsed.get("trunks") or []]
        for trunk in trunks:
            neighbor = self._neighbor_on_port(neighbors, str(trunk.get("port") or ""))
            if not neighbor and (trunk.get("neighbor_ip") or trunk.get("neighbor_name")):
                candidate = {
                    "local_ip": target,
                    "local_name": display_name,
                    "local_port": trunk.get("port") or "",
                    "remote_name": trunk.get("neighbor_name") or "",
                    "remote_port": "",
                    "remote_ip": trunk.get("neighbor_ip") or "",
                    "source": "propagation-report",
                }
                neighbor = candidate if self._switch_neighbor_evidence(candidate) else None
            if neighbor:
                trunk["neighbor"] = neighbor
                trunk["neighbor_name"] = neighbor.get("remote_name") or trunk.get("neighbor_name") or ""
                trunk["neighbor_ip"] = neighbor.get("remote_ip") or trunk.get("neighbor_ip") or ""
            trunk.setdefault("source", "vlan-inspection")

        # VLAN state comes only from the established helper report. Cached/live
        # switch links can extend traversal, but never become invented trunks.
        links = [dict(row) for row in trunks]
        for neighbor in neighbors:
            if not any(interface_matches(item.get("port"), neighbor.get("local_port")) for item in links):
                links.append({
                    "port": neighbor.get("local_port") or "",
                    "carries_vlan": None,
                    "neighbor": neighbor,
                    "neighbor_name": neighbor.get("remote_name") or "",
                    "neighbor_ip": neighbor.get("remote_ip") or "",
                    "source": "topology-switch-link",
                })

        error = str(parsed.get("error") or "")
        usable_report = parsed.get("defined") is not None
        if rc != 0 and not usable_report:
            error = error or f"inspection helper exited {rc} without a usable VLAN report"
        if parsed.get("defined") is None and not error:
            error = "VLAN state could not be parsed"
        missing = sum(1 for row in trunks if row.get("carries_vlan") is False)
        unknown = sum(1 for row in trunks if row.get("carries_vlan") is None)
        if error:
            state = "ERROR"
        elif parsed.get("defined") is False or missing:
            state = "MISSING"
        elif unknown:
            state = "PARTIAL"
        else:
            state = "OK"
        if error:
            result = "FAILED"
        elif parsed.get("defined") is False:
            result = "ABSENT"
        elif missing:
            result = "TRUNK GAP"
        else:
            result = "PRESENT"
        return {
            "ip": target,
            "name": display_name,
            "platform": device.get("platform") or "Unknown",
            "vlan": vlan,
            "defined": parsed.get("defined"),
            "vlan_status": "defined" if parsed.get("defined") is True else ("not defined" if parsed.get("defined") is False else "unknown"),
            "access_ports": parsed.get("access_ports") or [],
            "access_port_count": len(parsed.get("access_ports") or []),
            "trunks": trunks,
            "trunk_count": len(trunks),
            "trunks_carrying": sum(1 for row in trunks if row.get("carries_vlan") is True),
            "trunks_missing": missing,
            "trunks_unknown": unknown,
            "links": links,
            "neighbors": neighbors,
            "state": state,
            "result": result,
            "error": error,
            "helper_exit_code": rc,
            "helper_exit_ignored": bool(rc != 0 and usable_report and not error),
            "raw_excerpt": " ".join(clean_network_output(raw).split())[:600],
            "observed_at": now(),
        }

    def vlan_cascade(self, target: str, vlan: int, mode: str, opts: GlobalOptions, *, collect: bool = False) -> Any:
        root, choices = self.resolve_device_record(target)
        if not root:
            labels = ", ".join(str(row.get("hostname") or row.get("ip")) for row in choices[:8])
            message = f"Ambiguous switch target {target!r}: {labels}" if choices else f"Switch target not found: {target}"
            return self.usage_error("vlan", mode, opts, message, f"netops inventory list {shlex.quote(target)}", VALIDATION)

        depth_limit = max(0, min(int(opts.depth or 0), 10))
        node_limit = max(1, min(int(opts.max_nodes or 64), 256))
        root_name = clean_display_name(root.get("hostname") or root.get("ip"))
        if opts.dry_run:
            payload = {
                "ok": True,
                "dry_run": True,
                "mode": mode,
                "root": {"ip": root.get("ip"), "name": root_name},
                "vlan": vlan,
                "depth": depth_limit,
                "max_nodes": node_limit,
                "refresh_neighbors": opts.refresh_neighbors,
                "network_actions": ["SSH VLAN inspection", "cached topology correlation", "LLDP/CDP fallback", "bounded switch traversal"],
            }
            dry_text = f"Dry run: VLAN {vlan} {mode} cascade from {root_name} | depth={depth_limit} max_nodes={node_limit}"
            if collect:
                return SUCCESS, payload, dry_text
            self.emit(payload, opts, dry_text)
            return SUCCESS
        queue_rows: List[Tuple[Dict[str, Any], int, str]] = [(root, 0, "")]
        scheduled = {str(root.get("ip") or "").lower()}
        visited: set[str] = set()
        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []
        findings: List[Dict[str, Any]] = []
        inspection_errors = 0
        budget_hit = False
        index = 0
        while index < len(queue_rows) and len(nodes) < node_limit:
            device, layer, parent = queue_rows[index]
            index += 1
            ip = str(device.get("ip") or "")
            key = ip.lower() or str(device.get("hostname") or "").lower()
            if key in visited:
                continue
            visited.add(key)
            self.live_log("vlan", f"{layer}/{depth_limit} inspect {clean_display_name(device.get('hostname') or ip)} ({ip})")
            inspected = self.inspect_vlan_node(device, vlan, mode, opts)
            inspected["depth"] = layer
            inspected["parent"] = parent
            nodes.append({key: value for key, value in inspected.items() if key not in {"trunks", "links", "neighbors", "raw_excerpt"}})
            counters = f"trunks={inspected['trunk_count']} gaps={inspected['trunks_missing']} next-switches={len(inspected['neighbors'])}"
            if mode == "locate":
                counters = f"access={inspected['access_port_count']} {counters}"
            self.live_log("vlan", f"{layer}/{depth_limit} {inspected['name']}: VLAN {vlan} {inspected['vlan_status']}; {counters}")
            if inspected.get("error"):
                inspection_errors += 1
                findings.append({"severity": "error", "code": "INSPECTION_FAILED", "depth": layer, "device": inspected["name"], "ip": ip, "port": "", "detail": inspected["error"]})
            if inspected.get("defined") is False:
                findings.append({"severity": "critical", "code": "VLAN_NOT_DEFINED", "depth": layer, "device": inspected["name"], "ip": ip, "port": "", "detail": f"VLAN {vlan} is not defined on this switch"})

            for link in inspected["links"]:
                neighbor = link.get("neighbor") if isinstance(link.get("neighbor"), dict) else None
                remote_device = self._neighbor_device(neighbor) if neighbor else None
                edge = {
                    "depth": layer,
                    "source_ip": ip,
                    "source_name": inspected["name"],
                    "source_port": link.get("port") or "",
                    "link_type": link.get("source") or "vlan-inspection",
                    "carries_vlan": link.get("carries_vlan"),
                    "neighbor_name": (neighbor or {}).get("remote_name") or link.get("neighbor_name") or "",
                    "neighbor_ip": (neighbor or {}).get("remote_ip") or link.get("neighbor_ip") or "",
                    "neighbor_port": (neighbor or {}).get("remote_port") or "",
                    "neighbor_source": (neighbor or {}).get("source") or "unresolved",
                    "switch_neighbor": bool(neighbor),
                    "traversal": "not-followed",
                }
                if link.get("carries_vlan") is False:
                    edge["traversal"] = "missing-vlan"
                    findings.append({
                        "severity": "critical",
                        "code": "VLAN_MISSING_ON_TRUNK",
                        "depth": layer,
                        "device": inspected["name"],
                        "ip": ip,
                        "port": link.get("port") or "",
                        "detail": f"VLAN {vlan} is missing on trunk toward {edge['neighbor_name'] or edge['neighbor_ip'] or 'an unresolved neighbor'}",
                    })
                if remote_device and layer < depth_limit:
                    remote_key = str(remote_device.get("ip") or remote_device.get("hostname") or "").lower()
                    if remote_key in visited or remote_key in scheduled:
                        edge["traversal"] = "cycle-suppressed"
                    elif len(scheduled) >= node_limit:
                        edge["traversal"] = "node-budget"
                        budget_hit = True
                    else:
                        queue_rows.append((remote_device, layer + 1, ip))
                        scheduled.add(remote_key)
                        edge["traversal"] = "queued"
                elif remote_device and layer >= depth_limit:
                    edge["traversal"] = "depth-limit"
                elif not remote_device and neighbor:
                    edge["traversal"] = "neighbor-ip-unresolved"
                    findings.append({
                        "severity": "warning",
                        "code": "NEIGHBOR_DEVICE_UNRESOLVED",
                        "depth": layer,
                        "device": inspected["name"],
                        "ip": ip,
                        "port": link.get("port") or "",
                        "detail": f"Neighbor {edge['neighbor_name'] or edge['neighbor_ip']} could not be resolved to a safe SSH target",
                    })
                edges.append(edge)

        budget_reached = budget_hit or index < len(queue_rows)
        if budget_reached:
            findings.append({"severity": "warning", "code": "NODE_BUDGET_REACHED", "depth": depth_limit, "device": "", "ip": "", "port": "", "detail": f"Traversal stopped at the --max-nodes budget of {node_limit}"})
        missing_nodes = sum(1 for row in nodes if row.get("defined") is False)
        present_nodes = sum(1 for row in nodes if row.get("defined") is True)
        trunk_gaps = sum(int(row.get("trunks_missing") or 0) for row in nodes)
        physical_links = {
            tuple(sorted((str(row.get("source_ip") or ""), str(row.get("neighbor_ip") or ""))))
            for row in edges
            if row.get("switch_neighbor") and row.get("source_ip") and row.get("neighbor_ip") and row.get("source_ip") != row.get("neighbor_ip")
        }
        critical = sum(1 for row in findings if row.get("severity") == "critical")
        unresolved = sum(1 for row in findings if row.get("code") == "NEIGHBOR_DEVICE_UNRESOLVED")
        payload = {
            "ok": inspection_errors == 0,
            "healthy": critical == 0,
            "complete": inspection_errors == 0 and not budget_reached and unresolved == 0,
            "mode": mode,
            "root": {"ip": root.get("ip"), "name": root_name},
            "vlan": vlan,
            "depth": depth_limit,
            "max_nodes": node_limit,
            "nodes": timestamp_rows(nodes),
            "edges": edges,
            "findings": findings,
            "counts": {
                "visited_nodes": len(nodes),
                "switch_links": len(physical_links),
                "switch_link_observations": len(edges),
                "present_nodes": present_nodes,
                "missing_nodes": missing_nodes,
                "trunk_gaps": trunk_gaps,
                "critical_findings": critical,
                "warnings": sum(1 for row in findings if row.get("severity") == "warning"),
                "unresolved_links": unresolved,
                "inspection_errors": inspection_errors,
            },
            "observed_at": now(),
            "observed_at_iso": fmt_time(now()),
            "traversal": "breadth_first",
            "depth_semantics": "root is layer 0; depth is the maximum number of switch-link hops",
        }
        display_nodes = [{
            "layer": row.get("depth"),
            "device": row.get("name"),
            "ip": row.get("ip"),
            "vlan": row.get("vlan_status"),
            "trunks": row.get("trunk_count"),
            "gaps": row.get("trunks_missing"),
            "result": row.get("result"),
        } for row in payload["nodes"]]
        if mode == "locate":
            for display, row in zip(display_nodes, payload["nodes"]):
                display["access"] = row.get("access_port_count")
        columns = ["layer", "device", "ip", "vlan"] + (["access"] if mode == "locate" else []) + ["trunks", "gaps", "result"]
        node_text = self.render_table(display_nodes, columns)
        finding_text = self.render_table(findings[:opts.limit], ["severity", "code", "depth", "device", "port", "detail"]) if findings else "No VLAN gaps or inspection failures found."
        text = (
            f"VLAN {vlan} {mode} from {root_name}\n"
            f"Depth: {depth_limit} | Switches: {len(nodes)} | Switch links: {len(physical_links)} | "
            f"Present: {present_nodes} | Absent: {missing_nodes} | Trunk gaps: {trunk_gaps} | Errors: {inspection_errors}\n\n"
            f"Switch path\n{node_text}\n\nFindings\n{finding_text}"
        )
        code = PARTIAL if inspection_errors else SUCCESS
        if collect:
            return code, payload, text
        self.emit(payload, opts, text)
        return code

    def vlan_cascade_many(self, targets: Sequence[str], vlans: Sequence[int], mode: str, opts: GlobalOptions) -> int:
        unique_targets = list(dict.fromkeys(str(target).strip() for target in targets if str(target).strip()))
        unique_vlans = list(dict.fromkeys(int(vlan) for vlan in vlans))
        if len(unique_targets) == 1 and len(unique_vlans) == 1:
            return int(self.vlan_cascade(unique_targets[0], unique_vlans[0], mode, opts))
        runs: List[Dict[str, Any]] = []
        matrix: List[Dict[str, Any]] = []
        findings: List[Dict[str, Any]] = []
        codes: List[int] = []
        for target_index, target in enumerate(unique_targets, 1):
            for vlan_index, vlan in enumerate(unique_vlans, 1):
                self.live_log("vlan", f"scan {target_index}/{len(unique_targets)} root, {vlan_index}/{len(unique_vlans)} VLAN: {target} VLAN {vlan}")
                result = self.vlan_cascade(target, vlan, mode, opts, collect=True)
                if not isinstance(result, tuple):
                    return int(result)
                code, payload, _ = result
                codes.append(int(code))
                runs.append(payload)
                counts = payload.get("counts") or {}
                matrix.append({
                    "root": (payload.get("root") or {}).get("name") or target,
                    "root_ip": (payload.get("root") or {}).get("ip") or "",
                    "vlan": vlan,
                    "switches": counts.get("visited_nodes"),
                    "present": counts.get("present_nodes"),
                    "absent": counts.get("missing_nodes"),
                    "trunk_gaps": counts.get("trunk_gaps"),
                    "errors": counts.get("inspection_errors"),
                    "complete": payload.get("complete"),
                    "result": "ERROR" if counts.get("inspection_errors") else ("GAPS" if counts.get("critical_findings") else "PRESENT"),
                })
                for item in payload.get("findings") or []:
                    findings.append({"root": (payload.get("root") or {}).get("name") or target, "vlan": vlan, **item})
        observed = now()
        payload = {
            "ok": all(run.get("ok") for run in runs),
            "healthy": all(run.get("healthy") for run in runs),
            "complete": all(run.get("complete") for run in runs),
            "mode": mode,
            "targets": unique_targets,
            "vlans": unique_vlans,
            "depth": int(opts.depth or 0),
            "matrix": matrix,
            "runs": runs,
            "findings": findings,
            "counts": {
                "roots": len(unique_targets),
                "vlans": len(unique_vlans),
                "scans": len(runs),
                "visited_node_observations": sum(int((run.get("counts") or {}).get("visited_nodes") or 0) for run in runs),
                "trunk_gaps": sum(int((run.get("counts") or {}).get("trunk_gaps") or 0) for run in runs),
                "inspection_errors": sum(int((run.get("counts") or {}).get("inspection_errors") or 0) for run in runs),
            },
            "observed_at": observed,
            "observed_at_iso": fmt_time(observed),
        }
        finding_text = self.render_table(findings[:opts.limit], ["severity", "code", "root", "vlan", "depth", "device", "port", "detail"]) if findings else "No VLAN gaps or inspection failures found."
        text = (
            f"VLAN {mode}: {len(unique_targets)} root(s) x {len(unique_vlans)} VLAN(s), depth {int(opts.depth or 0)}\n"
            + self.render_table(matrix, ["root", "root_ip", "vlan", "switches", "present", "absent", "trunk_gaps", "errors", "result"])
            + f"\n\nFindings\n{finding_text}"
        )
        self.emit(payload, opts, text)
        return PARTIAL if any(code != SUCCESS for code in codes) else SUCCESS

    def point_of_truth_ping(
        self,
        target: str,
        opts: GlobalOptions,
        core_target: str = "",
        count: int = 5,
        packet_timeout: int = 2,
    ) -> int:
        destination = normalize_target_literal(target)
        if not is_ipv4_literal(destination):
            destination = self.resolve_one(target)
        if not is_ipv4_literal(destination):
            return self.usage_error("diagnose", "core-ping", opts, f"Could not resolve destination to a device IP: {target}", "netops diagnose core-ping 192.0.2.50", VALIDATION)

        configured_core = str(
            core_target
            or self.config.public.get("core_switch_ip")
            or self.config.public.get("core_switch")
            or ""
        ).strip()
        if not configured_core:
            return self.usage_error("diagnose", "core-ping", opts, "No core switch is configured. Set core_switch_ip or pass --core.", "netops diagnose core-ping 192.0.2.50 --core CORE01", VALIDATION)
        core, choices = self.resolve_device_record(configured_core)
        if not core:
            normalized_core = normalize_target_literal(configured_core)
            if is_ipv4_literal(normalized_core):
                core = {"ip": normalized_core, "hostname": configured_core, "platform": "Unknown", "model": "", "status": "UNKNOWN"}
            else:
                labels = ", ".join(str(row.get("hostname") or row.get("ip")) for row in choices[:8])
                return self.usage_error("diagnose", "core-ping", opts, f"Core switch could not be resolved safely: {configured_core}" + (f" ({labels})" if labels else ""), "netops inventory list <core>", VALIDATION)

        count = max(1, min(int(count or 5), 20))
        packet_timeout = max(1, min(int(packet_timeout or 2), 10))
        detection = self.detect_device_family(platform=core.get("platform"), model=core.get("model"), hostname=core.get("hostname"))
        driver = self.driver_for(family=detection.family)
        core_ip = str(core.get("ip") or configured_core)
        if opts.dry_run:
            payload = {
                "ok": True,
                "dry_run": True,
                "mode": "core-ping",
                "source": {"ip": core_ip, "name": core.get("hostname") or core_ip, "platform": core.get("platform") or "Unknown"},
                "target": target,
                "target_ip": destination,
                "count": count,
                "packet_timeout": packet_timeout,
                "note": "Vendor-specific read-only ping syntax is selected at execution time.",
            }
            self.emit(payload, opts, f"Dry run: point-of-truth ping {core.get('hostname') or core_ip} ({core_ip}) -> {destination}; count={count}")
            return SUCCESS
        if driver.family == "unknown":
            self.live_log("core-ping", f"{core_ip}: detect platform before selecting ping syntax")
            _, version_out, version_err = self.capture(self.legacy_cmd("netops-control", "show", core_ip, "show version"), opts.timeout or 90)
            version_text = (version_out or "") + (version_err or "")
            detection = self.detect_device_family(platform=core.get("platform"), model=core.get("model"), sysdescr=version_text, hostname=core.get("hostname"))
            driver = self.driver_for(family=detection.family)
            if driver.family != "unknown":
                core["platform"] = f"{driver.vendor} {driver.os_name}"
        if driver.family == "unknown":
            driver = self.driver_for(family="cisco-ios")
        ping_templates = driver.command_templates.get("ping") or ("ping {destination} repeat {count} timeout {timeout}",)
        device_command = ping_templates[0].format(destination=destination, count=count, timeout=packet_timeout)
        self.live_log("core-ping", f"{core.get('hostname') or core_ip} ({core_ip}) -> {destination}; count={count}")
        rc, stdout, stderr = self.capture(
            self.legacy_cmd("netops-control", "show", core_ip, device_command),
            opts.timeout or (count * packet_timeout + 45),
        )
        raw = (stdout or "") + (stderr or "")
        parsed = parse_ping_output(raw, count)
        observed = now()
        payload = {
            "ok": bool(parsed.get("parsed") and int(parsed.get("received") or 0) > 0),
            "healthy": parsed.get("status") == "REACHABLE",
            "mode": "core-ping",
            "source": {"ip": core_ip, "name": core.get("hostname") or core_ip, "platform": core.get("platform") or "Unknown"},
            "driver_family": driver.family,
            "target": target,
            "target_ip": destination,
            "command": device_command,
            "exit_code": rc,
            "helper_exit_ignored": bool(rc not in {0, None} and parsed.get("parsed")),
            **parsed,
            "observed_at": observed,
            "observed_at_iso": fmt_time(observed),
            "output_excerpt": " ".join(clean_network_output(raw).split())[:1000],
        }
        with contextlib.suppress(Exception):
            self.state.record_probe_result(destination, f"core-ping:{core_ip}", payload)
        self.live_log(
            "core-ping",
            f"status={payload['status']} received={payload['received']}/{payload['transmitted']} loss={payload.get('packet_loss_pct')}% avg={payload.get('avg_ms')} ms",
        )
        text = (
            f"Point-of-truth ping from {payload['source']['name']} ({core_ip}) to {destination}\n"
            f"Status: {payload['status']} | Received: {payload['received']}/{payload['transmitted']} | Loss: {payload.get('packet_loss_pct')}%\n"
            f"Latency min/avg/max: {payload.get('min_ms')} / {payload.get('avg_ms')} / {payload.get('max_ms')} ms\n"
            f"Recorded: {payload['observed_at_iso']}"
        )
        self.emit(payload, opts, text)
        if not parsed.get("parsed"):
            return PARTIAL
        if int(parsed.get("received") or 0) <= 0:
            return UNREACHABLE
        return PARTIAL if float(parsed.get("packet_loss_pct") or 0) > 0 else SUCCESS

    def internet_speed_diagnostic(self, runs: int, ca_file: str, opts: GlobalOptions, profile: str = "balanced") -> int:
        profile = (profile or "balanced").lower()
        profile_defaults = {"quick": 1, "balanced": 2, "thorough": 3}
        if profile not in profile_defaults:
            profile = "balanced"
        runs = max(1, min(int(runs or profile_defaults[profile]), 5))
        if profile != "quick" and runs < 2:
            runs = 2
        cmd = self.legacy_cmd("netops-probe", "-s", "--profile", profile, "--speed-runs", str(runs), "--json")
        if ca_file:
            cmd += ["--ca-file", ca_file]
        if opts.dry_run:
            payload = {
                "ok": True,
                "dry_run": True,
                "scope": "netops-host-to-internet",
                "profile": profile,
                "servers": runs,
                "command": shlex.join(cmd),
                "note": "No traffic was generated. Quick uses one complete server by default; balanced uses two; thorough uses three or more for stronger agreement.",
            }
            self.emit(payload, opts, f"Dry run: {payload['command']}")
            return SUCCESS
        rc, stdout, stderr = self.capture_streamed(cmd, opts.timeout or 1800)
        try:
            payload = json.loads(stdout)
        except (TypeError, ValueError, json.JSONDecodeError):
            detail = " ".join((stderr or stdout or "speed backend returned no structured result").split())[:1000]
            blocked = bool(re.search(r"\b401\b|authorization required|access denied|blocked|filter(?:ed|ing)?", detail, re.I))
            status = "BLOCKED" if blocked else "ERROR"
            error = {
                "ok": False,
                "status": status,
                "exit_code": rc,
                "error": detail,
                "failure_class": "UPSTREAM_AUTH_OR_POLICY" if blocked else "BACKEND_OR_CONNECTIVITY",
                "remediation": "Use an organization-approved authenticated benchmark path or a controlled iperf3 server; do not disable TLS verification." if blocked else "Run 'netops diagnose doctor --online' and inspect route, TLS trust, DNS, and upstream availability.",
                "observed_at": now(),
            }
            error["observed_at_iso"] = fmt_time(error["observed_at"])
            with contextlib.suppress(Exception):
                error["record_id"] = self.state.record_diagnostic_run("internet-speed", "internet", "netops-host", status, detail, error)
            self.emit(error, opts, f"Internet speed test {status.lower()}: {detail}\n{error['remediation']}\nRecorded: {error['observed_at_iso']}")
            return rc if rc else INTERNAL
        payload.setdefault("observed_at", now())
        payload["observed_at_iso"] = fmt_time(payload["observed_at"])
        reliability = payload.get("reliability") or {}
        rating = str(reliability.get("rating") or "unknown").upper()
        status = "PASS" if payload.get("ok") and rating in {"HIGH", "MEDIUM"} else ("ATTENTION" if payload.get("ok") else "ERROR")
        download = (payload.get("download_mbps") or {}).get("sustained")
        upload = (payload.get("upload_mbps") or {}).get("sustained")
        summary = f"{download} Mbps down, {upload} Mbps up, reliability {rating.lower()}"
        with contextlib.suppress(Exception):
            payload["speed_test_id"] = self.state.record_speed_result(payload)
            payload["record_id"] = self.state.record_diagnostic_run("internet-speed", "internet", "netops-host", status, summary, payload)
        text = (
            "Internet speed from this NetOps host\n"
            f"Profile: {payload.get('profile') or profile} | Servers: {payload.get('servers_completed')}/{payload.get('servers_attempted')}\n"
            f"Download: {download} Mbps | Upload: {upload} Mbps | Reliability: {rating}\n"
            f"Idle/loaded latency: {(payload.get('latency_ms') or {}).get('idle')} / "
            f"{(payload.get('latency_ms') or {}).get('loaded_download')} down / {(payload.get('latency_ms') or {}).get('loaded_upload')} up ms\n"
            f"TLS: verified via {(payload.get('tls') or {}).get('trust_source')} | Interface: {(payload.get('path') or {}).get('interface')}\n"
            f"Recorded: {payload['observed_at_iso']}\n"
            "Scope: the machine running NetOps to the Internet; this is not a measurement of an arbitrary endpoint."
        )
        self.emit(payload, opts, text)
        return rc if rc in {SUCCESS, PARTIAL} else (SUCCESS if payload.get("ok") else INTERNAL)

    def _diagnostic_device(self, target: str) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]]]:
        device, choices = self.resolve_device_record(target)
        if device:
            return device, choices
        normalized = normalize_target_literal(target)
        if is_ipv4_literal(normalized):
            return {"ip": normalized, "hostname": normalized, "platform": "Unknown", "model": "", "status": "UNKNOWN"}, []
        return None, choices

    def port_health_diagnostic(
        self,
        target: str,
        interface: str,
        sample_seconds: int,
        expected_speed: int,
        opts: GlobalOptions,
    ) -> int:
        device, choices = self._diagnostic_device(target)
        if not device:
            labels = ", ".join(str(row.get("hostname") or row.get("ip")) for row in choices[:8])
            return self.usage_error("diagnose", "port-health", opts, f"Device could not be resolved: {target}" + (f" ({labels})" if labels else ""), "netops diagnose port-health <device> on <interface>", VALIDATION)
        interface = str(interface or "").strip()
        if not interface or not re.fullmatch(r"[A-Za-z][A-Za-z0-9./:_-]{0,63}|\d{1,4}", interface):
            return self.usage_error("diagnose", "port-health", opts, "Interface name is invalid.", "netops diagnose port-health ZONE34 on Gi1/0/7", VALIDATION)
        sample_seconds = max(0, min(int(sample_seconds or 0), 60))
        expected_speed = max(0, min(int(expected_speed or 0), 400000))
        ip = str(device.get("ip") or "")
        driver = self.driver_for(platform=device.get("platform"), model=device.get("model"), hostname=device.get("hostname"))
        commands = [template.format(interface=interface) for template in driver.command_templates.get("interface_health") or (f"show interfaces {interface}",)]
        helpers = [self.legacy_cmd("netops-control", "show", ip, command) for command in commands]
        if opts.dry_run:
            rendered_commands = [shlex.join(helper) for helper in helpers]
            payload = {"ok": True, "dry_run": True, "device": device, "driver_family": driver.family, "interface": interface, "sample_seconds": sample_seconds, "expected_speed_mbps": expected_speed or None, "commands": rendered_commands}
            self.emit(payload, opts, f"Dry run: inspect {device.get('hostname') or ip} {interface} twice, {sample_seconds}s apart")
            return SUCCESS

        def snapshot() -> Tuple[int, str, str, Dict[str, Any]]:
            rc = 0; outputs: List[str] = []; errors: List[str] = []
            for helper in helpers:
                helper_rc, helper_output, helper_error = self.capture(helper, opts.timeout or 120)
                rc = rc or helper_rc
                outputs.append(helper_output or "")
                errors.append(helper_error or "")
            output = "\n".join(outputs)
            error = "\n".join(errors)
            return rc, output, error, parse_interface_health_output((output or "") + (error or ""))

        self.live_log("port-health", f"read baseline counters on {device.get('hostname') or ip} {interface}")
        rc1, out1, err1, baseline = snapshot()
        if not baseline.get("parsed"):
            self.live_log("port-health", "baseline is unusable; retry immediately instead of waiting for a delta sample")
            sample_seconds = 0
        elif sample_seconds:
            self.live_log("port-health", f"observe for {sample_seconds}s before reading counter deltas")
            time.sleep(sample_seconds)
        self.live_log("port-health", f"read current counters on {device.get('hostname') or ip} {interface}")
        rc2, out2, err2, current = snapshot()
        deltas: Dict[str, Optional[int]] = {}
        counter_resets: List[str] = []
        first_counters = baseline.get("counters") or {}
        last_counters = current.get("counters") or {}
        for key in sorted(set(first_counters) | set(last_counters)):
            if key not in first_counters or key not in last_counters:
                deltas[key] = None
                continue
            delta = int(last_counters[key]) - int(first_counters[key])
            if delta < 0:
                deltas[key] = None
                counter_resets.append(key)
            else:
                deltas[key] = delta

        findings: List[Dict[str, Any]] = []
        if not baseline.get("parsed"):
            findings.append({"severity": "warning", "code": "BASELINE_UNAVAILABLE", "detail": "The baseline output was not recognized, so active counter deltas could not be measured."})
        if not current.get("parsed"):
            findings.append({"severity": "critical", "code": "OUTPUT_UNPARSED", "detail": "Switch interface output was not recognized."})
        if current.get("admin_status") == "DOWN":
            findings.append({"severity": "critical", "code": "ADMIN_DOWN", "detail": "The switch port is administratively disabled."})
        elif current.get("oper_status") == "DOWN":
            findings.append({"severity": "critical", "code": "LINK_DOWN", "detail": "The physical/link protocol state is down."})
        if current.get("duplex") == "HALF":
            findings.append({"severity": "warning", "code": "HALF_DUPLEX", "detail": "The link negotiated half duplex; check both endpoints and cabling."})
        actual_speed = current.get("speed_mbps")
        if expected_speed and actual_speed is not None and float(actual_speed) < expected_speed:
            findings.append({"severity": "warning", "code": "SPEED_BELOW_EXPECTED", "detail": f"Negotiated {actual_speed} Mbps; expected at least {expected_speed} Mbps."})
        meaningful = {
            "crc_errors", "frame_errors", "input_errors", "output_errors", "collisions",
            "late_collisions", "excessive_collisions", "runts", "giants", "rx_errors",
        }
        for key in sorted(meaningful):
            value = deltas.get(key)
            if value and value > 0:
                severity = "critical" if key in {"crc_errors", "late_collisions", "excessive_collisions"} else "warning"
                findings.append({"severity": severity, "code": "COUNTER_INCREASE", "counter": key, "delta": value, "detail": f"{key.replace('_', ' ')} increased by {value} during the sample."})
        if counter_resets:
            findings.append({"severity": "warning", "code": "COUNTER_RESET", "detail": "Counters reset or wrapped during the sample: " + ", ".join(counter_resets)})
        status = "ERROR" if not current.get("parsed") else ("DOWN" if current.get("oper_status") == "DOWN" else ("ATTENTION" if findings else "HEALTHY"))
        speed_bps = float(actual_speed or 0) * 1_000_000
        utilization = round(max(float(current.get("input_bps") or 0), float(current.get("output_bps") or 0)) / speed_bps * 100, 3) if speed_bps else None
        observed = now()
        payload = {
            "ok": status not in {"ERROR"},
            "healthy": status == "HEALTHY",
            "status": status,
            "device": device.get("hostname") or ip,
            "device_ip": ip,
            "platform": device.get("platform") or "Unknown",
            "driver_family": driver.family,
            "interface": interface,
            "sample_seconds": sample_seconds,
            "baseline_exit_code": rc1,
            "current_exit_code": rc2,
            "helper_exit_ignored": bool(current.get("parsed") and rc2 not in {0, None}),
            "expected_speed_mbps": expected_speed or None,
            "baseline": baseline,
            "current": current,
            "counter_deltas": deltas,
            "utilization_pct": utilization,
            "findings": findings,
            "observed_at": observed,
            "observed_at_iso": fmt_time(observed),
            "interpretation": "Cumulative totals show history; only sampled increases indicate errors during this observation window.",
            "output_excerpt": " ".join(clean_network_output((out2 or "") + (err2 or "")).split())[:1200],
        }
        summary = f"{status}; link={current.get('oper_status')}; speed={actual_speed}; findings={len(findings)}"
        with contextlib.suppress(Exception):
            payload["interface_sample_id"] = self.state.record_interface_result(payload)
            payload["record_id"] = self.state.record_diagnostic_run("port-health", f"{ip}:{interface}", "switch", status, summary, payload)
        findings_text = self.render_table(findings, ["severity", "code", "counter", "delta", "detail"]) if findings else "No active link or counter-delta findings."
        text = (
            f"Port health: {device.get('hostname') or ip} ({ip}) {interface}\n"
            f"Status: {status} | Admin/oper: {current.get('admin_status')}/{current.get('oper_status')} | Speed/duplex: {actual_speed or 'unknown'} Mbps/{current.get('duplex')}\n"
            f"Sample: {sample_seconds}s | Utilization: {utilization if utilization is not None else 'unknown'}% | Recorded: {payload['observed_at_iso']}\n\n"
            f"Findings\n{findings_text}\n\nCumulative counters: {json.dumps(last_counters, sort_keys=True)}\n"
            f"Sampled deltas: {json.dumps(deltas, sort_keys=True)}"
        )
        self.emit(payload, opts, text)
        return PARTIAL if status in {"ATTENTION", "DOWN", "ERROR"} else SUCCESS

    def cable_diagnostic(
        self,
        target: str,
        interface: str,
        start_test: bool,
        wait_seconds: int,
        opts: GlobalOptions,
    ) -> int:
        device, choices = self._diagnostic_device(target)
        if not device:
            labels = ", ".join(str(row.get("hostname") or row.get("ip")) for row in choices[:8])
            return self.usage_error("diagnose", "cable", opts, f"Device could not be resolved: {target}" + (f" ({labels})" if labels else ""), "netops diagnose cable <device> on <interface>", VALIDATION)
        interface = str(interface or "").strip()
        if not interface or not re.fullmatch(r"[A-Za-z][A-Za-z0-9./:_-]{0,63}|\d{1,4}", interface):
            return self.usage_error("diagnose", "cable", opts, "Interface name is invalid.", "netops diagnose cable ZONE34 on Gi1/0/7", VALIDATION)
        wait_seconds = max(2, min(int(wait_seconds or 8), 60))
        ip = str(device.get("ip") or "")
        driver = self.driver_for(platform=device.get("platform"), model=device.get("model"), hostname=device.get("hostname"))
        if driver.family == "unknown":
            driver = self.driver_for(family="cisco-ios")
        family = driver.family
        status_templates = driver.command_templates.get("cable_status") or ()
        test_templates = driver.command_templates.get("cable_start") or ()
        if not status_templates:
            payload = {"ok": False, "status": "UNSUPPORTED", "device": device, "interface": interface, "platform_family": family, "reason": f"Cable diagnostics are not supported by the {family} driver."}
            self.emit(payload, opts, payload["reason"])
            return UNSUPPORTED
        status_command = status_templates[0].format(interface=interface)
        test_command = test_templates[0].format(interface=interface) if test_templates else ""
        if start_test and not test_command:
            payload = {"ok": False, "status": "UNSUPPORTED", "device": device, "interface": interface, "platform_family": family, "reason": f"Starting cable diagnostics is not supported by the {family} driver."}
            self.emit(payload, opts, payload["reason"])
            return UNSUPPORTED

        if start_test and not (opts.dry_run or opts.confirm):
            return self.usage_error(
                "diagnose", "cable", opts,
                "Starting cable diagnostics may interrupt a live copper link. Review with --dry-run or execute with --confirm.",
                f"netops diagnose cable {target} on {interface} --test --dry-run",
                CONFIRM_REQUIRED,
            )
        if opts.dry_run:
            commands = [test_command, f"wait {wait_seconds}s", status_command] if start_test else [status_command]
            payload = {
                "ok": True, "dry_run": True, "device": device, "interface": interface,
                "platform_family": family, "start_test": start_test, "commands": commands,
                "disruptive": start_test,
                "warning": "An active TDR can briefly interrupt copper traffic and cannot validate fiber or every intermittent defect.",
            }
            self.emit(payload, opts, "Cable diagnostic preview\n" + "\n".join(f"  {item}" for item in commands) + ("\nNo command executed." if start_test else ""))
            return SUCCESS

        if start_test and family == "aruba-aos-cx":
            payload = {"ok": False, "status": "UNSUPPORTED", "device": device, "interface": interface, "reason": "Aruba CX interactive confirmation is not automated; run the preview and execute directly on the switch during a maintenance window."}
            self.emit(payload, opts, payload["reason"])
            return UNSUPPORTED
        precheck_exit_code: Optional[int] = None
        precheck_exit_ignored = False
        test_start_exit_code: Optional[int] = None
        test_start_exit_ignored = False
        if start_test:
            self.live_log("cable", f"verify {interface} is copper before starting the disruptive TDR")
            interface_out = ""; interface_err = ""; precheck_exit_code = 0
            precheck_commands = [template.format(interface=interface) for template in driver.command_templates.get("interface_health") or (f"show interfaces {interface}",)]
            for precheck_command in precheck_commands:
                check_rc, check_out, check_err = self.capture(self.legacy_cmd("netops-control", "show", ip, precheck_command), opts.timeout or 120)
                precheck_exit_code = precheck_exit_code or check_rc
                interface_out += ("\n" if interface_out else "") + (check_out or "")
                interface_err += ("\n" if interface_err else "") + (check_err or "")
            interface_state = parse_interface_health_output((interface_out or "") + (interface_err or ""))
            if not interface_state.get("parsed"):
                detail = " ".join(clean_network_output((interface_out or "") + (interface_err or "")).split())[:800] or "interface media precheck returned no recognizable output"
                observed = now()
                payload = {
                    "ok": False,
                    "status": "ERROR",
                    "device": device.get("hostname") or ip,
                    "device_ip": ip,
                    "interface": interface,
                    "platform_family": family,
                    "precheck_exit_code": precheck_exit_code,
                    "error": detail,
                    "reason": "Active TDR was not started because NetOps could not verify the interface media.",
                    "observed_at": observed,
                    "observed_at_iso": fmt_time(observed),
                }
                with contextlib.suppress(Exception):
                    payload["record_id"] = self.state.record_diagnostic_run("cable", f"{ip}:{interface}", family, "ERROR", detail, payload)
                self.emit(payload, opts, f"{payload['reason']}\n{detail}\nRecorded: {payload['observed_at_iso']}")
                return PARTIAL
            precheck_exit_ignored = bool(precheck_exit_code not in {0, None})
            media = str(interface_state.get("media") or "").lower()
            if re.search(r"sfp|fiber|fibre|(?:^|[^a-z])\d*(?:sx|lx|zx|er|lr|sr)(?:$|[^a-z])|base-(?:sx|lx|zx|er|lr|sr)", media):
                payload = {"ok": False, "status": "UNSUPPORTED", "device": device, "interface": interface, "media": interface_state.get("media"), "reason": "TDR is a copper diagnostic and this port reports optical/removable media."}
                self.emit(payload, opts, payload["reason"])
                return UNSUPPORTED
            self.live_log("cable", f"start TDR on {device.get('hostname') or ip} {interface}")
            test_rc, test_out, test_err = self.capture(self.legacy_cmd("netops-control", "show", ip, test_command), opts.timeout or 120)
            test_start_exit_code = test_rc
            test_raw = clean_network_output((test_out or "") + (test_err or ""))
            rejected = bool(re.search(r"invalid input|unknown command|not supported|permission denied|authorization failed|authentication failed|connection (?:failed|timed out)|timed out|unable to|failed to|cannot|can't", test_raw, re.I))
            accepted = bool(re.search(r"(?:tdr|cable(?: diagnostic)?).{0,60}\b(?:started|initiated|running|scheduled|in progress)\b|\b(?:started|initiated|running|scheduled)\b.{0,60}(?:tdr|cable)", test_raw, re.I))
            if rejected or (test_rc and not accepted):
                detail = " ".join(test_raw.split())[:800] or f"cable test helper exited {test_rc} without an acknowledgement"
                failure_status = "UNSUPPORTED" if re.search(r"invalid input|unknown command|not supported", test_raw, re.I) else "ERROR"
                payload = {
                    "ok": False,
                    "status": failure_status,
                    "device": device,
                    "interface": interface,
                    "exit_code": test_rc,
                    "error": detail,
                    "observed_at": now(),
                }
                payload["observed_at_iso"] = fmt_time(payload["observed_at"])
                with contextlib.suppress(Exception):
                    payload["record_id"] = self.state.record_diagnostic_run("cable", f"{ip}:{interface}", family, failure_status, detail, payload)
                self.emit(payload, opts, f"Cable test could not be started: {detail}")
                return UNSUPPORTED if failure_status == "UNSUPPORTED" else PARTIAL
            test_start_exit_ignored = bool(test_rc and accepted)
            self.live_log("cable", f"wait {wait_seconds}s for TDR result")
            time.sleep(wait_seconds)

        self.live_log("cable", f"read {'new' if start_test else 'previous'} TDR result on {device.get('hostname') or ip} {interface}")
        rc, stdout, stderr = self.capture(self.legacy_cmd("netops-control", "show", ip, status_command), opts.timeout or 120)
        raw = (stdout or "") + (stderr or "")
        parsed = parse_cable_diagnostics_output(raw)
        # Some Aruba inventory records do not distinguish AOS-Switch from CX.
        if family == "aruba-aos-switch" and not parsed.get("parsed") and re.search(r"invalid input|unknown command", raw, re.I):
            fallback = f"diag cable-diagnostic show {interface}"
            rc, stdout, stderr = self.capture(self.legacy_cmd("netops-control", "show", ip, fallback), opts.timeout or 120)
            raw = (stdout or "") + (stderr or "")
            parsed = parse_cable_diagnostics_output(raw)
            status_command = fallback
            family = "aruba-aos-cx"
        observed = now()
        parsed_status = str(parsed.get("status") or "UNKNOWN")
        status = parsed_status if parsed.get("parsed") else "ERROR"
        payload = {
            "ok": bool(parsed.get("parsed")),
            "healthy": parsed.get("healthy"),
            "device": device.get("hostname") or ip,
            "device_ip": ip,
            "interface": interface,
            "platform_family": family,
            "test_started": start_test,
            "command": status_command,
            **parsed,
            "status": status,
            "exit_code": rc,
            "helper_exit_ignored": bool(parsed.get("parsed") and rc not in {0, None}),
            "precheck_exit_code": precheck_exit_code,
            "precheck_exit_ignored": precheck_exit_ignored,
            "test_start_exit_code": test_start_exit_code,
            "test_start_exit_ignored": test_start_exit_ignored,
            "observed_at": observed,
            "observed_at_iso": fmt_time(observed),
            "limitations": [
                "TDR applies to copper pairs, not fiber.",
                "A clean result does not prove application throughput or rule out intermittent movement-related faults.",
                "Pair mapping and fault distance are estimates; repeat suspicious tests during a maintenance window.",
            ],
            "output_excerpt": " ".join(clean_network_output(raw).split())[:1200],
        }
        summary = f"{status}; pairs={len(parsed.get('pairs') or [])}; active_test={start_test}"
        with contextlib.suppress(Exception):
            payload["record_id"] = self.state.record_diagnostic_run("cable", f"{ip}:{interface}", family, status, summary, payload)
        pair_text = self.render_table(parsed.get("pairs") or [], ["pair", "status", "distance_m"]) if parsed.get("pairs") else parsed.get("message")
        text = (
            f"Cable diagnostic: {device.get('hostname') or ip} ({ip}) {interface}\n"
            f"Status: {status} | Result: {'new active test' if start_test else 'previous stored test'} | Recorded: {payload['observed_at_iso']}\n"
            f"{pair_text}\n"
            "Note: TDR assesses copper pair continuity/impedance. Port error deltas and an iperf test are still required for end-to-end quality."
        )
        self.emit(payload, opts, text)
        if status == "HEALTHY":
            return SUCCESS
        if status == "UNSUPPORTED":
            return UNSUPPORTED
        if parsed.get("parsed"):
            return PARTIAL
        return PARTIAL if rc not in {0, None} else INTERNAL

    def throughput_diagnostic(
        self,
        server: str,
        port: int,
        seconds: int,
        parallel: int,
        direction: str,
        bind: str,
        opts: GlobalOptions,
    ) -> int:
        server = str(server or "").strip()
        if server.lower() == "core":
            server = str(self.config.public.get("core_iperf_server") or self.config.public.get("core_switch_ip") or self.config.public.get("core_switch") or "").strip()
        resolved, _ = self._diagnostic_device(server)
        if resolved:
            server = str(resolved.get("ip") or server)
        if not server:
            return self.usage_error("diagnose", "throughput", opts, "Missing iperf3 server. Configure core_iperf_server or supply a host/IP.", "netops diagnose throughput 203.0.113.20", VALIDATION)
        if not 1 <= port <= 65535 or not 1 <= seconds <= 300 or not 1 <= parallel <= 16:
            return self.usage_error("diagnose", "throughput", opts, "Use port 1-65535, seconds 1-300, and parallel streams 1-16.", "netops diagnose throughput 203.0.113.20 --seconds 10 --parallel 2", VALIDATION)
        if direction not in {"both", "upload", "download"}:
            return self.usage_error("diagnose", "throughput", opts, "Direction must be both, upload, or download.", "netops diagnose throughput 203.0.113.20 --direction both", VALIDATION)
        phases = ["upload", "download"] if direction == "both" else [direction]
        commands: List[List[str]] = []
        for phase in phases:
            cmd = ["iperf3", "-c", server, "-p", str(port), "-t", str(seconds), "-P", str(parallel), "-O", "2", "-J"]
            if bind:
                cmd += ["--bind", bind]
            if phase == "download":
                cmd.append("-R")
            commands.append(cmd)
        if opts.dry_run:
            payload = {
                "ok": True, "dry_run": True, "scope": "netops-client-to-controlled-iperf3-server",
                "server": server, "port": port, "seconds": seconds, "parallel": parallel,
                "directions": phases, "commands": [shlex.join(cmd) for cmd in commands],
                "requirement": "An iperf3 server must be listening at the target. To measure a specific endpoint, run this client from that endpoint or its NetOps agent.",
            }
            self.emit(payload, opts, "Throughput preview\n" + "\n".join(f"  {item}" for item in payload["commands"]))
            return SUCCESS
        if not shutil.which("iperf3"):
            self.emit({"ok": False, "error": "iperf3 is not installed"}, opts, "iperf3 is required for controlled endpoint/core throughput testing.")
            return UNSUPPORTED

        results: List[Dict[str, Any]] = []
        for phase, cmd in zip(phases, commands):
            self.live_log("throughput", f"{phase}: this host {'->' if phase == 'upload' else '<-'} {server}:{port}; {seconds}s, {parallel} stream(s)")
            rc, stdout, stderr = self.capture(cmd, opts.timeout or (seconds + 45))
            parsed = parse_iperf3_output(stdout)
            parsed.update({"requested_direction": phase, "exit_code": rc})
            if rc not in {0, None}:
                parsed["backend_reported_ok"] = bool(parsed.get("ok"))
                parsed["ok"] = False
                parsed["error"] = " ".join((stderr or f"iperf3 exited {rc} after emitting a summary").split())[:800]
            if not parsed.get("ok") and stderr and not parsed.get("error"):
                parsed["error"] = " ".join(stderr.split())[:800]
            results.append(parsed)
        observed = now()
        ok = all(row.get("ok") for row in results)
        status = "PASS" if ok else "ERROR"
        payload = {
            "ok": ok,
            "status": status,
            "scope": "netops-client-to-controlled-iperf3-server",
            "server": server,
            "port": port,
            "seconds": seconds,
            "parallel": parallel,
            "bind": bind or None,
            "results": results,
            "observed_at": observed,
            "observed_at_iso": fmt_time(observed),
            "interpretation": "This is TCP receiver goodput between this client and a controlled iperf3 server. Run the client on the endpoint attached to the port for endpoint-specific results.",
        }
        metrics = ", ".join(f"{row.get('requested_direction')}={row.get('megabits_per_second')} Mbps" for row in results if row.get("ok")) or "no completed direction"
        with contextlib.suppress(Exception):
            payload["record_id"] = self.state.record_diagnostic_run("throughput", f"{server}:{port}", "netops-host", status, metrics, payload)
        rows = [{"direction": row.get("requested_direction"), "mbps": row.get("megabits_per_second"), "retransmits": row.get("retransmits"), "seconds": row.get("seconds"), "status": "PASS" if row.get("ok") else "ERROR", "error": row.get("error") or ""} for row in results]
        text = (
            f"Controlled throughput: this NetOps client <-> {server}:{port}\n"
            f"Status: {status} | Recorded: {payload['observed_at_iso']}\n"
            f"{self.render_table(rows, ['direction','mbps','retransmits','seconds','status','error'])}\n"
            "Scope: run this command on the endpoint connected to the switch port for an endpoint-to-core measurement."
        )
        self.emit(payload, opts, text)
        return SUCCESS if ok else PARTIAL

    def diagnostics_doctor(self, online: bool, opts: GlobalOptions) -> int:
        checks: List[Dict[str, Any]] = []
        def add(name: str, status: str, detail: str) -> None:
            checks.append({"check": name, "status": status, "detail": detail})
        for command, required in (
            ("python3", True), ("jq", True), ("ping", True), ("ip", True),
            ("timeout", True), ("awk", True), ("perl", True), ("ssh", True),
            ("flock", True), ("mktemp", True), ("pgrep", True), ("realpath", True),
            ("grep", True), ("sed", True), ("sort", True), ("tr", True),
            ("xargs", True),
            ("ssh-keyscan", False), ("ssh-keygen", False),
            ("sshpass", False), ("expect", False), ("gpg", False), ("sudo", False),
            ("curl", False), ("traceroute", False), ("iperf3", False),
            ("ethtool", False), ("iw", False),
        ):
            path = shutil.which(command)
            add(command, "PASS" if path else ("FAIL" if required else "WARN"), path or ("required" if required else "optional capability unavailable"))
        for helper_name in ("netops-probe", "netops-control", "netops-connect"):
            helper_path = Path(self.paths.tool(helper_name))
            add(helper_name, "PASS" if helper_path.is_file() and os.access(helper_path, os.X_OK) else "FAIL", str(helper_path))
        ping_rc, ping_out, ping_err = self.capture(["ping", "-n", "-c", "1", "-W", "1", "127.0.0.1"], 5)
        ping_detail = " ".join((ping_err or ping_out).split())[:500]
        add("ICMP capability", "PASS" if ping_rc == 0 else "FAIL", "loopback probe succeeded" if ping_rc == 0 else (ping_detail or f"ping exited {ping_rc}"))
        rc, _, speed_error = self.capture([sys.executable, "-c", "import netops_platform.speed, speedtest"], 15)
        add("speed backend", "PASS" if rc == 0 else "FAIL", "netops_platform.speed" if rc == 0 else (speed_error or "speedtest module/helper missing"))
        route_rc, route_out, route_err = self.capture(["ip", "route", "get", "1.1.1.1"], 10)
        route = " ".join((route_out or route_err).split())
        add("Internet route", "PASS" if route_rc == 0 and " dev " in f" {route} " else "FAIL", route or "no route")
        is_wsl = False
        with contextlib.suppress(OSError):
            is_wsl = "microsoft" in Path("/proc/version").read_text(errors="ignore").lower()
        add("host environment", "WARN" if is_wsl else "PASS", "WSL: local ethtool data describes a virtual adapter, not the physical cable" if is_wsl else sys.platform)
        add("configuration directory", "PASS" if os.access(self.paths.config_dir, os.R_OK | os.X_OK) else "FAIL", str(self.paths.config_dir))
        add("cache directory", "PASS" if os.access(self.paths.cache_dir, os.R_OK | os.W_OK | os.X_OK) else "FAIL", str(self.paths.cache_dir))
        for label, path in (
            ("credential config permissions", self.paths.env_file),
            ("SSH vault permissions", Path(os.environ.get("NETOPS_PASSWORD_FILE", str(self.paths.home / ".ssh" / "sshpass_cache.gpg")))),
        ):
            if not path.exists():
                add(label, "WARN", f"not initialized: {path}")
                continue
            try:
                mode = path.stat().st_mode & 0o777
            except OSError as exc:
                add(label, "FAIL", f"could not inspect {path}: {exc}")
                continue
            add(label, "PASS" if mode & 0o077 == 0 else "FAIL", f"{path} mode={mode:04o}; expected no group/other access")
        vault_status = self.vault_status_payload()
        vault_mode = str(vault_status.get("mode") or "missing")
        if vault_mode == "sudo-gpg-v1":
            key_state = str(vault_status.get("root_key") or "not-checked")
            status = "PASS" if key_state == "available" else "FAIL" if key_state in {"missing", "insecure"} else "WARN"
            add("SSH vault mode", status, f"{vault_mode}; sudo={vault_status.get('sudo_session')}; root-key={key_state}; graphical-pinentry=disabled")
        elif vault_mode == "legacy-gpg":
            add("SSH vault mode", "WARN", "legacy-gpg; run 'netops vault migrate' for terminal sudo authentication without graphical pinentry")
        else:
            add("SSH vault mode", "WARN", vault_mode)
        host_key_mode = str(os.environ.get("NETOPS_SSH_HOST_KEY_MODE") or self.config.public.get("ssh_host_key_mode") or "accept-new").lower()
        mode_status = "PASS" if host_key_mode == "strict" else "WARN" if host_key_mode in {"accept-new", "accept_new", "managed"} else "FAIL"
        mode_detail = "strict verification; unknown hosts are rejected" if mode_status == "PASS" else "trust on first use; changed keys are rejected" if mode_status == "WARN" else "unsupported or insecure host-key policy"
        add("SSH host-key mode", mode_status, f"{host_key_mode}: {mode_detail}")
        ssh_user = str(os.environ.get("NETOPS_SSH_USER") or self.config.public.get("ssh_user") or self.config.secret.get("ssh_user") or "")
        add("SSH username", "PASS" if valid_ssh_username(ssh_user) else "FAIL", "configured" if valid_ssh_username(ssh_user) else "set a 1-255 character value without whitespace: netops config set ssh_user <username>")
        known_hosts = self.paths.ssh_known_hosts_file
        if known_hosts.exists():
            mode = known_hosts.stat().st_mode & 0o777
            add("SSH trust store", "PASS" if mode & 0o077 == 0 else "FAIL", f"{known_hosts} mode={mode:04o}; keys={len(self._known_host_rows())}")
        else:
            add("SSH trust store", "WARN", f"not initialized: {known_hosts}; use netops device trust scan/enroll")
        integrity = self.state.integrity_check()
        add("SQLite integrity", "PASS" if integrity.get("ok") else "FAIL", ", ".join(integrity.get("integrity_check") or ["unknown result"]))
        configured_workers = os.environ.get("NETOPS_JOB_CONCURRENCY", "3")
        effective_workers = bounded_int(configured_workers, 3, 1, 32)
        add("job concurrency", "PASS" if str(configured_workers).isdigit() and 1 <= int(configured_workers) <= 32 else "WARN", f"configured={configured_workers}; effective={effective_workers}; allowed=1..32")
        scan_limits = (
            ("scan workers", os.environ.get("NETOPS_SCAN_WORKERS", self.config.public.get("scan_workers", "30")), 1, 256),
            ("scan host limit", os.environ.get("NETOPS_SCAN_MAX_HOSTS", self.config.public.get("scan_max_hosts", "4096")), 1, 65536),
            ("scan host timeout", os.environ.get("NETOPS_SCAN_HOST_TIMEOUT", self.config.public.get("scan_host_timeout", "20")), 1, 300),
        )
        for label, configured, minimum, maximum in scan_limits:
            value = str(configured or "").strip()
            valid = value.isdigit() and minimum <= int(value) <= maximum
            add(label, "PASS" if valid else "FAIL", f"configured={value or 'missing'}; allowed={minimum}..{maximum}")
        core = str(self.config.public.get("core_switch_ip") or self.config.public.get("core_switch") or "").strip()
        add("core switch", "PASS" if core else "WARN", core or "set core_switch_ip for core-origin ping")
        iperf_server = str(self.config.public.get("core_iperf_server") or "").strip()
        add("core iperf3 server", "PASS" if iperf_server else "WARN", iperf_server or "set core_iperf_server or pass a server to diagnose throughput")
        if online and helper.is_file():
            self.live_log("doctor", "verify Speedtest server discovery and TLS trust")
            rc, stdout, stderr = self.capture([sys.executable, str(helper), "--timeout", "30", "servers", "--limit", "1"], opts.timeout or 120)
            try:
                speed_payload = json.loads(stdout)
            except (TypeError, ValueError, json.JSONDecodeError):
                speed_payload = {}
            trust = speed_payload.get("tls_trust") or {}
            add("online TLS/server discovery", "PASS" if rc == 0 and speed_payload.get("ok") and trust.get("verified") else "FAIL", f"trust={trust.get('source')}; servers={len(speed_payload.get('servers') or [])}" if speed_payload else " ".join((stderr or stdout).split())[:500])
        observed = now()
        failed = sum(1 for row in checks if row["status"] == "FAIL")
        warnings = sum(1 for row in checks if row["status"] == "WARN")
        status = "PASS" if failed == 0 else "FAIL"
        payload = {"ok": failed == 0, "status": status, "online": online, "checks": checks, "summary": {"passed": sum(1 for row in checks if row['status'] == 'PASS'), "warnings": warnings, "failed": failed}, "observed_at": observed, "observed_at_iso": fmt_time(observed)}
        with contextlib.suppress(Exception):
            payload["record_id"] = self.state.record_diagnostic_run("doctor", "local", "netops-host", status, f"failed={failed}; warnings={warnings}", payload)
        text = f"NetOps diagnostic readiness\nRecorded: {payload['observed_at_iso']}\n{self.render_table(checks, ['check','status','detail'])}"
        self.emit(payload, opts, text)
        return SUCCESS if failed == 0 else PARTIAL

    def mac_cached_payload(self, mac_value: str, limit: int = 100) -> Dict[str, Any]:
        clean = norm_mac(mac_value)
        if not clean:
            raise ValueError("MAC must be a valid physical unicast address")
        dotted = self.canonical_mac(clean, "dotted")
        colon = self.canonical_mac(clean, "colon")
        hyphen = f"{clean[:6]}-{clean[6:]}"
        mac_expr = "lower(replace(replace(replace(replace(COALESCE(mac,''),':',''),'.',''),'-',''),' ',''))"
        subject_expr = "lower(replace(replace(replace(replace(COALESCE(subject_id,''),':',''),'.',''),'-',''),' ',''))"
        devices = timestamp_rows(self.state.rows(f"SELECT 'device' AS kind,ip,hostname AS name,platform,model,serial,mac,status,last_seen FROM devices WHERE {mac_expr}=? ORDER BY last_seen DESC", (clean,)))
        aps = timestamp_rows(self.state.rows(f"SELECT 'ap' AS kind,ip,name,platform,'' AS model,'' AS serial,mac,status,last_seen,switch_ip,switch_name,switch_port FROM aps WHERE {mac_expr}=? ORDER BY last_seen DESC", (clean,)))
        inventory_history = self.version_rows(self.state.rows(f"SELECT * FROM inventory_history WHERE {mac_expr}=? OR lower(identity_value)=? ORDER BY created_at DESC,id DESC LIMIT ?", (clean, clean, limit)))
        relationships = timestamp_rows(self.state.rows(
            f"SELECT * FROM relationships_current WHERE {subject_expr}=? OR lower(COALESCE(attrs_json,'')) LIKE ? ORDER BY COALESCE(last_seen,updated_at,first_seen,0) DESC LIMIT ?",
            (clean, f"%{clean}%", limit),
        ))
        relationship_history = self.version_rows(self.state.rows(
            f"SELECT * FROM relationship_events WHERE {subject_expr}=? OR lower(COALESCE(current_json,'')) LIKE ? OR lower(COALESCE(previous_json,'')) LIKE ? ORDER BY created_at DESC,id DESC LIMIT ?",
            (clean, f"%{clean}%", f"%{clean}%", limit),
        ))
        cache_rows = timestamp_rows(self.state.rows(
            "SELECT id,created_at,target,exit_code,output FROM core_lookup_cache "
            "WHERE lower(replace(replace(replace(replace(COALESCE(target,''),':',''),'.',''),'-',''),' ',''))=? "
            "OR lower(output) LIKE ? OR lower(output) LIKE ? OR lower(output) LIKE ? ORDER BY created_at DESC,id DESC LIMIT ?",
            (clean, f"%{dotted.lower()}%", f"%{colon.lower()}%", f"%{hyphen.lower()}%", limit),
        ))
        ip_candidates: List[str] = []
        for row in devices + aps:
            ip = str(row.get("ip") or "")
            if IP_RE.fullmatch(ip) and ip not in ip_candidates:
                ip_candidates.append(ip)
        cache_evidence: List[Dict[str, Any]] = []
        for row in cache_rows:
            for ip in extract_ip_candidates(row.get("output")):
                if ip not in ip_candidates:
                    ip_candidates.append(ip)
            cache_evidence.append({
                "id": row.get("id"),
                "created_at": row.get("created_at"),
                "created_at_iso": row.get("created_at_iso"),
                "target": row.get("target"),
                "exit_code": row.get("exit_code"),
                "excerpt": " ".join(clean_network_output(row.get("output")).split())[:500],
            })
        locations = [row for row in relationships if row.get("rel_type") == "mac_location" and row.get("status") != "disappeared"]
        model_hints: List[str] = []
        for row in devices + aps:
            hint = " ".join(str(row.get(key) or "").strip() for key in ("platform", "model") if row.get(key)).strip()
            if hint and hint not in model_hints:
                model_hints.append(hint)
        oui = lookup_oui(clean)
        if oui.get("vendor") and oui["vendor"] != "Unknown" and oui["vendor"] not in model_hints:
            model_hints.append(oui["vendor"])
        last_recorded = max(
            [int(row.get("last_seen") or row.get("updated_at") or 0) for row in relationships]
            + [int(row.get("last_seen") or 0) for row in devices + aps]
            + [int(row.get("created_at") or 0) for row in cache_rows]
            + [0]
        )
        layer2_present = bool(locations)
        ip_present = bool(ip_candidates)
        if layer2_present and not ip_present:
            assessment = "Layer-2 location evidence exists, but no current IP correlation was found. This is consistent with a device that has not obtained an IP, although a switch CAM entry can remain until it ages out."
        elif layer2_present and ip_present:
            assessment = "Layer-2 location and IP evidence are both present."
        elif devices or aps:
            assessment = "An inventory identity exists, but no current structured switch-port observation is cached."
        else:
            assessment = "No current cached identity or switch-port evidence was found. Run MAC locate for a direct forwarding-table search."
        return {
            "ok": bool(devices or aps or relationships or cache_rows),
            "mac": dotted,
            "mac_colon": colon,
            "oui": oui,
            "inventory": devices + aps,
            "current_locations": locations,
            "relationships": relationships,
            "inventory_history": inventory_history,
            "relationship_history": relationship_history,
            "core_lookup_evidence": cache_evidence,
            "ip_candidates": ip_candidates,
            "model_hints": model_hints,
            "layer2_present": layer2_present,
            "ip_evidence_present": ip_present,
            "assessment": assessment,
            "last_recorded_at": last_recorded or None,
            "last_recorded_at_iso": fmt_time(last_recorded),
            "chronology": CHRONOLOGY,
            "time_format": TIME_FORMAT,
            "limitations": [
                "A learned MAC proves forwarding-table evidence, not continuous power or application health.",
                "OUI identifies the registered organization and cannot reliably identify an exact device model.",
                "An endpoint may use a private/randomized MAC or may be silent long enough for the CAM entry to age out.",
            ],
        }

    def render_mac_cached(self, payload: Dict[str, Any]) -> str:
        locations = payload.get("current_locations") or []
        inventory = payload.get("inventory") or []
        return (
            f"MAC evidence: {payload.get('mac')}\n"
            f"Vendor/OUI: {(payload.get('oui') or {}).get('vendor') or 'Unknown'} | IP evidence: {', '.join(payload.get('ip_candidates') or []) or 'none'}\n"
            f"Assessment: {payload.get('assessment')}\n"
            f"Last recorded: {payload.get('last_recorded_at_iso') or 'not recorded'}\n\n"
            f"Current L2 locations\n{self.render_table(locations, ['switch_name','switch_ip','switch_port','status','source','last_seen'])}\n\n"
            f"Inventory identities\n{self.render_table(inventory, ['kind','name','ip','platform','model','status','last_seen'])}"
        )

    def _mac_profile_commands(self, platform: str, port: str, mac: str) -> List[Tuple[str, str]]:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9./:_-]{0,63}", port or ""):
            return []
        dotted = self.canonical_mac(mac, "dotted")
        lower = str(platform or "").lower()
        if "aruba" in lower or "procurve" in lower or lower.startswith("hp"):
            return [
                ("interface", f"show interfaces {port}"),
                ("lldp", f"show lldp info remote-device {port}"),
                ("poe", f"show power-over-ethernet {port}"),
                ("arp", f"show arp | include {dotted}"),
            ]
        return [
            ("interface", f"show interfaces {port} status"),
            ("lldp", f"show lldp neighbors interface {port} detail"),
            ("cdp", f"show cdp neighbors interface {port} detail"),
            ("poe", f"show power inline {port}"),
            ("device_tracking", f"show device-tracking database interface {port}"),
            ("authentication", f"show authentication sessions interface {port} details"),
        ]

    def profile_mac_port(self, hit: Dict[str, Any], opts: GlobalOptions) -> Dict[str, Any]:
        switch_ip = str(hit.get("switch_ip") or "")
        port = str(hit.get("port") or "")
        evidence: List[Dict[str, Any]] = []
        ip_candidates: List[str] = []
        model_hints: List[str] = []
        description = ""
        for evidence_type, command in self._mac_profile_commands(str(hit.get("platform") or ""), port, str(hit.get("mac") or "")):
            rc, stdout, stderr = self.capture(self.legacy_cmd("netops-control", "show", switch_ip, command), opts.timeout or 90)
            text = (stdout or "") + (stderr or "")
            clean_text = clean_network_output(text)
            excerpt = "\n".join(line for line in clean_text.splitlines() if line.strip())[-1600:]
            evidence.append({"type": evidence_type, "command": command, "exit_code": rc, "excerpt": excerpt})
            for ip in extract_ip_candidates(clean_text):
                if ip not in ip_candidates and ip != switch_ip:
                    ip_candidates.append(ip)
            for neighbor in parse_neighbor_detail_output(clean_text):
                hint = str(neighbor.get("platform") or neighbor.get("remote_name") or "").strip()
                if hint and hint not in model_hints:
                    model_hints.append(hint)
            desc_match = re.search(r"(?im)^\s*(?:description|name)\s*[: ]\s*(.+)$", clean_text)
            if desc_match and not description:
                description = desc_match.group(1).strip()
        return {
            "switch_ip": switch_ip,
            "switch_name": hit.get("switch_name"),
            "port": port,
            "description": description,
            "ip_candidates": ip_candidates,
            "model_hints": model_hints,
            "evidence": evidence,
        }

    def locate_mac_live(self, mac_value: str, opts: GlobalOptions, scope: str = "all", profile: bool = False) -> int:
        clean = norm_mac(mac_value)
        if not clean:
            return self.usage_error("lookup", "mac-locate", opts, "MAC must be a valid physical unicast address.", "netops lookup mac locate 0200.0000.0025", VALIDATION)
        dotted = self.canonical_mac(clean, "dotted")
        if scope and not is_all_keyword(scope):
            row, choices = self.resolve_device_record(scope)
            if not row:
                labels = ", ".join(str(item.get("hostname") or item.get("ip")) for item in choices[:8])
                return self.usage_error("lookup", "mac-locate", opts, f"Switch scope could not be resolved uniquely: {scope}" + (f" ({labels})" if labels else ""), "netops inventory list <switch>", VALIDATION)
            targets = [row]
        else:
            targets = self.current_switch_targets(opts, opts.site)
        if opts.dry_run:
            rows = [{"switch": row.get("hostname") or row.get("ip"), "ip": row.get("ip"), "command": shlex.join(self.legacy_cmd("netops-control", "mac-lookup", str(row.get("ip")), dotted))} for row in targets]
            self.emit({"ok": True, "dry_run": True, "mac": dotted, "scope": scope, "targets": rows, "count": len(rows)}, opts, self.render_table(rows, ["switch", "ip", "command"]))
            return SUCCESS
        if not targets:
            self.emit({"ok": False, "mac": dotted, "rows": [], "error": "no current online switch targets matched"}, opts, "No current online switch targets matched.")
            return PARTIAL

        self.live_log("mac", f"locating {dotted} across {len(targets)} switch(es)")
        core_output = ""
        core_ip = str(self.config.public.get("core_switch_ip") or "").strip()
        if core_ip:
            self.live_log("mac", f"query core ARP/MAC evidence on {core_ip}")
            core_rc, core_stdout, core_stderr = self.capture(self.legacy_cmd("netops-control", "core-lookup", self.canonical_mac(clean, "colon")), opts.timeout or 120)
            core_output = (core_stdout or "") + (core_stderr or "")
            with contextlib.suppress(Exception):
                self.state.record_core_lookup(dotted, core_output, core_rc)

        hits: List[Dict[str, Any]] = []
        errors: List[Dict[str, Any]] = []
        observed = now()
        for index, row in enumerate(targets, 1):
            switch_ip = str(row.get("ip") or "")
            switch_name = clean_display_name(row.get("hostname") or switch_ip)
            rc, stdout, stderr = self.capture(self.legacy_cmd("netops-control", "mac-lookup", switch_ip, dotted), opts.timeout or 120)
            raw = (stdout or "") + (stderr or "")
            parsed_hits = parse_mac_table_output(raw, clean)
            if rc != 0:
                errors.append({"switch_name": switch_name, "switch_ip": switch_ip, "exit_code": rc, "error": " ".join(clean_network_output(raw).split())[:240]})
            neighbors = self.cached_switch_neighbors(row)
            for parsed in parsed_hits:
                neighbor = self._neighbor_on_port(neighbors, str(parsed.get("port") or ""))
                item = {
                    **parsed,
                    "switch_ip": switch_ip,
                    "switch_name": switch_name,
                    "platform": row.get("platform") or "Unknown",
                    "role": "switch-link" if neighbor else "edge-candidate",
                    "neighbor_name": (neighbor or {}).get("remote_name") or "",
                    "neighbor_ip": (neighbor or {}).get("remote_ip") or "",
                    "observed_at": observed,
                    "observed_at_iso": fmt_time(observed),
                }
                hits.append(item)
                with contextlib.suppress(Exception):
                    self.state.record_mac_observation(clean, switch_ip, switch_name, str(item.get("port") or ""), str(item.get("vlan") or ""), str(item.get("entry_type") or ""))
                self.live_log("mac", f"hit {switch_name} {item.get('port')} VLAN {item.get('vlan') or '?'} role={item['role']}")
            if index == len(targets) or index % 10 == 0:
                self.live_log("mac", f"checked {index}/{len(targets)} switch(es); hits={len(hits)} errors={len(errors)}")

        profiles: List[Dict[str, Any]] = []
        if profile:
            edge_hits = [row for row in hits if row.get("role") == "edge-candidate"][:3]
            for hit in edge_hits:
                self.live_log("mac", f"profile likely edge {hit.get('switch_name')} {hit.get('port')}")
                profiles.append(self.profile_mac_port(hit, opts))
        ip_candidates = extract_ip_candidates(core_output)
        model_hints: List[str] = []
        oui = lookup_oui(clean)
        if oui.get("vendor") and oui.get("vendor") != "Unknown":
            model_hints.append(str(oui["vendor"]))
        for profile_row in profiles:
            for ip in profile_row.get("ip_candidates") or []:
                if ip not in ip_candidates:
                    ip_candidates.append(ip)
            for hint in profile_row.get("model_hints") or []:
                if hint not in model_hints:
                    model_hints.append(hint)
        cached = self.mac_cached_payload(clean, opts.limit)
        for ip in cached.get("ip_candidates") or []:
            if ip not in ip_candidates:
                ip_candidates.append(ip)
        for hint in cached.get("model_hints") or []:
            if hint not in model_hints:
                model_hints.append(hint)
        edge_hits = [row for row in hits if row.get("role") == "edge-candidate"]
        if hits and not ip_candidates:
            assessment = "The MAC is present in switch forwarding tables, but no IP evidence was found. It may be connected without DHCP/static IP; CAM aging means this is not proof of continuous power."
        elif hits and ip_candidates:
            assessment = "Direct forwarding-table evidence and one or more IP correlations were found."
        else:
            assessment = "No forwarding-table hit was found in the scanned scope. The endpoint may be offline, silent, aged out, outside the scope, or using another MAC."
        payload = {
            "ok": bool(hits),
            "mode": "mac-profile" if profile else "mac-locate",
            "mac": dotted,
            "scope": scope,
            "oui": oui,
            "hits": hits,
            "likely_edge_locations": edge_hits,
            "profiles": profiles,
            "ip_candidates": ip_candidates,
            "model_hints": model_hints,
            "layer2_present": bool(hits),
            "ip_evidence_present": bool(ip_candidates),
            "assessment": assessment,
            "errors": errors,
            "counts": {"switches_checked": len(targets), "hits": len(hits), "edge_candidates": len(edge_hits), "errors": len(errors)},
            "observed_at": observed,
            "observed_at_iso": fmt_time(observed),
            "limitations": cached.get("limitations") or [],
        }
        table = self.render_table(hits, ["role", "switch_name", "switch_ip", "vlan", "port", "entry_type", "neighbor_name", "observed_at"])
        profile_text = ""
        if profiles:
            profile_text = "\n\nEdge profile\n" + self.render_table(profiles, ["switch_name", "switch_ip", "port", "description", "ip_candidates", "model_hints"])
        text = (
            f"MAC {'profile' if profile else 'location'}: {dotted}\n"
            f"Checked: {len(targets)} | Hits: {len(hits)} | Likely edges: {len(edge_hits)} | Errors: {len(errors)}\n"
            f"IP evidence: {', '.join(ip_candidates) or 'none'} | Vendor: {oui.get('vendor') or 'Unknown'}\n"
            f"Assessment: {assessment}\n\nForwarding-table evidence\n{table}{profile_text}"
        )
        self.emit(payload, opts, text)
        return SUCCESS if hits else PARTIAL

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
        rows = reconcile_ap_rows(self.state.rows("SELECT * FROM aps"))
        if pattern and not is_all_keyword(pattern):
            rows = [row for row in rows if ap_rows_match(row, pattern)]
        if opts.status:
            rows = [row for row in rows if norm_status(row.get("status")) == opts.status]
        if opts.site:
            rows = [row for row in rows if opts.site.lower() in json.dumps(row, default=str).lower()]
        return rows[:opts.limit]

    def ask_payload(self, question: str, opts: GlobalOptions, session: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return self.natural_ask.ask(question, opts, session=session)

    def format_ask_text(self, payload: Dict[str, Any]) -> str:
        answer = str(payload.get("answer") or payload.get("error") or "No deterministic answer.")
        plan = payload.get("command_plan") if isinstance(payload.get("command_plan"), dict) else {}
        if plan:
            answer += f"\nPlan: {plan.get('label') or plan.get('action')} [{plan.get('status')}]"
            if plan.get("command"):
                answer += f"\nPreview: {plan['command']}"
            if plan.get("missing_args"):
                answer += "\nNeeds: " + ", ".join(str(item) for item in plan["missing_args"])
            if plan.get("execution_hint"):
                answer += f"\nExecute: {plan['execution_hint']}"
        choices = payload.get("choices") or []
        if choices:
            labels = [str(item.get("name") or item.get("ip") or item) if isinstance(item, dict) else str(item) for item in choices[:12]]
            answer += "\nChoices: " + ", ".join(labels)
        suggestions = payload.get("suggestions") or []
        if suggestions and (not payload.get("ok") or plan):
            answer += "\nTry: " + " | ".join(str(item) for item in suggestions[:4])
        return answer

    def execute_ask_plan(self, payload: Dict[str, Any], opts: GlobalOptions) -> int:
        plan = payload.get("command_plan") if isinstance(payload.get("command_plan"), dict) else None
        if not plan:
            self.emit({**payload, "ok": False, "error": "The question produced a retrieval answer, not an executable command plan."}, opts, self.format_ask_text(payload) + "\nNo command plan to execute.")
            return VALIDATION
        action = str(plan.get("action") or "")
        spec = self.command_spec(action)
        if not spec:
            self.emit({**payload, "ok": False, "error": f"Unknown planned action: {action}"}, opts, self.format_ask_text(payload))
            return VALIDATION
        missing = list(plan.get("missing_args") or [])
        if missing:
            self.emit({**payload, "ok": False, "error": "Command plan needs more information."}, opts, self.format_ask_text(payload))
            return VALIDATION
        if not spec.run_supported or spec.risk_level in {"config", "danger"}:
            self.emit({**payload, "ok": False, "error": plan.get("reason") or "This plan is preview-only."}, opts, self.format_ask_text(payload))
            return CONFIRM_REQUIRED
        if spec.effective_safety_class() != "read-only" and not opts.confirm:
            plan["execution_hint"] = f"netops ask --execute --confirm {shlex.quote(str(payload.get('question') or ''))}"
            self.emit({**payload, "ok": False, "error": "Active or state-changing plans require --confirm in addition to --execute."}, opts, self.format_ask_text(payload))
            return CONFIRM_REQUIRED
        try:
            cmd, _, _ = self.command_for_action(action, dict(plan.get("args") or {}))
        except (PermissionError, ValueError) as exc:
            self.emit({**payload, "ok": False, "error": str(exc)}, opts, self.format_ask_text(payload))
            return VALIDATION
        return self.run_interactive(cmd, opts) if spec.output_type == "terminal" else self.run_subprocess(cmd, opts)

    def cmd_ask_chat(self, opts: GlobalOptions) -> int:
        if opts.json:
            return self.usage_error("ask", "chat", opts, "Interactive Natural Ask is plain text only.", 'netops ask "question" --json', VALIDATION)
        session: Dict[str, Any] = {"history": []}
        interactive = sys.stdin.isatty()
        if interactive:
            print("NetOps Ask")
            print("Deterministic questions over current inventory and memory. /patterns lists examples; /exit leaves.")
        while True:
            try:
                question = input("ask> ").strip() if interactive else sys.stdin.readline().strip()
                if not question and not interactive:
                    break
            except KeyboardInterrupt:
                print("\nInterrupted.")
                return SUCCESS
            except EOFError:
                print("")
                return SUCCESS
            if not question:
                continue
            lower = question.lower()
            if lower in {"/exit", "/quit", "exit", "quit"}:
                break
            if lower in {"/patterns", "/help"}:
                examples = [example for item in QUESTION_PATTERNS for example in item["examples"]]
                print("\nanswer>\n" + "\n".join(f"  {example}" for example in examples))
                continue
            if lower == "/history":
                print("\nanswer>\n" + (json_dumps(session.get("history")) if session.get("history") else "No session history."))
                continue
            if lower == "/reset":
                session = {"history": []}
                print("\nanswer>\nSession context cleared.")
                continue
            if lower.startswith("/alias "):
                value = question[7:].strip()
                if "=" not in value:
                    print("\nanswer>\nUse: /alias phrase = target")
                    continue
                phrase, target = [part.strip() for part in value.split("=", 1)]
                payload = self.natural_ask.set_alias(phrase, target)
                print("\nanswer>\n" + (f"Alias saved: {phrase} -> {target}" if payload.get("ok") else str(payload.get("error"))))
                continue
            payload = self.ask_payload(question, opts, session=session)
            self.natural_ask.update_session(question, payload, session)
            print("\nanswer>\n" + self.format_ask_text(payload))
        return SUCCESS

    def cmd_ask(self, args: List[str], opts: GlobalOptions) -> int:
        if self.handle_help("ask", args, opts):
            return SUCCESS
        if not args:
            return self.cmd_ask_chat(opts)
        verb = args[0].lower()
        if verb == "patterns":
            payload = self.natural_ask.patterns_payload()
            rows = [{"intent": item["intent"], "purpose": item["purpose"], "examples": " | ".join(item["examples"])} for item in payload["patterns"]]
            self.emit(payload, opts, self.render_table(rows, ["intent", "purpose", "examples"]))
            return SUCCESS
        if verb == "aliases":
            rows = self.natural_ask.aliases()
            self.emit({"ok": True, "rows": rows, "count": len(rows)}, opts, self.render_table(rows, ["phrase", "target", "updated_at"]))
            return SUCCESS
        if verb == "alias":
            action = args[1].lower() if len(args) > 1 else ""
            if action == "set" and len(args) >= 4:
                payload = self.natural_ask.set_alias(args[2], " ".join(args[3:]))
                self.emit(payload, opts, f"Alias saved: {payload.get('phrase')} -> {payload.get('target')}" if payload.get("ok") else str(payload.get("error")))
                return SUCCESS if payload.get("ok") else VALIDATION
            if action in {"remove", "delete", "unset"} and len(args) >= 3:
                payload = self.natural_ask.remove_alias(" ".join(args[2:]))
                self.emit(payload, opts, f"Alias removed: {payload.get('removed', {}).get('phrase')}" if payload.get("ok") else str(payload.get("error")))
                return SUCCESS if payload.get("ok") else VALIDATION
            return self.usage_error("ask", "alias", opts, "Alias action requires set <phrase> <target> or remove <phrase>.", "netops ask alias set 'engineering office' 'engg ofc'", VALIDATION)
        question = " ".join(args).strip()
        payload = self.ask_payload(question, opts, session={"history": []})
        if opts.execute:
            return self.execute_ask_plan(payload, opts)
        self.emit(payload, opts, self.format_ask_text(payload))
        return SUCCESS if payload.get("ok") else VALIDATION
    def attention_payload(self, limit: int = 80) -> Dict[str, Any]:
        limit = clean_limit(limit, 80, 300)
        health = self.state.rows("SELECT entity_type,entity_id,name,platform,status,last_seen,last_failed,outage_started_at,flap_count,switch_ip,switch_port FROM health_state WHERE status='OFFLINE' OR flap_count>=3 OR (last_seen IS NOT NULL AND last_seen < strftime('%s','now') - 86400) ORDER BY status,flap_count DESC,last_seen LIMIT ?", (limit,))
        topology = self.state.rows("SELECT * FROM topology_events ORDER BY created_at DESC,id DESC LIMIT ?", (limit,))
        moves = self.state.rows("SELECT * FROM ap_move_events ORDER BY created_at DESC,id DESC LIMIT ?", (limit,))
        backups = self.state.rows("SELECT * FROM backup_history ORDER BY created_at DESC,id DESC LIMIT ?", (limit,))
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
        return {"ok": True, "items": items[:limit], "health": health, "topology_changes": topology, "ap_moves": moves, "backups": backups}


    def command_registry(self) -> List[CommandSpec]:
        tool = self.paths.tool
        return [
            CommandSpec("tui-open", "Operator console", [tool("netops"), "tui"], "Open the local full-screen operator console.", domain="tui", output_type="terminal", run_supported=False),
            CommandSpec("init-run", "Initialize profile", [tool("netops"), "init"], "Create neutral profile state and check host capabilities.", writes_local=True, domain="init", safety_class="local-write"),
            CommandSpec("profile-list", "List profiles", [tool("netops"), "profile", "list"], "List isolated NetOps profiles.", domain="profile", output_type="table"),
            CommandSpec("profile-show", "Show profile", [tool("netops"), "profile", "show", "<name>"], "Show profile paths and non-secret settings.", args=["name"], domain="profile", output_type="table"),
            CommandSpec("profile-create", "Create profile", [tool("netops"), "profile", "create", "<name>"], "Create a neutral isolated profile.", writes_local=True, args=["name"], domain="profile", safety_class="local-write"),
            CommandSpec("profile-use", "Select profile", [tool("netops"), "profile", "use", "<name>"], "Select the profile used by future commands.", writes_local=True, args=["name"], domain="profile", safety_class="local-write"),
            CommandSpec("profile-paths", "Profile paths", [tool("netops"), "profile", "paths"], "Show active profile XDG paths.", domain="profile", output_type="table"),
            CommandSpec("profile-migrate-legacy", "Migrate legacy profile", [tool("netops"), "profile", "migrate-legacy", "<name>"], "Copy legacy netsnmp state without deleting the source.", writes_local=True, args=["name"], domain="profile", safety_class="local-write"),
            CommandSpec("config-show", "Show configuration", [tool("netops"), "config", "show"], "Show effective redacted profile settings.", domain="config", output_type="table"),
            CommandSpec("config-get", "Get configuration", [tool("netops"), "config", "get", "<key>"], "Read one effective non-secret setting.", args=["key"], domain="config", output_type="text"),
            CommandSpec("config-set", "Set configuration", [tool("netops"), "config", "set", "<key>", "<value>"], "Set one non-secret profile override.", writes_local=True, args=["key", "value"], domain="config", safety_class="local-write"),
            CommandSpec("config-unset", "Unset configuration", [tool("netops"), "config", "unset", "<key>"], "Remove one profile override.", writes_local=True, args=["key"], domain="config", safety_class="local-write"),
            CommandSpec("config-validate", "Validate configuration", [tool("netops"), "config", "validate"], "Validate effective settings and legacy-secret state.", domain="config", output_type="table"),
            CommandSpec("config-paths", "Configuration paths", [tool("netops"), "config", "paths"], "Show global and profile configuration files.", domain="config", output_type="table"),
            CommandSpec("secrets-list", "List named secrets", [tool("netops"), "secrets", "list"], "List named secrets without values.", domain="secrets", output_type="table"),
            CommandSpec("secrets-status", "Named secret status", [tool("netops"), "secrets", "status"], "Show named-secret store security and lock state.", domain="secrets", output_type="table"),
            CommandSpec("secrets-set", "Set named secret", [tool("netops"), "secrets", "set", "<name>"], "Prompt for and encrypt one named secret.", read_only=False, writes_local=True, args=["name"], domain="secrets", output_type="terminal", run_supported=False, safety_class="local-write"),
            CommandSpec("secrets-delete", "Delete named secret", [tool("netops"), "secrets", "delete", "<name>", "--confirm"], "Delete one named secret after confirmation.", read_only=False, writes_local=True, args=["name"], domain="secrets", output_type="terminal", run_supported=False, safety_class="local-write"),
            CommandSpec("secrets-import-ssh", "Import SSH secret", [tool("netops"), "secrets", "import-ssh"], "Import the legacy SSH vault into ssh/default/password.", read_only=False, writes_local=True, domain="secrets", output_type="terminal", run_supported=False, safety_class="local-write"),
            CommandSpec("ingest-channels", "List ingest channels", [tool("netops"), "ingest", "channels"], "List declarative channels in the active profile.", writes_local=True, domain="ingest", output_type="table"),
            CommandSpec("ingest-validate", "Validate ingest channels", [tool("netops"), "ingest", "validate"], "Validate channel manifests without fetching records.", domain="ingest", output_type="table"),
            CommandSpec("ingest-run", "Run ingest channel", [tool("netops"), "ingest", "run", "<channel>"], "Run one provenance-preserving ingest channel.", writes_local=True, args=["channel"], domain="ingest", timeout_seconds=1800),
            CommandSpec("ingest-history", "Ingest history", [tool("netops"), "ingest", "history"], "Show ingest runs newest first.", domain="ingest", output_type="table"),
            CommandSpec("ingest-rejects", "Ingest rejects", [tool("netops"), "ingest", "rejects", "<run_id>"], "Show redacted quarantine metadata.", args=["run_id"], domain="ingest", output_type="table"),
            CommandSpec("ingest-observations", "Ingest observations", [tool("netops"), "ingest", "observations", "<channel>"], "Show append-only channel observations.", args=["channel"], domain="ingest", output_type="table"),
            CommandSpec("plugin-list", "List plugins", [tool("netops"), "plugin", "list"], "Discover plugins without importing disabled code.", domain="plugin", output_type="table"),
            CommandSpec("plugin-enable", "Enable plugin", [tool("netops"), "plugin", "enable", "<plugin_id>"], "Enable one trusted entry point in this profile.", writes_local=True, args=["plugin_id"], domain="plugin", safety_class="local-write"),
            CommandSpec("plugin-disable", "Disable plugin", [tool("netops"), "plugin", "disable", "<plugin_id>"], "Disable one plugin in this profile.", writes_local=True, args=["plugin_id"], domain="plugin", safety_class="local-write"),
            CommandSpec("plugin-check", "Check plugins", [tool("netops"), "plugin", "check", "<group>"], "Load enabled plugins and isolate failures.", args=["group"], domain="plugin", output_type="table"),
            CommandSpec("plugin-groups", "Plugin groups", [tool("netops"), "plugin", "groups"], "List stable entry-point groups and policy.", domain="plugin", output_type="table"),
            CommandSpec("path-inspect", "Inspect forwarding path", [tool("netops"), "path", "inspect", "<endpoint>", "--vlan", "<vlan>"], "Inspect a bounded L2/L3 endpoint path with cached and live read-only evidence.", writes_local=True, args=["endpoint", "vlan", "source", "destination", "depth", "max_nodes", "mode", "explain"], domain="path", safety_class="network-read", timeout_seconds=1800),
            CommandSpec("path-history", "Path history", [tool("netops"), "path", "history", "<endpoint>"], "Show chronological path inspections.", args=["endpoint"], domain="path", output_type="table"),
            CommandSpec("path-show", "Show path run", [tool("netops"), "path", "show", "<run_id>"], "Open one persisted path result.", args=["run_id"], domain="path", output_type="table"),
            CommandSpec("support-bundle", "Create support bundle", [tool("netops"), "support", "bundle"], "Create a redacted support archive without inventory, secrets, raw evidence, or backups.", writes_local=True, domain="support", output_type="table", safety_class="local-write"),
            CommandSpec("vault-status", "Vault status", [tool("netops"), "vault", "status"], "Show the SSH vault format, permissions, recording time, and non-prompting lock state.", domain="vault", output_type="table"),
            CommandSpec("vault-set", "Set vault password", [tool("netops"), "vault", "set"], "Store a new SSH password in the terminal sudo-gated GPG vault.", read_only=False, writes_local=True, domain="vault", output_type="terminal", risk_level="warning", run_supported=False, safety_class="local-write"),
            CommandSpec("vault-migrate", "Migrate vault", [tool("netops"), "vault", "migrate"], "Convert a legacy passphrase GPG vault to terminal sudo-gated GPG without exposing the SSH password.", read_only=False, writes_local=True, domain="vault", output_type="terminal", risk_level="warning", run_supported=False, safety_class="local-write"),
            CommandSpec("vault-unlock", "Unlock vault", [tool("netops"), "vault", "unlock"], "Authenticate through sudo and verify the encrypted SSH vault for the current sudo timeout.", read_only=False, writes_local=True, domain="vault", output_type="terminal", risk_level="warning", run_supported=False, safety_class="local-write"),
            CommandSpec("db-migrate", "Migrate database", [tool("netops"), "db", "migrate"], "Apply SQLite schema migrations and reconcile derived state.", writes_local=True, domain="db", safety_class="local-write"),
            CommandSpec("db-status", "Database status", [tool("netops"), "db", "status"], "Show database paths, schema version, file sizes, and record counts.", domain="db", output_type="table"),
            CommandSpec("db-path", "Database path", [tool("netops"), "db", "path"], "Print the active SQLite database path.", domain="db", output_type="text"),
            CommandSpec("db-integrity", "Database integrity", [tool("netops"), "db", "integrity"], "Run SQLite integrity checks without modifying state.", domain="db", output_type="table"),
            CommandSpec("db-repair", "Repair database", [tool("netops"), "db", "repair"], "Reindex and repair recoverable SQLite structures, then verify integrity.", writes_local=True, domain="db", safety_class="local-write"),
            CommandSpec("db-vacuum", "Vacuum database", [tool("netops"), "db", "vacuum"], "Compact the SQLite database.", writes_local=True, domain="db", safety_class="local-write"),
            CommandSpec("inventory-import-flat", "Import flat files", [tool("netops"), "inventory", "import-flat"], "Import legacy flat caches into SQLite.", writes_local=True, domain="inventory"),
            CommandSpec("inventory-export-flat", "Export flat files", [tool("netops"), "inventory", "export-flat"], "Export SQLite inventory back to legacy flat files.", writes_local=True, domain="inventory"),
            CommandSpec("inventory-scan", "Inventory scan", [tool("netops"), "inventory", "scan", "<target>"], "Refresh switch/router inventory.", writes_local=True, args=["target"], domain="inventory"),
            CommandSpec("inventory-list", "Inventory list", [tool("netops"), "inventory", "list", "<target>"], "Search current canonical device and AP inventory.", args=["target"], domain="inventory", output_type="table"),
            CommandSpec("inventory-show", "Inventory show", [tool("netops"), "inventory", "show", "<target>"], "Search current canonical inventory only.", args=["target"], domain="inventory", output_type="table"),
            CommandSpec("inventory-details", "Inventory details", [tool("netops"), "inventory", "details", "<target>"], "Collect detailed inventory for one target.", args=["target"], domain="inventory", output_type="table", safety_class="network-read"),
            CommandSpec("inventory-activity", "Inventory activity", [tool("netops"), "inventory", "activity", "<target>"], "Ping one or more inventory targets and report current activity.", args=["target"], domain="inventory", output_type="table", safety_class="network-read"),
            CommandSpec("inventory-merge", "Preview device identity merge", [tool("netops"), "inventory", "merge", "<source>", "<target>", "--reason", "<reason>", "--dry-run"], "Preview retiring an old device into a current device while preserving chronological evidence. Apply explicitly in the CLI with --confirm.", writes_local=False, args=["source", "target", "reason"], domain="inventory", risk_level="warning", run_supported=False, safety_class="read-only", arg_schema=[{"name":"source","label":"Historical Device","type":"text","required":True,"placeholder":"exact hostname or IP"},{"name":"target","label":"Current Device","type":"text","required":True,"placeholder":"exact hostname or IP"},{"name":"reason","label":"Audit Reason","type":"text","required":True,"placeholder":"approved replacement or correction"}]),
            CommandSpec("inventory-merges", "Manual identity merges", [tool("netops"), "inventory", "merges"], "List active manual device merges and their chronology.", domain="inventory", output_type="table"),
            CommandSpec("inventory-unmerge", "Plan device merge revocation", [tool("netops"), "inventory", "unmerge", "<merge_id>", "--reason", "<reason>"], "Prepare restoration of a manually retired source device. Apply explicitly in the CLI with --confirm.", writes_local=False, args=["merge_id", "reason"], domain="inventory", risk_level="warning", run_supported=False, safety_class="read-only", arg_schema=[{"name":"merge_id","label":"Merge ID","type":"text","required":True},{"name":"reason","label":"Revocation Reason","type":"text","required":True}]),
            CommandSpec("health-check", "Fast health check", [tool("netops"), "health", "check", "<target>"], "Ping known/supplied devices and APs, then refresh health state.", writes_local=True, args=["target"], domain="health"),
            CommandSpec("health-status", "Health status", [tool("netops"), "health", "status", "<target>"], "Read current canonical health, optionally filtered by target.", args=["target"], domain="health", output_type="table"),
            CommandSpec("health-offline", "Offline health records", [tool("netops"), "health", "offline", "<target>"], "List current offline entities, optionally filtered by target.", args=["target"], domain="health", output_type="table"),
            CommandSpec("health-attention", "Health attention", [tool("netops"), "health", "attention"], "Show health, topology, AP movement, and backup items needing review.", domain="health", output_type="table"),
            CommandSpec("health-timeline", "Health timeline", [tool("netops"), "health", "timeline", "<target>"], "Read health state changes newest first.", args=["target"], domain="health", output_type="table"),
            CommandSpec("ap-scan", "AP scan", [tool("netops"), "ap", "scan"], "Refresh AP inventory.", writes_local=True, domain="ap"),
            CommandSpec("ap-list", "AP list", [tool("netops"), "ap", "list", "<target>"], "Search current reconciled AP inventory.", args=["target"], domain="ap", output_type="table"),
            CommandSpec("ap-unjoined", "Unjoined APs", [tool("netops"), "ap", "unjoined", "<target>"], "List AP observations that are not joined to a controller.", args=["target"], domain="ap", output_type="table"),
            CommandSpec("ap-on-switch", "APs on switch", [tool("netops"), "ap", "on-switch", "<target>"], "Show canonical APs attached to a switch or site.", args=["target"], domain="ap", output_type="table"),
            CommandSpec("ap-moves", "AP moves", [tool("netops"), "ap", "moves"], "Show recorded AP attachment changes newest first.", domain="ap", output_type="table"),
            CommandSpec("ap-timeline", "AP timeline", [tool("netops"), "ap", "timeline", "<target>"], "Show AP attachment history newest first.", args=["target"], domain="ap", output_type="table"),
            CommandSpec("topology-scan", "Topology scan", [tool("netops"), "topology", "scan"], "Refresh LLDP/CDP topology.", writes_local=True, domain="topology"),
            CommandSpec("topology-show", "Topology show", [tool("netops"), "topology", "show", "<target>"], "Show topology, optionally querying one target.", args=["target"], domain="topology", output_type="table", safety_class="network-read"),
            CommandSpec("topology-neighbors", "Topology neighbors", [tool("netops"), "topology", "neighbors", "<target>"], "Show cached topology neighbor rows or query one target.", args=["target"], domain="topology", output_type="table", safety_class="network-read"),
            CommandSpec("topology-changes", "Topology changes", [tool("netops"), "topology", "changes"], "Show recorded topology changes newest first.", domain="topology", output_type="table"),
            CommandSpec("topology-timeline", "Topology timeline", [tool("netops"), "topology", "timeline", "<target>"], "Show neighbor-link history newest first.", args=["target"], domain="topology", output_type="table"),
            CommandSpec("memory-refresh", "Memory refresh", [tool("netops"), "memory", "refresh"], "Recompute relationship memory from canonical state.", writes_local=True, domain="memory"),
            CommandSpec("memory-switch", "Memory switch", [tool("netops"), "memory", "switch", "<target>"], "Show APs, neighbors, relationships, and timeline for a switch/site.", args=["target"], domain="memory", output_type="table"),
            CommandSpec("memory-device", "Memory device", [tool("netops"), "memory", "device", "<target>"], "Show current identity relationships and history for a device.", args=["target"], domain="memory", output_type="table"),
            CommandSpec("memory-ip", "Memory IP", [tool("netops"), "memory", "ip", "<target>"], "Show historical ownership and relationship events for an IP.", args=["target"], domain="memory", output_type="table"),
            CommandSpec("memory-mac", "Memory MAC", [tool("netops"), "memory", "mac", "<target>"], "Show identity and movement history for a MAC address.", args=["target"], domain="memory", output_type="table"),
            CommandSpec("memory-port", "Memory port", [tool("netops"), "memory", "port", "<target>", "<interface>"], "Show current and historical occupancy for a switch port.", args=["target", "interface"], domain="memory", output_type="table"),
            CommandSpec("memory-timeline", "Memory timeline", [tool("netops"), "memory", "timeline", "<target>"], "Search all relationship events newest first.", args=["target"], domain="memory", output_type="table"),
            CommandSpec("memory-explain", "Explain memory sources", [tool("netops"), "memory", "explain", "<target>"], "Explain relationship sources, confidence, and last observations.", args=["target"], domain="memory", output_type="table"),
            CommandSpec("memory-export", "Export memory", [tool("netops"), "memory", "export", "--json"], "Export all current relationships as JSON.", domain="memory", output_type="json"),
            CommandSpec("memory-prune", "Prune memory", [tool("netops"), "memory", "prune"], "Memory pruning is intentionally disabled because history is retained by default.", read_only=False, writes_local=True, domain="memory", risk_level="danger", run_supported=False),
            CommandSpec("ask-query", "Natural Ask", [tool("netops"), "ask", "<question>"], "Run a deterministic question workflow over current inventory and relationship memory.", args=["question"], domain="ask", output_type="table", examples=['netops ask "How many APs are offline in ZONE10?"']),
            CommandSpec("ask-chat", "Ask chat", [tool("netops"), "ask"], "Open the stateful Natural Ask terminal session.", domain="ask", output_type="terminal", run_supported=False),
            CommandSpec("ask-patterns", "Ask patterns", [tool("netops"), "ask", "patterns"], "List supported retrieval and command-center examples.", domain="ask", output_type="table"),
            CommandSpec("ask-aliases", "Ask aliases", [tool("netops"), "ask", "aliases"], "List deterministic phrase aliases.", domain="ask", output_type="table"),
            CommandSpec("ask-alias-set", "Set Ask alias", [tool("netops"), "ask", "alias", "set", "<phrase>", "<alias_target>"], "Create or update a durable deterministic phrase alias.", writes_local=True, args=["phrase", "alias_target"], domain="ask", safety_class="local-write"),
            CommandSpec("ask-alias-remove", "Remove Ask alias", [tool("netops"), "ask", "alias", "remove", "<phrase>"], "Remove a durable deterministic phrase alias.", writes_local=True, args=["phrase"], domain="ask", safety_class="local-write"),
            CommandSpec("backup-run", "Backup online", [tool("netops"), "backup", "run", "<target>"], "Online-only changed-only config backup.", writes_local=True, args=["target"], domain="backup"),
            CommandSpec("backup-history", "Backup history", [tool("netops"), "backup", "history", "<target>"], "Show backup history for a target.", args=["target"], domain="backup"),
            CommandSpec("backup-diff", "Backup diff", [tool("netops"), "backup", "diff", "<target>"], "Diff latest changed backups for a target.", args=["target"], domain="backup"),
            CommandSpec("backup-verify", "Verify backups", [tool("netops"), "backup", "verify"], "Review recorded backup checksums, paths, and statuses.", domain="backup", output_type="table"),
            CommandSpec("diagnose-latency", "Latency probe", [tool("netops"), "diagnose", "latency", "<target>"], "Run latency probing.", writes_local=True, args=["target", "count"], domain="diagnose"),
            CommandSpec("diagnose-core-ping", "Point-of-truth core ping", [tool("netops"), "diagnose", "core-ping", "<target>"], "Issue ICMP from the configured/selected core switch and store parsed latency.", writes_local=True, args=["target", "core", "count"], domain="diagnose", examples=["netops diagnose core-ping 192.0.2.50 --count 5"]),
            CommandSpec("diagnose-speed", "Internet speed test", [tool("netops"), "diagnose", "speed"], "Measure this NetOps host's routed Internet path with verified profile-based testing.", writes_local=True, args=["profile", "runs", "ca_file"], domain="diagnose", timeout_seconds=1800),
            CommandSpec("diagnose-throughput", "Controlled throughput", [tool("netops"), "diagnose", "throughput", "<target>"], "Measure TCP receiver goodput between this client and a controlled iperf3 server.", writes_local=True, args=["target", "port", "seconds", "parallel", "direction", "bind"], domain="diagnose", timeout_seconds=720),
            CommandSpec("diagnose-port-health", "Port health", [tool("netops"), "diagnose", "port-health", "<device>", "on", "<interface>"], "Sample link negotiation and switch error-counter deltas.", writes_local=True, args=["device", "interface", "sample_seconds", "expected_speed"], domain="diagnose", safety_class="network-read", timeout_seconds=240),
            CommandSpec("diagnose-cable", "Cable diagnostic status", [tool("netops"), "diagnose", "cable", "<device>", "on", "<interface>"], "Read the last recorded copper cable/TDR result without starting a test.", writes_local=True, args=["device", "interface"], domain="diagnose", safety_class="network-read", timeout_seconds=180),
            CommandSpec("diagnose-cable-test", "Start cable diagnostic", [tool("netops"), "diagnose", "cable", "<device>", "on", "<interface>", "--test", "--dry-run"], "Preview a potentially disruptive copper TDR. Confirmed execution remains CLI-only.", read_only=False, writes_local=True, args=["device", "interface", "wait"], domain="diagnose", risk_level="danger", run_supported=False, safety_class="disruptive"),
            CommandSpec("diagnose-doctor", "Diagnostic readiness", [tool("netops"), "diagnose", "doctor"], "Audit diagnostic dependencies, routing, host limitations, trust, and core settings.", writes_local=True, args=["online"], domain="diagnose"),
            CommandSpec("diagnose-filtering", "Filtering check", [tool("netops"), "diagnose", "filtering", "<target>"], "DNS/TLS/filtering diagnostics.", writes_local=True, args=["target"], domain="diagnose"),
            CommandSpec("diagnose-interface", "Interface monitor", [tool("netops"), "diagnose", "interface", "<device>", "on", "<interface>"], "Legacy interface rate monitor; command-center jobs default to one finite sample.", writes_local=True, args=["device", "interface", "chart", "once"], domain="diagnose"),
            CommandSpec("lookup-core", "Core lookup", [tool("netops"), "lookup", "core", "<target>"], "Core IP/MAC lookup cached into memory.", writes_local=True, args=["target"], domain="lookup"),
            CommandSpec("lookup-mac", "MAC lookup", [tool("netops"), "lookup", "mac", "<target>", "<mac>"], "MAC lookup from one target or from all current switches with target=all.", writes_local=True, args=["target", "mac"], domain="lookup", timeout_seconds=120),
            CommandSpec("lookup-mac-inspect", "MAC evidence inspection", [tool("netops"), "lookup", "mac", "inspect", "<mac>"], "Correlate cached MAC identity, location, IP, vendor, and history evidence.", args=["mac"], domain="lookup", output_type="table"),
            CommandSpec("lookup-mac-locate", "Direct MAC location", [tool("netops"), "lookup", "mac", "locate", "<mac>"], "Search switch forwarding tables without requiring an endpoint IP.", writes_local=True, args=["mac", "scope"], domain="lookup", timeout_seconds=0),
            CommandSpec("lookup-mac-profile", "MAC edge profile", [tool("netops"), "lookup", "mac", "profile", "<mac>"], "Locate a MAC and profile likely edge ports with interface, LLDP/CDP, PoE, device-tracking, and core evidence.", writes_local=True, args=["mac", "scope"], domain="lookup", timeout_seconds=0),
            CommandSpec("lookup-mac-history", "MAC movement history", [tool("netops"), "lookup", "mac", "history", "<mac>"], "Show newest-first identity and switch-port events for a MAC.", args=["mac"], domain="lookup", output_type="table"),
            CommandSpec("lookup-mac-vendor", "MAC OUI vendor", [tool("netops"), "lookup", "mac", "vendor", "<mac>"], "Resolve a MAC prefix from the locally installed OUI database.", args=["mac"], domain="lookup", output_type="text"),
            CommandSpec("lookup-mac-online", "IEEE MAC assignment", [tool("netops"), "lookup", "mac", "online", "<mac>"], "Resolve the longest authoritative IEEE MA-L/MA-M/MA-S assignment with cache provenance.", writes_local=True, args=["mac"], domain="lookup", output_type="table", safety_class="network-read"),
            CommandSpec("lookup-mac-registry", "IEEE MAC registry status", [tool("netops"), "lookup", "mac", "registry", "status"], "Show cached IEEE registry files, row counts, checksums, sources, and last refresh time.", domain="lookup", output_type="table"),
            CommandSpec("lookup-mac-registry-refresh", "Refresh IEEE MAC registry", [tool("netops"), "lookup", "mac", "registry", "refresh"], "Refresh all IEEE public MAC assignment CSV registries into the private local cache.", writes_local=True, domain="lookup", output_type="table", safety_class="network-read"),
            CommandSpec("device-show", "Device show", [tool("netops"), "device", "show", "<target>", "<command>"], "Run a policy-checked read-only show command.", args=["target", "command"], domain="device", safety_class="network-read"),
            CommandSpec("device-ssh", "Device SSH", [tool("netops"), "device", "ssh", "<target>"], "Open an interactive SSH session in a terminal.", args=["target"], domain="device", output_type="terminal", run_supported=False),
            CommandSpec("device-inventory", "Device inventory", [tool("netops"), "device", "inventory", "<target>"], "Run the device inventory helper for one target.", args=["target"], domain="device", safety_class="network-read"),
            CommandSpec("device-support", "Device support profile", [tool("netops"), "device", "support", "<target>"], "Classify a device and show driver capability maturity for Cisco, Aruba, or Ruckus.", args=["target"], domain="device", output_type="table"),
            CommandSpec("device-identity", "Device identity comparison", [tool("netops"), "device", "identity", "<target>", "<target2>"], "Explain confidence and conflicts between two switch identity records.", args=["target", "target2"], domain="device", output_type="table"),
            CommandSpec("device-trust-status", "SSH trust status", [tool("netops"), "device", "trust", "status", "<target>"], "Inspect managed SSH host-key fingerprints without network access.", args=["target"], domain="device", output_type="table"),
            CommandSpec("device-trust-scan", "Scan SSH host keys", [tool("netops"), "device", "trust", "scan", "<target>"], "Retrieve SSH host keys and SHA-256 fingerprints without enrolling them.", args=["target"], domain="device", output_type="table", safety_class="network-read"),
            CommandSpec("device-trust-enroll", "Enroll SSH host key", [tool("netops"), "device", "trust", "enroll", "<target>", "--fingerprint", "<fingerprint>", "--confirm"], "Enroll only an out-of-band verified SSH host-key fingerprint.", writes_local=True, args=["target", "fingerprint"], domain="device", output_type="table", safety_class="local-write"),
            CommandSpec("device-trust-forget", "Forget SSH host key", [tool("netops"), "device", "trust", "forget", "<target>", "--confirm"], "Remove a target from the managed SSH trust store.", writes_local=True, args=["target"], domain="device", output_type="table", safety_class="local-write"),
            CommandSpec("workflow-morning-check", "Morning check", [tool("netops"), "workflow", "morning-check"], "Health, memory, topology, filtering, and attention summary.", writes_local=True, domain="workflow"),
            CommandSpec("workflow-refresh-inventory", "Refresh inventory", [tool("netops"), "workflow", "refresh-inventory"], "Health, AP, topology, and memory refresh.", writes_local=True, domain="workflow"),
            CommandSpec("workflow-backup-online", "Backup online workflow", [tool("netops"), "workflow", "backup-online", "<target>"], "Changed-only backups for online devices.", writes_local=True, args=["target"], domain="workflow"),
            CommandSpec("workflow-site-health", "Site health", [tool("netops"), "workflow", "site-health", "<target>"], "Latency and filtering checks for a target/site.", writes_local=True, args=["target"], domain="workflow"),
            CommandSpec("workflow-ap-audit", "AP audit", [tool("netops"), "workflow", "ap-audit"], "Refresh AP records and show AP moves.", writes_local=True, domain="workflow"),
            CommandSpec("vlan-locate", "Locate VLAN", [tool("netops"), "vlan", "locate", "<target>", "<vlan>"], "Locate one or many VLANs from one or many roots; optional depth traverses LLDP/CDP-confirmed switch links.", args=["target", "vlan", "depth", "max_nodes", "refresh_neighbors"], domain="vlan", safety_class="network-read"),
            CommandSpec("vlan-propagation", "VLAN propagation", [tool("netops"), "vlan", "propagation", "<target>", "<vlan>"], "Trace a root-by-VLAN matrix with bounded breadth-first switch traversal.", args=["target", "vlan", "depth", "max_nodes", "refresh_neighbors"], domain="vlan", safety_class="network-read"),
            CommandSpec("jobs-list", "Jobs list", [tool("netops"), "jobs", "list"], "List recorded jobs newest first.", domain="jobs", output_type="table"),
            CommandSpec("jobs-show", "Job details", [tool("netops"), "jobs", "show", "<job_id>"], "Show one recorded job and its logs.", args=["job_id"], domain="jobs", output_type="table"),
            CommandSpec("jobs-logs", "Job logs", [tool("netops"), "jobs", "logs", "<job_id>"], "Show logs for one recorded job.", args=["job_id"], domain="jobs", output_type="table"),
            CommandSpec("jobs-cancel", "Cancel job", [tool("netops"), "jobs", "cancel", "<job_id>"], "Cancel a live job through the process that owns it.", args=["job_id"], domain="jobs", risk_level="warning", run_supported=False),
            CommandSpec("commands-list", "Commands list", [tool("netops"), "commands", "list"], "List the structured command registry and safety metadata.", domain="commands", output_type="table"),
            CommandSpec("commands-show", "Command details", [tool("netops"), "commands", "show", "<action>"], "Show metadata for one registry action.", args=["action"], domain="commands", output_type="table"),
            CommandSpec("commands-run", "Registry command runner", [tool("netops"), "commands", "run", "<action>", "--preview"], "Meta-action for previewing a registry command. Ask plans the selected action directly.", args=["action"], domain="commands", run_supported=False),
            CommandSpec("device-config", "Device config preview", [tool("netops"), "device", "config", "<target>", "<commands>"], "Preview/confirmed config command wrapper. WebUI preview only.", read_only=False, writes_local=True, args=["target", "commands"], domain="device", risk_level="config", run_supported=False),
            CommandSpec(
                "vlan-set", "Guarded VLAN change", [tool("netops"), "vlan", "set", "<target>", "<interface>", "<vlan_mode>", "<vlan>"],
                "Back up, apply, and verify one typed access or trunk VLAN change through the audited core.",
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
            CommandSpec("serve-run", "Start API server", [tool("netops"), "serve"], "Start the loopback API and WebUI server.", domain="serve", output_type="terminal", run_supported=False),
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
            "inventory-scan": {"target"}, "inventory-list": {"target"}, "inventory-show": {"target"},
            "health-check": {"target"}, "health-status": {"target"}, "health-offline": {"target"}, "health-timeline": {"target"},
            "ap-list": {"target"}, "ap-unjoined": {"target"}, "ap-timeline": {"target"},
            "topology-show": {"target"}, "topology-neighbors": {"target"}, "topology-timeline": {"target"},
            "memory-timeline": {"target"}, "memory-explain": {"target"},
            "diagnose-latency": {"count"}, "diagnose-speed": {"runs", "profile"}, "diagnose-filtering": {"target"},
            "diagnose-core-ping": {"core", "count"}, "diagnose-interface": {"chart"}, "lookup-mac": {"target"},
            "lookup-mac-locate": {"scope"}, "lookup-mac-profile": {"scope"},
            "vlan-locate": {"depth", "max_nodes", "refresh_neighbors"},
            "vlan-propagation": {"depth", "max_nodes", "refresh_neighbors"},
            "device-trust-status": {"target"},
            "profile-show": {"name"}, "profile-migrate-legacy": {"name"},
            "ingest-rejects": {"run_id"}, "ingest-observations": {"channel"},
            "plugin-check": {"group"}, "path-history": {"endpoint"},
            "path-inspect": {"source", "destination", "depth", "max_nodes", "mode", "explain"},
        }.get(spec.id, set())
        return [field["name"] for field in spec.inferred_arg_schema() if field.get("required") and field["name"] not in optional]

    def _template_command(self, spec: CommandSpec, args: Dict[str, Any]) -> List[str]:
        if spec.id == "vlan-set":
            target = str(args.get("target") or "<target>").strip()
            interface = str(args.get("interface") or args.get("port") or "<interface>").strip()
            mode = str(args.get("vlan_mode") or args.get("mode") or "access").strip().lower()
            vlan = str(args.get("vlan") or "<vlan>").strip()
            return [self.paths.tool("netops"), "vlan", "set", target, interface, f"--{mode}", vlan, "--dry-run"]
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

    def preview_hash_for_action(self, action: str, args: Dict[str, Any], preview: Optional[Dict[str, Any]]=None) -> str:
        payload = preview or self.preview_for_action(action, args)
        targets = [
            str(args.get(name)).strip()
            for name in ("target", "device", "core", "scope", "interface", "mac")
            if args.get(name) not in (None, "", [])
        ]
        canonical = json.dumps(
            {"action": action, "args": dict(args), "command": payload.get("command"), "targets": targets},
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def command_for_action(self, action: str, args: Dict[str, Any]) -> Tuple[List[str], bool, bool]:
        args = args or {}
        action = self.command_aliases().get(str(action or ""), str(action or ""))
        tool = self.paths.tool
        target = normalize_target_literal(str(args.get("target") or args.get("query") or "").strip())
        simple: Dict[str, List[str]] = {
            "db-migrate": ["db", "migrate"], "db-status": ["db", "status"], "db-path": ["db", "path"],
            "db-integrity": ["db", "integrity"], "db-repair": ["db", "repair"], "db-vacuum": ["db", "vacuum"],
            "health-attention": ["health", "attention"], "ap-moves": ["ap", "moves"],
            "topology-changes": ["topology", "changes"], "memory-export": ["memory", "export", "--json"],
            "ask-patterns": ["ask", "patterns"], "ask-aliases": ["ask", "aliases"],
            "backup-verify": ["backup", "verify"], "jobs-list": ["jobs", "list"], "commands-list": ["commands", "list"],
            "init-run": ["init"], "profile-list": ["profile", "list"], "profile-paths": ["profile", "paths"],
            "config-show": ["config", "show"], "config-validate": ["config", "validate"], "config-paths": ["config", "paths"],
            "secrets-list": ["secrets", "list"], "secrets-status": ["secrets", "status"],
            "ingest-channels": ["ingest", "channels"], "ingest-validate": ["ingest", "validate"], "ingest-history": ["ingest", "history"],
            "plugin-list": ["plugin", "list"], "plugin-groups": ["plugin", "groups"],
            "support-bundle": ["support", "bundle"], "inventory-merges": ["inventory", "merges"],
            "vault-status": ["vault", "status"],
            "lookup-mac-registry": ["lookup", "mac", "registry", "status"],
            "lookup-mac-registry-refresh": ["lookup", "mac", "registry", "refresh"],
        }
        if action in simple:
            return [tool("netops"), *simple[action]], True, action in {"db-migrate", "db-repair", "db-vacuum", "init-run", "ingest-channels", "support-bundle", "lookup-mac-registry-refresh"}
        if action in {"profile-show", "profile-create", "profile-use", "profile-migrate-legacy"}:
            name = str(args.get("name") or "").strip()
            verb = action.removeprefix("profile-")
            command = [tool("netops"), "profile", verb]
            if name: command.append(name)
            return command, True, action in {"profile-create", "profile-use", "profile-migrate-legacy"}
        if action in {"config-get", "config-set", "config-unset"}:
            key = str(args.get("key") or "").strip()
            if not key: raise ValueError(f"{action} requires key")
            command = [tool("netops"), "config", action.removeprefix("config-"), key]
            if action == "config-set":
                value = str(args.get("value") or "")
                if not value: raise ValueError("config-set requires value")
                command.append(value)
            return command, True, action != "config-get"
        if action == "ingest-run":
            channel = str(args.get("channel") or "").strip()
            if not channel: raise ValueError("ingest-run requires channel")
            return [tool("netops"), "ingest", "run", channel], True, True
        if action in {"ingest-rejects", "ingest-observations"}:
            value = str(args.get("run_id") or args.get("channel") or "").strip()
            return [tool("netops"), "ingest", action.removeprefix("ingest-")] + ([value] if value else []), True, False
        if action in {"plugin-enable", "plugin-disable"}:
            plugin_id = str(args.get("plugin_id") or "").strip()
            if not plugin_id: raise ValueError(f"{action} requires plugin_id")
            return [tool("netops"), "plugin", action.removeprefix("plugin-"), plugin_id], True, True
        if action == "plugin-check":
            group = str(args.get("group") or "").strip()
            return [tool("netops"), "plugin", "check"] + ([group] if group else []), True, False
        if action == "path-history":
            endpoint = str(args.get("endpoint") or "").strip()
            return [tool("netops"), "path", "history"] + ([endpoint] if endpoint else []), True, False
        if action == "path-show":
            run_id = str(args.get("run_id") or "").strip()
            if not run_id: raise ValueError("path-show requires run_id")
            return [tool("netops"), "path", "show", run_id], True, False
        if action == "path-inspect":
            endpoint = str(args.get("endpoint") or args.get("target") or "").strip()
            vlan = str(args.get("vlan") or "").strip()
            if not endpoint or not vlan: raise ValueError("path-inspect requires endpoint and vlan")
            if not vlan.isdigit() or not 1 <= int(vlan) <= 4094:
                raise ValueError("vlan must be between 1 and 4094")
            command = [tool("netops"), "path", "inspect", endpoint, "--vlan", vlan]
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
        if action == "inventory-import-flat": return [tool("netops"), "inventory", "import-flat"], True, True
        if action == "inventory-export-flat": return [tool("netops"), "inventory", "export-flat"], True, True
        if action == "inventory-scan": return [tool("netops"), "inventory", "scan"] + ([target] if target else []), True, True
        if action in {"inventory-list", "inventory-show"}:
            verb = action.removeprefix("inventory-")
            return [tool("netops"), "inventory", verb] + ([target] if target and not is_all_keyword(target) else []), True, False
        if action in {"inventory-details", "inventory-activity"}:
            if not target: raise ValueError(f"{action} requires target")
            return [tool("netops"), "inventory", action.removeprefix("inventory-"), target], True, False
        if action == "health-check": return [tool("netops"), "health", "check"] + ([target] if target else []), True, True
        if action in {"health-status", "health-offline", "health-timeline"}:
            return [tool("netops"), "health", action.removeprefix("health-")] + ([target] if target else []), True, False
        if action == "ap-scan": return [tool("netops"), "ap", "scan"], True, True
        if action in {"ap-list", "ap-unjoined", "ap-timeline"}:
            return [tool("netops"), "ap", action.removeprefix("ap-")] + ([target] if target else []), True, False
        if action == "ap-on-switch":
            if not target: raise ValueError("ap-on-switch requires target")
            return [tool("netops"), "ap", "on-switch", target], True, False
        if action == "topology-scan": return [tool("netops"), "topology", "scan"], True, True
        if action in {"topology-show", "topology-neighbors", "topology-timeline"}:
            return [tool("netops"), "topology", action.removeprefix("topology-")] + ([target] if target else []), True, False
        if action == "memory-refresh": return [tool("netops"), "memory", "refresh"], True, True
        if action == "ask-query":
            question = str(args.get("question") or args.get("query") or args.get("target") or "").strip()
            if not question: raise ValueError("ask-query requires question")
            return [tool("netops"), "ask", question], True, False
        if action == "ask-alias-set":
            phrase = str(args.get("phrase") or "").strip(); alias_target = str(args.get("alias_target") or "").strip()
            if not phrase or not alias_target: raise ValueError("ask-alias-set requires phrase and alias_target")
            return [tool("netops"), "ask", "alias", "set", phrase, alias_target], True, True
        if action == "ask-alias-remove":
            phrase = str(args.get("phrase") or "").strip()
            if not phrase: raise ValueError("ask-alias-remove requires phrase")
            return [tool("netops"), "ask", "alias", "remove", phrase], True, True
        if action == "inventory-show":
            return [tool("netops"), "inventory", "show"] + ([target] if target and not is_all_keyword(target) else []), True, False
        if action == "ap-list":
            return [tool("netops"), "ap", "list"] + ([target] if target and not is_all_keyword(target) else []), True, False
        if action == "topology-neighbors":
            return [tool("netops"), "topology", "neighbors"] + ([target] if target and not is_all_keyword(target) else []), True, False
        if action == "memory-switch":
            if not target: raise ValueError("memory-switch requires target")
            return [tool("netops"), "memory", "switch", target], True, False
        if action == "memory-ip":
            if not target: raise ValueError("memory-ip requires target")
            return [tool("netops"), "memory", "ip", target], True, False
        if action == "memory-mac":
            if not target: raise ValueError("memory-mac requires target")
            return [tool("netops"), "memory", "mac", target], True, False
        if action == "memory-port":
            iface = str(args.get("interface") or args.get("port") or "").strip()
            if not target or not iface: raise ValueError("memory-port requires target and interface")
            return [tool("netops"), "memory", "port", target, iface], True, False
        if action == "memory-device":
            if not target: raise ValueError("memory-device requires target")
            return [tool("netops"), "memory", "device", target], True, False
        if action in {"memory-timeline", "memory-explain"}:
            return [tool("netops"), "memory", action.removeprefix("memory-")] + ([target] if target else []), True, False
        if action == "backup-run":
            if not target: raise ValueError("backup-run requires target")
            return [tool("netops"), "backup", "run", target], True, True
        if action == "backup-history":
            if not target: raise ValueError("backup-history requires target")
            return [tool("netops"), "backup", "history", target], True, False
        if action == "backup-diff":
            if not target: raise ValueError("backup-diff requires target")
            return [tool("netops"), "backup", "diff", target], True, False
        if action == "diagnose-latency":
            if not target: raise ValueError("diagnose-latency requires target")
            cmd = [tool("netops"), "diagnose", "latency", target]
            if args.get("count"): cmd += ["--count", str(args.get("count"))]
            return cmd, True, True
        if action == "diagnose-core-ping":
            if not target: raise ValueError("diagnose-core-ping requires target")
            cmd = [tool("netops"), "diagnose", "core-ping", target]
            if args.get("core"): cmd += ["--core", str(args.get("core"))]
            if args.get("count"): cmd += ["--count", str(args.get("count"))]
            return cmd, True, True
        if action == "diagnose-speed":
            cmd = [tool("netops"), "diagnose", "speed"]
            if args.get("profile"): cmd += ["--profile", str(args.get("profile"))]
            if args.get("runs"): cmd += ["--runs", str(args.get("runs"))]
            if args.get("ca_file"): cmd += ["--ca-file", str(args.get("ca_file"))]
            return cmd, True, True
        if action == "diagnose-throughput":
            if not target: raise ValueError("diagnose-throughput requires an iperf3 server")
            cmd = [tool("netops"), "diagnose", "throughput", target]
            for key, flag in (("port","--port"),("seconds","--seconds"),("parallel","--parallel"),("direction","--direction"),("bind","--bind")):
                if args.get(key) not in (None, ""): cmd += [flag, str(args.get(key))]
            return cmd, True, True
        if action == "diagnose-port-health":
            device = str(args.get("device") or target or "").strip(); iface = str(args.get("interface") or args.get("port_name") or "").strip()
            if not device or not iface: raise ValueError("diagnose-port-health requires device and interface")
            cmd = [tool("netops"), "diagnose", "port-health", device, "on", iface]
            if args.get("sample_seconds") not in (None, ""): cmd += ["--sample-seconds", str(args.get("sample_seconds"))]
            if args.get("expected_speed") not in (None, ""): cmd += ["--expected-speed", str(args.get("expected_speed"))]
            return cmd, True, True
        if action == "diagnose-cable":
            device = str(args.get("device") or target or "").strip(); iface = str(args.get("interface") or args.get("port") or "").strip()
            if not device or not iface: raise ValueError("diagnose-cable requires device and interface")
            return [tool("netops"), "diagnose", "cable", device, "on", iface], True, True
        if action == "diagnose-doctor":
            cmd = [tool("netops"), "diagnose", "doctor"]
            if str(args.get("online") or "").lower() in {"1", "true", "yes", "on"}: cmd.append("--online")
            return cmd, True, True
        if action == "diagnose-filtering": return [tool("netops"), "diagnose", "filtering"] + ([target] if target else []), True, True
        if action == "diagnose-interface":
            device = str(args.get("device") or target or "").strip(); iface = str(args.get("interface") or args.get("port") or "").strip()
            if not device or not iface: raise ValueError("diagnose-interface requires device and interface")
            cmd = [tool("netops"), "diagnose", "interface", device, "on", iface]
            if args.get("chart"): cmd += ["--chart", str(args.get("chart"))]
            if str(args.get("once", True)).lower() not in {"0", "false", "no", "off"}: cmd += ["--once"]
            return cmd, True, True
        if action == "lookup-core":
            if not target: raise ValueError("lookup-core requires target")
            return [tool("netops"), "lookup", "core", target], True, True
        if action == "lookup-mac":
            mac = str(args.get("mac") or "").strip()
            if not mac and target: mac = target; target = ""
            if not mac: raise ValueError("lookup-mac requires mac")
            if str(args.get("all") or "").lower() in {"1", "true", "yes"} or target.lower() == "all":
                return [tool("netops"), "lookup", "mac", "all", mac], True, True
            return [tool("netops"), "lookup", "mac"] + ([target] if target else []) + [mac], True, True
        if action in {"lookup-mac-inspect", "lookup-mac-locate", "lookup-mac-profile", "lookup-mac-history", "lookup-mac-vendor"}:
            mac = str(args.get("mac") or args.get("target") or "").strip()
            if not norm_mac(mac): raise ValueError(f"{action} requires a valid physical unicast MAC")
            subaction = action.removeprefix("lookup-mac-")
            cmd = [tool("netops"), "lookup", "mac", subaction, mac]
            scope = str(args.get("scope") or "").strip()
            if scope and action in {"lookup-mac-locate", "lookup-mac-profile"}: cmd.append(scope)
            return cmd, True, action in {"lookup-mac-locate", "lookup-mac-profile"}
        if action == "lookup-mac-online":
            mac = str(args.get("mac") or args.get("target") or "").strip()
            if not norm_mac(mac): raise ValueError("lookup-mac-online requires a valid physical unicast MAC")
            cmd = [tool("netops"), "lookup", "mac", "online", mac]
            if str(args.get("refresh") or "").lower() in {"1", "true", "yes", "on"}: cmd.append("--refresh")
            if str(args.get("offline") or "").lower() in {"1", "true", "yes", "on"}: cmd.append("--offline")
            return cmd, True, True
        if action == "device-show":
            command = str(args.get("command") or "").strip()
            if not target or not command: raise ValueError("device-show requires target and command")
            if not self.safe_show_command(command): raise ValueError("device-show accepts only policy-approved show/display/get commands")
            return [tool("netops"), "device", "show", target, command], True, False
        if action == "device-ssh":
            if not target: raise ValueError("device-ssh requires target")
            return [tool("netops"), "device", "ssh", target], True, False
        if action == "device-inventory":
            if not target: raise ValueError("device-inventory requires target")
            return [tool("netops"), "device", "inventory", target], True, False
        if action == "device-support":
            if not target: raise ValueError("device-support requires target")
            return [tool("netops"), "device", "support", target], True, False
        if action == "device-identity":
            target2 = normalize_target_literal(str(args.get("target2") or "").strip())
            if not target or not target2: raise ValueError("device-identity requires target and target2")
            return [tool("netops"), "device", "identity", target, target2], True, False
        if action == "device-trust-status":
            return [tool("netops"), "device", "trust", "status"] + ([target] if target else []), True, False
        if action == "device-trust-scan":
            if not target: raise ValueError("device-trust-scan requires target")
            return [tool("netops"), "device", "trust", "scan", target], True, False
        if action == "device-trust-enroll":
            fingerprint = str(args.get("fingerprint") or "").strip()
            if not target or not fingerprint: raise ValueError("device-trust-enroll requires target and fingerprint")
            return [tool("netops"), "device", "trust", "enroll", target, "--fingerprint", fingerprint, "--confirm"], True, True
        if action == "device-trust-forget":
            if not target: raise ValueError("device-trust-forget requires target")
            return [tool("netops"), "device", "trust", "forget", target, "--confirm"], True, True
        if action == "vlan-set":
            request = self.vlan_change_request(args)
            cmd = [tool("netops"), "vlan", "set", request["target"], request["interface"], f"--{request['vlan_mode']}", request["vlan"]]
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
            cmd = [tool("netops"), "vlan", action.removeprefix("vlan-"), target, vlan]
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
        if action in {"jobs-show", "jobs-logs", "jobs-cancel"}:
            job_id = str(args.get("job_id") or args.get("id") or "").strip()
            if not job_id: raise ValueError(f"{action} requires job_id")
            return [tool("netops"), "jobs", action.removeprefix("jobs-"), job_id], True, False
        if action == "commands-show":
            command_id = str(args.get("action") or args.get("command_id") or target or "").strip()
            if not command_id: raise ValueError("commands-show requires action")
            return [tool("netops"), "commands", "show", command_id], True, False
        if action.startswith("workflow-"):
            name = action.removeprefix("workflow-")
            return [tool("netops"), "workflow", name] + ([target] if target else []), True, True
        if action in {"device-config", "memory-prune", "jobs-cancel", "serve-run", "ask-chat", "commands-run"}:
            raise PermissionError("Config-changing WebUI/API execution is blocked. Preview in UI, then run explicitly in the CLI with --confirm.")
        raise ValueError(f"Unknown action: {action}")

    def cmd_commands(self,args:List[str],opts:GlobalOptions)->int:
        if self.handle_help("commands", args, opts): return SUCCESS
        verb=args[0] if args else "list"; rest=args[1:]
        if verb=="list":
            rows=[self.command_dict(c) for c in self.command_registry()]
            self.emit({"ok":True,"commands":rows},opts,self.render_table(rows,["id","domain","risk_level","read_only","writes_local","description"])); return SUCCESS
        if verb=="show":
            if not rest: return self.usage_error("commands","show",opts,"Missing command id.","netops commands show backup-run")
            spec=self.command_spec(rest[0])
            if not spec: return self.usage_error("commands","show",opts,f"Unknown command id: {rest[0]}","netops commands list",VALIDATION)
            payload=self.command_dict(spec); self.emit({"ok":True,"command":payload},opts,self.render_plain(payload)); return SUCCESS
        if verb=="run":
            if not rest: return self.usage_error("commands","run",opts,"Missing command id.","netops commands run health-check --preview")
            action=rest[0]; raw=[x for x in rest[1:] if x != "--preview"]; preview=("--preview" in rest) or opts.dry_run
            parsed=self.parse_registry_args(raw); spec=self.command_spec(action)
            if opts.depth: parsed.setdefault("depth", str(opts.depth))
            if opts.max_nodes != 64: parsed.setdefault("max_nodes", str(opts.max_nodes))
            if opts.refresh_neighbors: parsed.setdefault("refresh_neighbors", True)
            if opts.site and action in {"lookup-mac-locate","lookup-mac-profile"}: parsed.setdefault("scope", opts.site)
            if not spec: return self.usage_error("commands","run",opts,f"Unknown command id: {action}","netops commands list",VALIDATION)
            if not spec.run_supported and not preview:
                return self.usage_error("commands","run",opts,"This registry action is preview-only. Run its public CLI form directly if the documented policy permits it.",f"netops commands run {action} --preview",CONFIRM_REQUIRED)
            if spec.risk_level=="config" and not preview and not opts.confirm:
                return self.usage_error("commands","run",opts,"Config-changing command requires --dry-run/--preview or --confirm.",f"netops commands run {action} --preview",CONFIRM_REQUIRED)
            try: cmd,ro,wl=self.command_for_action(action,parsed)
            except PermissionError as exc: return self.usage_error("commands","run",opts,str(exc),f"netops commands run {action} --preview",CONFIRM_REQUIRED)
            except ValueError as exc: return self.usage_error("commands","run",opts,str(exc),f"netops commands show {action}",VALIDATION)
            if preview:
                self.emit({"ok":True,"preview":True,"command":shlex.join(cmd),"read_only":ro,"writes_local":wl},opts,shlex.join(cmd)); return SUCCESS
            return self.run_subprocess(cmd,opts)
        return self.unknown_action("commands", verb, opts)

    def cmd_jobs(self,args:List[str],opts:GlobalOptions)->int:
        if self.handle_help("jobs", args, opts): return SUCCESS
        verb=args[0] if args else "list"; rest=args[1:]
        if verb=="list": rows=self.jobs_list()[:opts.limit]; self.emit({"ok":True,"rows":rows},opts,self.render_table(rows,["id","action","status","created_at","started_at","finished_at","exit_code"])); return SUCCESS
        if verb in {"show","logs"}:
            if not rest: return self.usage_error("jobs",verb,opts,"Missing job id.","netops jobs show <id>")
            jid=rest[0]; job=self.state.one("SELECT * FROM jobs WHERE id=?",(jid,)); logs=self.state.rows("SELECT created_at,stream,line FROM job_logs WHERE job_id=? ORDER BY id",(jid,))
            if not job: return self.usage_error("jobs",verb,opts,f"Job not found: {jid}","netops jobs list",VALIDATION)
            text=self.render_plain(job)+"\n\nLogs\n"+self.render_table(logs,["created_at","stream","line"])
            self.emit({"ok":True,"job":job,"logs":logs},opts,text); return SUCCESS
        if verb=="cancel":
            if not rest: return self.usage_error("jobs","cancel",opts,"Missing job id.","netops jobs cancel <id>")
            jid=rest[0]
            cancelled,message=self.cancel_job(jid)
            if cancelled:
                self.emit({"ok":True,"id":jid,"status":"cancelled"},opts,f"Cancelled job {jid}"); return SUCCESS
            return self.usage_error("jobs","cancel",opts,message,"netops jobs list",VALIDATION)
        return self.unknown_action("jobs", verb, opts)

    def workflow_manifest(self, name: str, target: str = "") -> Dict[str, Any]:
        tool = self.paths.tool
        def step(step_id: str, label: str, command: List[str], on_failure: str = "continue") -> Dict[str, Any]:
            return {"id": step_id, "label": label, "command": command, "on_failure": on_failure}
        manifests: Dict[str, Dict[str, Any]] = {
            "morning-check": {"description": "Refresh local state and surface operational attention.", "steps": [
                step("import", "Import legacy caches", [tool("netops"), "inventory", "import-flat"]),
                step("health", "Check reachability", [tool("netops"), "health", "check"]),
                step("memory", "Refresh relationships", [tool("netops"), "memory", "refresh"]),
                step("topology", "Review topology changes", [tool("netops"), "topology", "changes"]),
                step("filtering", "Check Internet filtering", [tool("netops"), "diagnose", "filtering", "google.com"]),
                step("attention", "Build attention queue", [tool("netops"), "health", "attention"]),
            ]},
            "refresh-inventory": {"description": "Refresh health, wireless, topology, and relationship state.", "steps": [
                step("health", "Check reachability", [tool("netops"), "health", "check"]),
                step("aps", "Scan access points", [tool("netops"), "ap", "scan"]),
                step("topology", "Scan LLDP/CDP topology", [tool("netops"), "topology", "scan"]),
                step("memory", "Refresh relationships", [tool("netops"), "memory", "refresh"]),
                step("attention", "Build attention queue", [tool("netops"), "health", "attention"]),
            ]},
            "ap-audit": {"description": "Refresh AP evidence and surface movement or health findings.", "steps": [
                step("aps", "Scan access points", [tool("netops"), "ap", "scan"]),
                step("memory", "Refresh relationships", [tool("netops"), "memory", "refresh"]),
                step("moves", "Review AP moves", [tool("netops"), "ap", "moves"]),
                step("attention", "Build attention queue", [tool("netops"), "health", "attention"]),
            ]},
        }
        if name == "backup-online":
            if not target: raise ValueError("backup-online requires target")
            return {"name": name, "description": "Back up the selected online scope.", "steps": [step("backup", "Back up changed configurations", [tool("netops"), "backup", "run", target], "stop")]}
        if name == "site-health":
            if not target: raise ValueError("site-health requires target")
            return {"name": name, "description": "Measure latency, filtering, and recorded health for a target.", "steps": [
                step("latency", "Measure latency", [tool("netops"), "diagnose", "latency", target, "--count", "5"]),
                step("filtering", "Check filtering", [tool("netops"), "diagnose", "filtering", target]),
                step("health", "Read health state", [tool("netops"), "health", "status", target]),
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
        except ValueError as exc: return self.usage_error("workflow",name,opts,str(exc),"netops workflow morning-check",VALIDATION)
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
            result = {"step":index,"id":item["id"],"label":item["label"],"status":"SUCCESS" if rc == 0 else "FAILED","exit_code":rc,"duration_ms":duration_ms,"on_failure":item["on_failure"],"summary":summary,"result":redact_for_api(result_payload) if isinstance(result_payload, dict) else None}
            results.append(result)
            if not opts.json:
                print(f"\n[{index}/{len(steps)}] {item['label']} ({result['status']})")
                if stdout.strip(): print(stdout.rstrip())
            if rc != 0 and item["on_failure"] == "stop":
                stopped = True
                self.live_log("workflow", f"stopped after {item['id']} exited {rc}")
                break
        failed = [item for item in results if item["exit_code"] != 0]
        finished = now()
        status = "SUCCESS" if not failed else "FAILED" if stopped else "PARTIAL"
        payload = {"ok":not failed,"workflow":name,"description":manifest["description"],"status":status,"steps":results,"completed_steps":len(results),"total_steps":len(steps),"failed_steps":len(failed),"stopped":stopped,"started_at":started,"started_at_iso":fmt_time(started),"finished_at":finished,"finished_at_iso":fmt_time(finished)}
        summary_text = f"Workflow {name}: {status} | completed={len(results)}/{len(steps)} | failed={len(failed)} | recorded={payload['finished_at_iso']}\n" + self.render_table(results,["step","label","status","exit_code","duration_ms","on_failure","summary"])
        self.emit(payload,opts,summary_text)
        return SUCCESS if not failed else PARTIAL

    def cmd_backup(self,args:List[str],opts:GlobalOptions)->int:
        if self.handle_help("backup", args, opts): return SUCCESS
        verb=args[0] if args else "run"; rest=args[1:]
        if verb=="run":
            if not rest: return self.usage_error("backup","run",opts,"Missing backup target.","netops backup run ZONE34")
            target=rest[0]; extra=[x for x in rest[1:] if x not in {"--online-only","--changed-only","--summary"}]
            cmd=self.legacy_cmd("netops-control","backup",target,"--online-only","--changed-only","--summary",*extra)
            return self.run_subprocess(cmd,opts)
        if verb=="history":
            if not rest: return self.usage_error("backup","history",opts,"Missing target.","netops backup history ZONE34")
            return self.run_subprocess(self.legacy_cmd("netops-control","backup-history",rest[0]),opts)
        if verb=="diff":
            if not rest: return self.usage_error("backup","diff",opts,"Missing target.","netops backup diff ZONE34")
            return self.run_subprocess(self.legacy_cmd("netops-control","diff",rest[0]),opts)
        if verb=="verify":
            rows=self.state.rows("SELECT * FROM backup_history ORDER BY created_at DESC,id DESC LIMIT ?",(opts.limit,))
            self.emit({"ok":True,"rows":rows},opts,self.render_table(rows,["created_at","device_ip","hostname","status","changed","sha256","path","message"])); return SUCCESS
        return self.unknown_action("backup", verb, opts)

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

    def _trust_target(self, raw_target: str) -> Tuple[str, str]:
        raw = str(raw_target or "").strip()
        if not raw:
            raise ValueError("Missing SSH trust target.")
        device, choices = self.resolve_device_record(raw)
        if device:
            return str(device.get("hostname") or raw), str(device.get("ip") or raw)
        if len(choices) > 1:
            names = ", ".join(str(item.get("hostname") or item.get("ip")) for item in choices[:5])
            raise ValueError(f"SSH trust target is ambiguous: {names}")
        normalized = normalize_target_literal(raw)
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,252}", normalized):
            raise ValueError("SSH trust target must be a hostname or IP address.")
        return raw, normalized

    def _scan_host_keys(self, host: str, timeout: int = 8) -> Tuple[List[Dict[str, Any]], str]:
        scanner = shutil.which("ssh-keyscan")
        if not scanner:
            return [], "ssh-keyscan is not installed"
        try:
            completed = subprocess.run(
                [scanner, "-T", str(max(1, min(timeout, 30))), host],
                capture_output=True,
                text=True,
                timeout=max(3, min(timeout, 30)) + 3,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return [], "SSH host-key scan timed out"
        rows: List[Dict[str, Any]] = []
        for raw in completed.stdout.splitlines():
            fields = raw.strip().split()
            if len(fields) < 3 or not fields[1].startswith(("ssh-", "ecdsa-", "sk-")):
                continue
            fingerprint = self._host_key_fingerprint(fields[2])
            if fingerprint:
                rows.append({"host": fields[0], "key_type": fields[1], "fingerprint": fingerprint, "key_line": " ".join(fields[:3])})
        error = "" if rows else (" ".join(completed.stderr.split())[:300] or f"ssh-keyscan exited {completed.returncode} without a usable key")
        return rows, error

    def _write_known_hosts(self, lines: Sequence[str]) -> None:
        path = self.paths.ssh_known_hosts_file
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with contextlib.suppress(OSError):
            path.parent.chmod(0o700)
        descriptor, staged_name = tempfile.mkstemp(prefix=".known-hosts.", suffix=".tmp", dir=str(path.parent))
        staged = Path(staged_name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                for line in lines:
                    handle.write(line.rstrip("\n") + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(staged, path)
            path.chmod(0o600)
        finally:
            with contextlib.suppress(OSError):
                staged.unlink()

    def cmd_device_trust(self, args: List[str], opts: GlobalOptions) -> int:
        action = args[0].lower() if args else "status"
        rest = args[1:]
        target = ""
        fingerprints: List[str] = []
        index = 0
        while index < len(rest):
            item = rest[index]
            if item == "--fingerprint" and index + 1 < len(rest):
                fingerprints.extend(part.strip() for part in rest[index + 1].split(",") if part.strip())
                index += 2
            elif item.startswith("--"):
                return self.usage_error("device", f"trust-{action}", opts, f"Unknown SSH trust option: {item}", "netops help device trust-status", VALIDATION)
            elif not target:
                target = item; index += 1
            else:
                return self.usage_error("device", f"trust-{action}", opts, "SSH trust accepts one target.", "netops help device trust-status", VALIDATION)
        if action == "status":
            wanted: List[str] = []
            label = "all managed hosts"
            if target:
                try: label, host = self._trust_target(target)
                except ValueError as exc: return self.usage_error("device", "trust-status", opts, str(exc), "netops device trust status ZONE34", VALIDATION)
                wanted = [host, target]
            rows = self._known_host_rows(wanted)
            mode = os.environ.get("NETOPS_SSH_HOST_KEY_MODE") or self.config.public.get("ssh_host_key_mode") or "accept-new"
            payload = {"ok": True, "target": label, "mode": mode, "known_hosts_file": str(self.paths.ssh_known_hosts_file), "rows": rows, "count": len(rows)}
            self.emit(payload, opts, f"SSH trust: {label} | mode={mode} | keys={len(rows)}\n" + self.render_table(rows, ["host", "key_type", "fingerprint", "line"]))
            return SUCCESS
        if action not in {"scan", "enroll", "forget"}:
            return self.usage_error("device", "trust-status", opts, f"Unknown SSH trust action: {action}", "netops device trust status|scan|enroll|forget", VALIDATION)
        if not target:
            return self.usage_error("device", f"trust-{action}", opts, "Missing SSH trust target.", f"netops device trust {action} ZONE34", VALIDATION)
        try: label, host = self._trust_target(target)
        except ValueError as exc: return self.usage_error("device", f"trust-{action}", opts, str(exc), f"netops device trust {action} ZONE34", VALIDATION)
        if action == "scan":
            if opts.dry_run:
                self.emit({"ok": True, "dry_run": True, "target": label, "host": host, "command": f"ssh-keyscan -T {opts.timeout or 8} {host}"}, opts, f"Would scan SSH host keys for {label} ({host}); no trust state would change.")
                return SUCCESS
            rows, error = self._scan_host_keys(host, opts.timeout or 8)
            observed = now()
            payload = {"ok": bool(rows), "target": label, "host": host, "observed_at": observed, "observed_at_iso": fmt_time(observed), "trusted": False, "rows": [{k:v for k,v in row.items() if k != "key_line"} for row in rows], "error": error}
            self.emit(payload, opts, self.render_table(payload["rows"], ["host", "key_type", "fingerprint"]) if rows else f"SSH host-key scan failed: {error}")
            return SUCCESS if rows else UNREACHABLE
        if not (opts.dry_run or opts.confirm):
            return self.usage_error("device", f"trust-{action}", opts, "SSH trust changes require --dry-run or --confirm.", f"netops device trust {action} {target} --dry-run", CONFIRM_REQUIRED)
        if action == "forget":
            existing_lines = self.paths.ssh_known_hosts_file.read_text(encoding="utf-8", errors="ignore").splitlines() if self.paths.ssh_known_hosts_file.is_file() else []
            aliases_to_remove = {host, target}
            retained: List[str] = []
            removed = 0
            for line in existing_lines:
                fields = line.strip().split()
                offset = 1 if fields and fields[0].startswith("@") else 0
                aliases = fields[offset].split(",") if len(fields) > offset else []
                matched = any(self._known_host_alias_matches(alias, wanted) for alias in aliases for wanted in aliases_to_remove)
                if matched:
                    removed += 1
                else:
                    retained.append(line)
            if opts.dry_run:
                self.emit({"ok": True, "dry_run": True, "target": label, "host": host, "would_remove": removed}, opts, f"Would remove {removed} managed SSH key(s) for {label} ({host}).")
                return SUCCESS
            self._write_known_hosts(retained)
            actor = os.environ.get("SUDO_USER") or os.environ.get("USER") or str(os.getuid())
            self.state.record_audit_event("ssh_trust_forgotten", "device-trust-forget", actor=actor, actor_uid=os.getuid(), target=host, result="success", detail={"removed": removed})
            self.emit({"ok": True, "target": label, "host": host, "removed": removed}, opts, f"Removed {removed} managed SSH key(s) for {label} ({host}).")
            return SUCCESS
        if not fingerprints:
            return self.usage_error("device", "trust-enroll", opts, "Enrollment requires at least one independently verified --fingerprint.", f"netops device trust scan {target}", VALIDATION)
        if opts.dry_run:
            self.emit({"ok": True, "dry_run": True, "target": label, "host": host, "fingerprints": fingerprints}, opts, f"Would rescan {label} ({host}) and enroll only {', '.join(fingerprints)}.")
            return SUCCESS
        rows, error = self._scan_host_keys(host, opts.timeout or 8)
        wanted_fingerprints = {value.casefold() for value in fingerprints}
        matched = [row for row in rows if str(row.get("fingerprint") or "").casefold() in wanted_fingerprints]
        if not matched:
            message = error or "None of the scanned SSH keys matched the verified fingerprint."
            self.emit({"ok": False, "target": label, "host": host, "error": message, "observed_fingerprints": [row.get("fingerprint") for row in rows]}, opts, message)
            return AUTH
        existing_lines = self.paths.ssh_known_hosts_file.read_text(encoding="utf-8", errors="ignore").splitlines() if self.paths.ssh_known_hosts_file.is_file() else []
        retained = []
        for line in existing_lines:
            fields = line.strip().split()
            offset = 1 if fields and fields[0].startswith("@") else 0
            aliases = fields[offset].split(",") if len(fields) > offset else []
            if not any(self._known_host_alias_matches(alias, host) for alias in aliases):
                retained.append(line)
        retained.extend(str(row["key_line"]) for row in matched)
        self._write_known_hosts(retained)
        actor = os.environ.get("SUDO_USER") or os.environ.get("USER") or str(os.getuid())
        self.state.record_audit_event("ssh_trust_enrolled", "device-trust-enroll", actor=actor, actor_uid=os.getuid(), target=host, result="success", detail={"fingerprints": [row["fingerprint"] for row in matched]})
        payload = {"ok": True, "target": label, "host": host, "known_hosts_file": str(self.paths.ssh_known_hosts_file), "rows": [{k:v for k,v in row.items() if k != "key_line"} for row in matched], "count": len(matched)}
        self.emit(payload, opts, f"Enrolled {len(matched)} verified SSH host key(s) for {label} ({host}).")
        return SUCCESS

    def vault_status_payload(self) -> Dict[str, Any]:
        vault = Path(os.environ.get("NETOPS_PASSWORD_FILE", str(self.paths.home / ".ssh" / "sshpass_cache.gpg")))
        exists = vault.is_file()
        mode = "missing"
        permissions = ""
        modified_at = 0
        if exists:
            try:
                with vault.open("rb") as handle:
                    marker = handle.readline(64).rstrip(b"\r\n")
                mode = "sudo-gpg-v1" if marker == b"NETOPS-SUDO-GPG-V1" else "legacy-gpg"
                file_stat = vault.stat()
                permissions = f"{file_stat.st_mode & 0o777:04o}"
                modified_at = int(file_stat.st_mtime)
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
            if os.environ.get("NETOPS_TEST_MODE", "").lower() in {"1", "true", "yes"}:
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
                    if os.environ.get("NETOPS_TEST_MODE", "").lower() in {"1", "true", "yes"}:
                        key_dir = os.environ.get("NETOPS_SUDO_VAULT_KEY_DIR", key_dir)
                    key_file = str(Path(key_dir) / f"{os.getuid()}.key")
                    fixture_sudo = os.environ.get("NETOPS_TEST_MODE", "").lower() in {"1", "true", "yes"} and sudo_bin != "/usr/bin/sudo"
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
            "graphical_pinentry": False if mode in {"legacy-gpg", "sudo-gpg-v1"} else None,
        }

    def cmd_vault(self, args: List[str], opts: GlobalOptions) -> int:
        if self.handle_help("vault", args, opts):
            return SUCCESS
        verb = args[0].lower() if args else "status"
        rest = args[1:]
        if verb == "status":
            if rest:
                return self.usage_error("vault", "status", opts, f"Unknown vault status option: {rest[0]}", "netops vault status", VALIDATION)
            payload = self.vault_status_payload()
            text = "\n".join(
                [
                    f"SSH vault: {payload['path']}",
                    f"Mode: {payload['mode']}",
                    f"Permissions: {payload['permissions'] or 'not available'}",
                    f"Last recorded: {payload['modified_at_iso'] or 'never'}",
                    f"Expected password expiry: {payload['expected_expiry_at_iso'] or 'unknown'}",
                    f"Estimated expiry window: {payload['expiry_window_start_iso'] or 'unknown'} to {payload['expiry_window_end_iso'] or 'unknown'}",
                    f"Credential state: {payload['credential_state']}",
                    f"Authentication: {'Windows Hello via sudo/PAM' if payload['sudo_authenticator'] == 'windows-hello' else 'sudo password/PAM'}",
                    f"Sudo session: {payload['sudo_session']}",
                    f"Root key: {payload['root_key']}",
                ]
            )
            self.emit(payload, opts, text)
            return SUCCESS
        if verb not in {"set", "migrate", "unlock"}:
            return self.unknown_action("vault", verb, opts)
        if opts.json:
            return self.usage_error("vault", verb, opts, "Interactive vault actions do not emit JSON.", f"netops vault {verb}", VALIDATION)
        helper_args: List[str]
        if verb == "set":
            invalid = [item for item in rest if item != "--legacy-vault"]
            if invalid or rest.count("--legacy-vault") > 1:
                bad = invalid[0] if invalid else "duplicate --legacy-vault"
                return self.usage_error("vault", "set", opts, f"Unknown vault set option: {bad}", "netops vault set [--legacy-vault]", VALIDATION)
            helper_args = ["--set-password"]
            if "--legacy-vault" in rest:
                helper_args.append("--legacy-vault")
        else:
            if rest:
                return self.usage_error("vault", verb, opts, f"Vault {verb} does not accept arguments.", f"netops vault {verb}", VALIDATION)
            helper_args = ["--migrate-vault" if verb == "migrate" else "--unlock-vault"]
        code = self.run_vault_interactive(self.legacy_cmd("netops-connect", *helper_args), opts)
        if code == SUCCESS and not opts.dry_run:
            actor = os.environ.get("SUDO_USER") or os.environ.get("USER") or str(os.getuid())
            event = {"set": "vault_password_set", "migrate": "vault_migrated", "unlock": "vault_unlocked"}[verb]
            self.state.record_audit_event(event, f"vault-{verb}", actor=actor, actor_uid=os.getuid(), result="success", detail={"vault": str(self.vault_status_payload().get("path") or "")})
        return code

    def cmd_device(self,args:List[str],opts:GlobalOptions)->int:
        if self.handle_help("device", args, opts): return SUCCESS
        verb=args[0] if args else "ssh"; rest=args[1:]
        if verb in {"support", "compatibility"}:
            target = " ".join(rest).strip()
            if not target:
                rows = [driver.report() for driver in self.device_drivers.all()]
                payload = {"ok": True, "target": "", "drivers": rows, "count": len(rows), "observed_at": now()}
                self.emit(payload, opts, self.render_table(rows, ["family", "vendor", "os_name", "device_kind", "support_level"]))
                return SUCCESS
            device, choices = self.resolve_device_record(target)
            if not device:
                labels = ", ".join(str(row.get("hostname") or row.get("ip")) for row in choices[:8])
                return self.usage_error("device", "support", opts, f"Device could not be resolved: {target}" + (f" ({labels})" if labels else ""), "netops inventory list <target>", VALIDATION)
            detection = self.detect_device_family(platform=device.get("platform"), model=device.get("model"), hostname=device.get("hostname"))
            driver = self.driver_for(family=detection.family)
            payload = {"ok": detection.family != "unknown", "device": device, "detection": detection.as_dict(), "driver": driver.report(), "observed_at": now()}
            capability_rows = [{"capability": key, "support": value} for key, value in sorted(driver.capabilities.items())]
            text = f"Device support: {device.get('hostname') or device.get('ip')}\nFamily: {driver.family} | OS: {driver.os_name} | Level: {driver.support_level}\n" + self.render_table(capability_rows, ["capability", "support"])
            self.emit(payload, opts, text)
            return SUCCESS if payload["ok"] else UNSUPPORTED
        if verb in {"identity", "compare"}:
            if len(rest) < 2:
                return self.usage_error("device", "identity", opts, "Two device targets are required.", "netops device identity <first> <second>", VALIDATION)
            left, left_choices = self.resolve_device_record(rest[0])
            right, right_choices = self.resolve_device_record(rest[1])
            if not left or not right:
                return self.usage_error("device", "identity", opts, "Both device targets must resolve unambiguously.", "netops inventory list <target>", VALIDATION)
            assessment = identity_match_evidence(left, right, "switch")
            payload = {"ok": True, "left": left, "right": right, "assessment": assessment, "observed_at": now()}
            verdict = "same device" if assessment["same_device"] else ("candidate requiring corroboration" if assessment["candidate"] else "different devices")
            self.emit(payload, opts, f"Identity assessment: {verdict}\nConfidence: {assessment['confidence']}% | Name similarity: {assessment['signals']['name_similarity']}% | Required name threshold: {assessment['signals']['name_threshold']}%\nConflicts: {', '.join(assessment['conflicts']) or 'none'}")
            return SUCCESS
        if verb=="ssh":
            legacy = False
            target_parts: List[str] = []
            for item in rest:
                if item in {"-l", "--legacy"}:
                    legacy = True
                elif item.startswith("-"):
                    return self.usage_error("device", "ssh", opts, f"Unknown SSH option: {item}", "netops device ssh [-l|--legacy] <target>", VALIDATION)
                else:
                    target_parts.append(item)
            target_query = " ".join(target_parts).strip()
            if not target_query: return self.usage_error("device","ssh",opts,"Missing target.","netops device ssh ZONE34")
            device, choices = self.resolve_device_record(target_query)
            target = str(device.get("ip") or target_query) if device and len(choices) == 1 else target_query
            helper_args = (["--legacy"] if legacy else []) + [target]
            return self.run_vault_interactive(self.legacy_cmd("netops-connect", *helper_args),opts)
        if verb=="show":
            if len(rest)<2: return self.usage_error("device","show",opts,"Missing target or show command.","netops device show ZONE34 show version")
            target=rest[0]; command=" ".join(rest[1:])
            if not self.safe_show_command(command): return self.usage_error("device","show",opts,"Only read-only show/display/get commands are allowed here.","netops device config <target> <commands> --dry-run",VALIDATION)
            device, choices = self.resolve_device_record(target)
            resolved_target = str(device.get("ip") or target) if device and len(choices) == 1 else target
            return self.run_subprocess(self.legacy_cmd("netops-control","show",resolved_target,command),opts)
        if verb=="config":
            if len(rest)<2: return self.usage_error("device","config",opts,"Missing target or config command(s).","netops device config ZONE34 'interface Gi1/0/7' --dry-run")
            if not (opts.dry_run or opts.confirm): return self.usage_error("device","config",opts,"Config changes require --dry-run or --confirm.","netops device config ZONE34 'show intent' --dry-run",CONFIRM_REQUIRED)
            device, _ = self.resolve_device_record(rest[0])
            if device:
                driver = self.driver_for(platform=device.get("platform"), model=device.get("model"), hostname=device.get("hostname"))
                if driver.capability("configuration") != "supported":
                    payload = {
                        "ok": False,
                        "status": "UNSUPPORTED",
                        "target": rest[0],
                        "driver_family": driver.family,
                        "support": driver.capability("configuration"),
                        "reason": f"Configuration writes are not approved for the {driver.family} driver.",
                    }
                    self.emit(payload, opts, payload["reason"])
                    return UNSUPPORTED
                rest = [str(device.get("ip") or rest[0]), *rest[1:]]
            return self.run_subprocess(self.legacy_cmd("netops-control","config",*rest),opts)
        if verb=="trust": return self.cmd_device_trust(rest,opts)
        if verb=="inventory": return self.run_subprocess(self.legacy_cmd("netops-control","inventory",*rest),opts)
        return self.unknown_action("device", verb, opts)

    @staticmethod
    def _validated_vlan_values(value: Any, *, allow_list: bool) -> Tuple[str, List[int]]:
        text = re.sub(r"\s+", "", str(value or ""))
        if not text or len(text) > 512:
            raise ValueError("VLAN value is missing or too long.")
        if not allow_list and not text.isdigit():
            raise ValueError("Access VLAN must be one integer from 1 through 4094.")
        if not re.fullmatch(r"\d{1,4}(?:-\d{1,4})?(?:,\d{1,4}(?:-\d{1,4})?)*", text):
            raise ValueError("Trunk VLANs must be comma-separated IDs or ascending ranges.")
        values: List[int] = []
        for part in text.split(","):
            if "-" in part:
                first_text, last_text = part.split("-", 1)
                first, last = int(first_text), int(last_text)
                if not 1 <= first <= last <= 4094:
                    raise ValueError("VLAN ranges must be ascending and within 1 through 4094.")
                values.extend(range(first, last + 1))
            else:
                number = int(part)
                if not 1 <= number <= 4094:
                    raise ValueError("VLAN IDs must be within 1 through 4094.")
                values.append(number)
        return text, sorted(set(values))

    def vlan_change_request(self, args: Dict[str, Any]) -> Dict[str, Any]:
        target = normalize_target_literal(str(args.get("target") or "").strip())
        interface = str(args.get("interface") or args.get("port") or "").strip()
        mode = str(args.get("vlan_mode") or args.get("mode") or "").strip().lower()
        if not target:
            raise ValueError("VLAN change requires a switch target.")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9./:_-]{0,63}", interface):
            raise ValueError("Interface name is invalid.")
        if mode not in {"access", "trunk"}:
            raise ValueError("Port mode must be access or trunk.")
        vlan_text, vlan_values = self._validated_vlan_values(args.get("vlan"), allow_list=mode == "trunk")
        native_raw = args.get("native_vlan")
        native_vlan = ""
        if native_raw not in (None, ""):
            native_vlan, _ = self._validated_vlan_values(native_raw, allow_list=False)
            if mode != "trunk":
                raise ValueError("Native VLAN is valid only for trunk mode.")
        replace = str(args.get("replace") or "").strip().lower() in {"1", "true", "yes", "on"}
        if replace and mode != "trunk":
            raise ValueError("Replace is valid only for a trunk allowed list.")
        helper_args = ["vlan", target, interface, f"--{mode}", vlan_text]
        if native_vlan:
            helper_args += ["--native", native_vlan]
        if replace:
            helper_args.append("--replace")
        return {
            "target": target,
            "interface": interface,
            "vlan_mode": mode,
            "vlan": vlan_text,
            "vlan_values": vlan_values,
            "native_vlan": native_vlan,
            "replace": replace,
            "helper_args": helper_args,
        }

    def apply_vlan_change(self, request: Dict[str, Any], opts: GlobalOptions) -> int:
        public_command = [self.paths.tool("netops"), "vlan", "set", request["target"], request["interface"], f"--{request['vlan_mode']}", request["vlan"]]
        if request.get("native_vlan"):
            public_command += ["--native", str(request["native_vlan"])]
        if request.get("replace"):
            public_command.append("--replace")
        public_command.append("--confirm")
        steps = [
            {"step": "preflight", "purpose": "capture current interface VLAN evidence"},
            {"step": "backup", "purpose": "save changed-only running configuration"},
            {"step": "apply", "purpose": "apply typed VLAN intent through the internal adapter"},
            {"step": "verify", "purpose": "confirm the requested VLAN is present on the interface"},
        ]
        if opts.dry_run:
            payload = {"ok": True, "dry_run": True, "request": {k:v for k,v in request.items() if k != "helper_args"}, "command": shlex.join(public_command), "steps": steps, "rollback": "Automatic rollback is not attempted without a fully parsed vendor pre-state; retained evidence supports manual rollback."}
            self.emit(payload, opts, "Guarded VLAN change preview\n" + "\n".join(f"  {index}. {item['step']}: {item['purpose']}" for index, item in enumerate(steps, 1)) + f"\nCommand: {payload['command']}\nNo network command executed.")
            return SUCCESS
        device, choices = self.resolve_device_record(request["target"])
        if not device:
            labels = ", ".join(str(row.get("hostname") or row.get("ip")) for row in choices[:8])
            return self.usage_error("vlan", "set", opts, "Switch target could not be uniquely resolved." + (f" Matches: {labels}" if labels else ""), "netops vlan set <target> <interface> --access 131 --dry-run", VALIDATION)
        ip = str(device.get("ip") or "")
        name = str(device.get("hostname") or ip)
        driver = self.driver_for(platform=device.get("platform"), model=device.get("model"), hostname=device.get("hostname"))
        detection = self.detect_device_family(
            platform=device.get("platform"),
            model=device.get("model"),
            hostname=device.get("hostname"),
        )
        writes_enabled = str(self.config.public.get("device_writes_enabled") or "").lower() in {"1", "true", "yes", "on"}
        write_support = driver.capability("vlan_write")
        write_approved = (
            driver.source == "built-in"
            and write_support == "firmware-gated"
            and writes_enabled
            and detection.firmware_profile in driver.firmware_profiles
        )
        if not write_approved:
            payload = {
                "ok": False,
                "status": "UNSUPPORTED",
                "request": {k:v for k,v in request.items() if k != "helper_args"},
                "device": device,
                "driver_family": driver.family,
                "firmware_profile": detection.firmware_profile,
                "writes_enabled": writes_enabled,
                "support": write_support,
                "error": f"VLAN writes require an explicitly enabled, certified built-in {driver.family} firmware profile; no network command was executed.",
            }
            self.emit(payload, opts, payload["error"])
            return UNSUPPORTED
        platform = f"{device.get('platform') or ''} {device.get('model') or ''}".lower()
        preflight_command = f"show vlan ports {request['interface']} detail" if any(token in platform for token in ("aruba", "procurve", "hp")) else f"show interfaces {request['interface']} switchport"
        started = now()
        phase_results: List[Dict[str, Any]] = []
        self.live_log("change", f"1/4 preflight {name} {request['interface']}")
        pre_rc, pre_out, pre_err = self.capture(self.legacy_cmd("netops-control", "show", ip, preflight_command), opts.timeout or 180, opts)
        pre_excerpt = " ".join(clean_network_output((pre_out or "") + (pre_err or "")).split())[:1600]
        phase_results.append({"phase": "preflight", "status": "PASS" if pre_rc == 0 and pre_excerpt else "FAIL", "exit_code": pre_rc, "detail": pre_excerpt})
        if pre_rc != 0 or not pre_excerpt:
            payload = {"ok": False, "status": "BLOCKED", "request": request, "device": device, "phases": phase_results, "error": "Pre-change interface evidence could not be captured; no configuration was applied.", "started_at": started, "finished_at": now()}
            self.emit(payload, opts, payload["error"])
            return PARTIAL
        self.live_log("change", f"2/4 backup {name}")
        backup_rc, backup_out, backup_err = self.capture(self.legacy_cmd("netops-control", "backup", ip, "--online-only", "--changed-only", "--summary"), opts.timeout or 300, opts)
        backup_excerpt = " ".join(clean_network_output((backup_out or "") + (backup_err or "")).split())[:1200]
        phase_results.append({"phase": "backup", "status": "PASS" if backup_rc == 0 else "FAIL", "exit_code": backup_rc, "detail": backup_excerpt})
        if backup_rc != 0:
            payload = {"ok": False, "status": "BLOCKED", "request": request, "device": device, "phases": phase_results, "error": "Configuration backup failed; no VLAN change was applied.", "started_at": started, "finished_at": now()}
            self.emit(payload, opts, payload["error"])
            return PARTIAL
        self.live_log("change", f"3/4 apply {request['vlan_mode']} VLAN {request['vlan']} on {name} {request['interface']}")
        apply_rc, apply_out, apply_err = self.capture(self.legacy_cmd("netops-control", *request["helper_args"]), opts.timeout or 300, opts)
        apply_excerpt = " ".join(clean_network_output((apply_out or "") + (apply_err or "")).split())[:1600]
        phase_results.append({"phase": "apply", "status": "PASS" if apply_rc == 0 else "FAIL", "exit_code": apply_rc, "detail": apply_excerpt})
        if apply_rc != 0:
            payload = {"ok": False, "status": "FAILED", "request": request, "device": device, "phases": phase_results, "error": "Device rejected the VLAN change. Review pre-change evidence before any manual rollback.", "started_at": started, "finished_at": now()}
            self.emit(payload, opts, payload["error"])
            return PARTIAL
        requested_vlans = [int(value) for value in request["vlan_values"]]
        verification_complete = len(requested_vlans) <= 8
        if verification_complete:
            verification_vlans = list(requested_vlans)
        else:
            verification_vlans = [requested_vlans[0], requested_vlans[-1]]
        if request.get("native_vlan"):
            verification_vlans.append(int(request["native_vlan"]))
        verification_vlans = list(dict.fromkeys(verification_vlans))
        verification_checks: List[Dict[str, Any]] = []
        for verify_index, verification_vlan in enumerate(verification_vlans, 1):
            self.live_log("change", f"4/4 verify VLAN {verification_vlan} on {name} {request['interface']} ({verify_index}/{len(verification_vlans)})")
            verify_rc, verify_out, verify_err = self.capture(self.legacy_cmd("netops-control", "locate-vlan", ip, str(verification_vlan)), opts.timeout or 180, opts)
            verify_raw = (verify_out or "") + (verify_err or "")
            verified_report = parse_vlan_control_output(verify_raw, "locate")
            expected_ports = verified_report.get("access_ports") if request["vlan_mode"] == "access" else [row.get("port") for row in verified_report.get("trunks") or [] if row.get("carries_vlan")]
            check_verified = verify_rc == 0 and verified_report.get("defined") is True and any(interface_matches(request["interface"], port) for port in expected_ports or [])
            verification_checks.append({
                "vlan": verification_vlan,
                "verified": check_verified,
                "exit_code": verify_rc,
                "detail": " ".join(clean_network_output(verify_raw).split())[:800],
                "parsed": verified_report,
            })
        verification_observed = bool(verification_checks) and all(item["verified"] for item in verification_checks)
        verified = verification_observed and verification_complete
        passed_checks = sum(bool(item["verified"]) for item in verification_checks)
        verification_detail = f"{passed_checks}/{len(verification_checks)} VLAN checks passed; complete={'yes' if verification_complete else 'no (sampled first/last VLAN only)'}"
        verification_status = "PASS" if verified else "ATTENTION" if verification_observed else "FAIL"
        phase_results.append({
            "phase": "verify",
            "status": verification_status,
            "exit_code": max((int(item["exit_code"]) for item in verification_checks), default=1),
            "detail": verification_detail,
            "checks": verification_checks,
        })
        finished = now()
        status = "SUCCESS" if verified else "ATTENTION"
        payload = {
            "ok": verified,
            "status": status,
            "request": {k:v for k,v in request.items() if k != "helper_args"},
            "device": device,
            "phases": phase_results,
            "verification_vlan": verification_vlans[0],
            "verification_vlans": verification_vlans,
            "verification_complete": verification_complete,
            "verification_observed": verification_observed,
            "verified": verified,
            "started_at": started,
            "started_at_iso": fmt_time(started),
            "finished_at": finished,
            "finished_at_iso": fmt_time(finished),
            "rollback": "Review the captured preflight evidence and latest configuration backup before manual rollback or complete manual verification." if not verified else "Not required; complete post-change verification passed.",
        }
        actor = os.environ.get("SUDO_USER") or os.environ.get("USER") or str(os.getuid())
        self.state.record_audit_event("vlan_change_finished", "vlan-set", actor=actor, actor_uid=os.getuid(), target=f"{ip}:{request['interface']}", result=status.lower(), detail={"request":payload["request"], "phases":phase_results})
        text = f"Guarded VLAN change: {status}\nDevice: {name} ({ip}) {request['interface']}\n" + self.render_table(phase_results, ["phase", "status", "exit_code", "detail"]) + f"\nRecorded: {payload['finished_at_iso']}\n{payload['rollback']}"
        self.emit(payload, opts, text)
        return SUCCESS if verified else PARTIAL

    def parse_vlan_scan_request(self, args: Sequence[str]) -> Tuple[List[str], List[int]]:
        target_specs: List[str] = []
        vlan_specs: List[str] = []
        positional: List[str] = []
        index = 0
        while index < len(args):
            item = str(args[index])
            if item in {"--target", "--device"}:
                if index + 1 >= len(args):
                    raise ValueError(f"{item} requires a device name, IP, or comma-separated target list")
                target_specs.append(str(args[index + 1])); index += 2
            elif item == "--vlan":
                if index + 1 >= len(args):
                    raise ValueError("--vlan requires an ID, range, or comma-separated list")
                vlan_specs.append(str(args[index + 1])); index += 2
            elif item.startswith("--"):
                raise ValueError(f"unknown VLAN scan option: {item}")
            else:
                positional.append(item); index += 1
        if not target_specs and positional:
            target_specs.append(positional.pop(0))
        if not vlan_specs and positional:
            vlan_specs.append(positional.pop(0))
        if positional:
            raise ValueError("additional positional values are ambiguous; repeat --target or --vlan")
        targets = [token.strip() for spec in target_specs for token in spec.split(",") if token.strip()]
        vlans: List[int] = []
        for spec in vlan_specs:
            _, values = self._validated_vlan_values(spec, allow_list=True)
            vlans.extend(values)
        targets = list(dict.fromkeys(targets))
        vlans = list(dict.fromkeys(vlans))
        if not targets or not vlans:
            raise ValueError("at least one target and one VLAN are required")
        if len(targets) > 16:
            raise ValueError("a VLAN scan accepts at most 16 root targets per invocation")
        if len(vlans) > 128:
            raise ValueError("a VLAN scan accepts at most 128 distinct VLANs per invocation")
        return targets, vlans

    def cmd_vlan(self,args:List[str],opts:GlobalOptions)->int:
        if self.handle_help("vlan", args, opts): return SUCCESS
        verb=args[0] if args else "locate"; rest=args[1:]
        if verb=="locate":
            try: targets, vlans = self.parse_vlan_scan_request(rest)
            except ValueError as exc: return self.usage_error("vlan","locate",opts,str(exc),"netops vlan locate SW1,SW2 10,20 --depth 2",VALIDATION)
            if opts.depth or len(targets)>1 or len(vlans)>1: return self.vlan_cascade_many(targets,vlans,"locate",opts)
            return self.run_subprocess(self.legacy_cmd("netops-control","locate-vlan",targets[0],str(vlans[0])),opts)
        if verb=="propagation":
            try: targets, vlans = self.parse_vlan_scan_request(rest)
            except ValueError as exc: return self.usage_error("vlan","propagation",opts,str(exc),"netops vlan propagation SW1,SW2 10,20 --depth 2",VALIDATION)
            if opts.depth or len(targets)>1 or len(vlans)>1: return self.vlan_cascade_many(targets,vlans,"propagation",opts)
            return self.run_subprocess(self.legacy_cmd("netops-control","propagated",targets[0],str(vlans[0])),opts)
        if verb=="set":
            if len(rest)<2: return self.usage_error("vlan","set",opts,"Missing target or interface.","netops vlan set ZONE34 Gi1/0/7 --access 120 --dry-run")
            if not (opts.dry_run or opts.confirm): return self.usage_error("vlan","set",opts,"VLAN changes require --dry-run or --confirm.","netops vlan set ZONE34 Gi1/0/7 --access 120 --dry-run",CONFIRM_REQUIRED)
            parsed: Dict[str, Any] = {"target": rest[0], "interface": rest[1]}
            index = 2
            while index < len(rest):
                item = rest[index]
                if item in {"--access", "--trunk"} and index + 1 < len(rest):
                    parsed["vlan_mode"] = item[2:]; parsed["vlan"] = rest[index + 1]; index += 2
                elif item == "--native" and index + 1 < len(rest):
                    parsed["native_vlan"] = rest[index + 1]; index += 2
                elif item == "--replace":
                    parsed["replace"] = True; index += 1
                else:
                    return self.usage_error("vlan", "set", opts, f"Unknown or incomplete VLAN option: {item}", "netops vlan set ZONE34 Gi1/0/7 --access 120 --dry-run", VALIDATION)
            try: request = self.vlan_change_request(parsed)
            except ValueError as exc: return self.usage_error("vlan", "set", opts, str(exc), "netops vlan set ZONE34 Gi1/0/7 --access 120 --dry-run", VALIDATION)
            return self.apply_vlan_change(request,opts)
        return self.unknown_action("vlan", verb, opts)

    def current_switch_targets(self, opts: GlobalOptions, pattern: str = "") -> List[Dict[str, Any]]:
        clauses = ["COALESCE(ip,'')!=''"]
        args: List[Any] = []
        if opts.status:
            clauses.append("upper(status)=?")
            args.append(opts.status)
        else:
            clauses.append("upper(COALESCE(status,'ONLINE'))!='OFFLINE'")
        if pattern:
            like = f"%{pattern.lower()}%"
            clauses.append("(lower(ip) LIKE ? OR lower(hostname) LIKE ? OR lower(platform) LIKE ? OR lower(model) LIKE ?)")
            args.extend([like, like, like, like])
        where = " AND ".join(clauses)
        args.append(opts.limit)
        return self.state.rows(f"SELECT ip,hostname,platform,model,status,last_seen FROM devices WHERE {where} ORDER BY hostname,ip LIMIT ?", tuple(args))

    def core_lookup_workflow(self, target: str, opts: GlobalOptions) -> int:
        raw_target = str(target or "").strip()
        target_mac = norm_mac(raw_target)
        target_ip = normalize_target_literal(raw_target)
        if not target_mac and not is_ipv4_literal(target_ip):
            return self.usage_error("lookup", "core", opts, "Target must be an IP address or physical unicast MAC.", "netops lookup core 198.51.100.92", VALIDATION)

        configured_core = str(self.config.public.get("core_switch_ip") or self.config.public.get("core_switch") or "").strip()
        if not configured_core:
            return self.usage_error("lookup", "core", opts, "No core switch is configured.", "Set core_switch_ip, then run: netops lookup core 198.51.100.92", VALIDATION)
        core, choices = self.resolve_device_record(configured_core)
        if not core:
            normalized_core = normalize_target_literal(configured_core)
            if is_ipv4_literal(normalized_core):
                core = {"ip": normalized_core, "hostname": configured_core, "platform": "Unknown", "model": "", "status": "UNKNOWN"}
            else:
                labels = ", ".join(str(row.get("hostname") or row.get("ip")) for row in choices[:8])
                return self.usage_error("lookup", "core", opts, "Core switch could not be resolved safely." + (f" Matches: {labels}" if labels else ""), "netops inventory list <core>", VALIDATION)

        core_ip = str(core.get("ip") or "")
        detection = self.detect_device_family(platform=core.get("platform"), model=core.get("model"), hostname=core.get("hostname"))
        driver = self.driver_for(family=detection.family)
        if opts.dry_run:
            payload = {
                "ok": True,
                "dry_run": True,
                "target": raw_target,
                "core": core,
                "driver_family": driver.family,
                "steps": ["classify core", "query ARP", "query forwarding table", "inspect learned interface", "record evidence"],
            }
            self.emit(payload, opts, f"Dry run: core lookup {raw_target} from {core.get('hostname') or core_ip} using {driver.family}")
            return SUCCESS

        evidence_parts: List[str] = []
        if driver.family == "unknown":
            self.live_log("lookup", f"{core_ip}: classify core switch before selecting vendor commands")
            version_rc, version_out, version_err = self.capture(self.legacy_cmd("netops-control", "show", core_ip, "show version"), opts.timeout or 90)
            version_text = (version_out or "") + (version_err or "")
            evidence_parts.append(version_text)
            detection = self.detect_device_family(platform=core.get("platform"), model=core.get("model"), sysdescr=version_text, hostname=core.get("hostname"))
            driver = self.driver_for(family=detection.family)
            if version_rc != 0 and driver.family == "unknown":
                payload = {"ok": False, "status": "ERROR", "target": raw_target, "core": core, "driver_family": "unknown", "error": "Core platform classification failed; no vendor command was assumed."}
                self.emit(payload, opts, payload["error"])
                return UNSUPPORTED
        if driver.family == "unknown" or not driver.command_templates.get("arp_lookup"):
            payload = {"ok": False, "status": "UNSUPPORTED", "target": raw_target, "core": core, "driver_family": driver.family, "error": "The core platform has no registered ARP lookup capability."}
            self.emit(payload, opts, payload["error"])
            return UNSUPPORTED

        lookup_value = target_ip
        if target_mac:
            styles = {
                "cisco-ios": self.canonical_mac(target_mac, "dotted"),
                "aruba-aos-switch": f"{target_mac[:6]}-{target_mac[6:]}",
                "aruba-aos-cx": self.canonical_mac(target_mac, "colon"),
                "ruckus-fastiron": target_mac,
            }
            lookup_value = styles.get(driver.family, self.canonical_mac(target_mac, "colon"))
        arp_command = driver.command_templates["arp_lookup"][0].format(lookup=lookup_value)
        self.live_log("lookup", f"ARP on {core.get('hostname') or core_ip} using {driver.family}")
        arp_rc, arp_out, arp_err = self.capture(self.legacy_cmd("netops-control", "show", core_ip, arp_command), opts.timeout or 120)
        arp_text = (arp_out or "") + (arp_err or "")
        evidence_parts.append(arp_text)
        arp_rows = parse_arp_output(arp_text, target_mac or target_ip)
        found_ip = str((arp_rows[0] if arp_rows else {}).get("ip") or (target_ip if not target_mac else ""))
        found_mac = str((arp_rows[0] if arp_rows else {}).get("mac") or target_mac)

        mac_rc = 0
        mac_text = ""
        fdb_rows: List[Dict[str, Any]] = []
        if found_mac:
            self.live_log("lookup", f"forwarding table on {core.get('hostname') or core_ip}")
            mac_rc, mac_out, mac_err = self.capture(
                self.legacy_cmd("netops-control", "mac-lookup", core_ip, self.canonical_mac(found_mac, "dotted")),
                opts.timeout or 120,
            )
            mac_text = (mac_out or "") + (mac_err or "")
            evidence_parts.append(mac_text)
            fdb_rows = parse_mac_table_output(mac_text, found_mac)

        port = str((fdb_rows[0] if fdb_rows else {}).get("port") or "")
        vlan = str((fdb_rows[0] if fdb_rows else {}).get("vlan") or "")
        description = ""
        interface_rc: Optional[int] = None
        interface_command = ""
        if port and driver.command_templates.get("interface_health"):
            interface_command = driver.command_templates["interface_health"][0].format(interface=port)
            interface_rc, interface_out, interface_err = self.capture(
                self.legacy_cmd("netops-control", "show", core_ip, interface_command),
                opts.timeout or 120,
            )
            interface_text = (interface_out or "") + (interface_err or "")
            evidence_parts.append(interface_text)
            description_match = re.search(r"(?im)^\s*description\s*(?::|\s)\s*(.+?)\s*$", clean_network_output(interface_text))
            if description_match:
                description = description_match.group(1).strip()

        observed = now()
        status = "FOUND" if fdb_rows else ("ARP_ONLY" if arp_rows else "NOT_FOUND")
        payload = {
            "ok": bool(arp_rows or fdb_rows),
            "complete": bool(fdb_rows and port),
            "status": status,
            "query": raw_target,
            "core": {"ip": core_ip, "name": core.get("hostname") or core_ip, "platform": core.get("platform") or "Unknown"},
            "driver_family": driver.family,
            "ip": found_ip,
            "mac": self.canonical_mac(found_mac, "dotted") if found_mac else "",
            "vlan": vlan,
            "port": port,
            "description": description,
            "arp": arp_rows,
            "forwarding_table": fdb_rows,
            "commands": {"arp": arp_command, "interface": interface_command},
            "exit_codes": {"arp": arp_rc, "mac": mac_rc if found_mac else None, "interface": interface_rc},
            "observed_at": observed,
            "observed_at_iso": fmt_time(observed),
        }
        combined_evidence = "\n".join(evidence_parts)
        with contextlib.suppress(Exception):
            self.state.record_core_lookup(raw_target, combined_evidence, 0 if payload["ok"] else max(arp_rc, mac_rc))
        if fdb_rows:
            with contextlib.suppress(Exception):
                self.state.record_mac_observation(found_mac, core_ip, str(core.get("hostname") or core_ip), port, vlan, str(fdb_rows[0].get("entry_type") or ""))
        text = (
            f"Core lookup: {status}\n"
            f"Core: {core.get('hostname') or core_ip} ({core_ip}) | Driver: {driver.family}\n"
            f"IP: {found_ip or 'not found'} | MAC: {payload['mac'] or 'not found'} | VLAN: {vlan or 'unknown'} | Port: {port or 'unknown'}\n"
            f"Description: {description or 'not available'}\nRecorded: {payload['observed_at_iso']}"
        )
        self.emit(payload, opts, text)
        return SUCCESS if payload["complete"] else PARTIAL

    def lookup_mac_all(self, mac: str, opts: GlobalOptions, pattern: str = "") -> int:
        mac = self.canonical_mac(mac, "dotted") or mac.strip()
        if not mac:
            return self.usage_error("lookup", "mac", opts, "Missing MAC address.", "netops lookup mac all 0200.0000.0025", VALIDATION)
        targets = self.current_switch_targets(opts, pattern)
        if opts.dry_run:
            rows = [{"target": clean_display_name(r.get("hostname") or r.get("ip")), "ip": r.get("ip"), "command": shlex.join(self.legacy_cmd("netops-control", "mac-lookup", str(r.get("ip")), mac))} for r in targets]
            self.emit({"ok": True, "dry_run": True, "scope": "all", "mac": mac, "targets": rows, "count": len(rows)}, opts, self.render_table(rows, ["target", "ip", "command"]))
            return SUCCESS
        if not targets:
            self.emit({"ok": False, "scope": "all", "mac": mac, "rows": [], "count": 0, "error": "no current online switch targets matched"}, opts, "No current online switch targets matched.")
            return PARTIAL
        results: List[Dict[str, Any]] = []
        found = False
        for idx, row in enumerate(targets, 1):
            ip = str(row.get("ip") or "").strip()
            name = clean_display_name(row.get("hostname") or ip)
            self._progress_update(f"[STATUS] lookup mac all {idx}/{len(targets)} {name}", opts)
            rc, out, err = self.capture(self.legacy_cmd("netops-control", "mac-lookup", ip, mac), opts.timeout or 90)
            text = (out or "") + (err or "")
            with contextlib.suppress(Exception): self.state.record_core_lookup(ip, text, rc)
            parsed_hits = parse_mac_table_output(text, mac)
            hit = rc == 0 and bool(parsed_hits)
            for parsed in parsed_hits:
                with contextlib.suppress(Exception):
                    self.state.record_mac_observation(mac, ip, name, str(parsed.get("port") or ""), str(parsed.get("vlan") or ""), str(parsed.get("entry_type") or ""))
            found = found or hit
            excerpt = " ".join(strip_ansi(text).split())[:240]
            results.append({"target": name, "ip": ip, "status": "FOUND" if hit else ("ERROR" if rc else "checked"), "exit_code": rc, "excerpt": excerpt})
        self._progress_clear(opts)
        payload = {"ok": found, "scope": "all", "mac": mac, "rows": results, "count": len(results), "found": sum(1 for r in results if r.get("status") == "FOUND")}
        text = f"MAC lookup across {len(results)} switch(es): {payload['found']} hit(s).\n" + self.render_table(results, ["status", "target", "ip", "exit_code", "excerpt"])
        self.emit(payload, opts, text)
        return SUCCESS if found else PARTIAL

    def cmd_lookup(self,args:List[str],opts:GlobalOptions)->int:
        if self.handle_help("lookup", args, opts): return SUCCESS
        verb=args[0] if args else "core"; rest=args[1:]
        if verb=="core":
            if not rest: return self.usage_error("lookup","core",opts,"Missing IP or MAC.","netops lookup core 198.51.100.92")
            if len(rest) > 1: return self.usage_error("lookup","core",opts,"Core lookup accepts exactly one IP or MAC.","netops lookup core 198.51.100.92",VALIDATION)
            return self.core_lookup_workflow(rest[0], opts)
        if verb=="mac":
            if not rest: return self.usage_error("lookup","mac",opts,"Missing MAC address.","netops lookup mac 0200.0000.0025")
            subaction=rest[0].lower()
            if subaction == "registry":
                action = rest[1].lower() if len(rest) > 1 else "status"
                registry = IeeeMacRegistry(self.paths.mac_registry_dir)
                if action == "refresh":
                    if opts.dry_run:
                        command = [self.paths.tool("netops"), "lookup", "mac", "registry", "refresh"]
                        self.emit({"ok": True, "dry_run": True, "command": shlex.join(command)}, opts, f"Dry run: {shlex.join(command)}")
                        return SUCCESS
                    payload = registry.refresh(force=True, timeout=opts.timeout or 15)
                    text = f"IEEE MAC registry refresh: {payload['available_registries']}/{payload['required_registries']} registries available\n" + self.render_table(payload["rows"], ["registry", "status", "rows", "fetched_at_iso", "error"])
                    self.emit(payload, opts, text)
                    return SUCCESS if payload.get("complete") else PARTIAL
                if action != "status":
                    return self.usage_error("lookup", "mac-registry", opts, f"Unknown registry action: {action}", "netops lookup mac registry refresh", VALIDATION)
                manifest = registry._manifest()
                rows = list((manifest.get("registries") or {}).values())
                payload = {"ok": bool(rows), "provider": manifest.get("provider") or "IEEE Registration Authority", "provider_url": manifest.get("provider_url"), "updated_at": manifest.get("updated_at"), "updated_at_iso": manifest.get("updated_at_iso") or "never", "rows": rows, "cache_dir": str(self.paths.mac_registry_dir)}
                self.emit(payload, opts, f"IEEE MAC registry cache: {payload['updated_at_iso']}\n" + (self.render_table(rows, ["registry", "prefix_bits", "rows", "fetched_at_iso", "sha256"]) if rows else "No registry cache exists. Run: netops lookup mac registry refresh"))
                return SUCCESS if rows else PARTIAL
            if subaction in {"inspect","vendor","online","history","locate","profile"}:
                if len(rest)<2: return self.usage_error("lookup",f"mac-{subaction}",opts,"Missing MAC address.",f"netops lookup mac {subaction} 0200.0000.0025")
                mac=rest[1]
                if subaction=="inspect":
                    try: payload=self.mac_cached_payload(mac,opts.limit)
                    except ValueError as exc: return self.usage_error("lookup","mac-inspect",opts,str(exc),"netops lookup mac inspect 0200.0000.0025",VALIDATION)
                    self.emit(payload,opts,self.render_mac_cached(payload)); return SUCCESS if payload.get("ok") else PARTIAL
                if subaction in {"vendor", "online"}:
                    clean=norm_mac(mac)
                    if not clean: return self.usage_error("lookup","mac-vendor",opts,"MAC must be a valid physical unicast address.","netops lookup mac vendor 00:00:5e:00:53:01",VALIDATION)
                    flags = set(rest[2:])
                    invalid_flags = flags - {"--online", "--refresh", "--offline"}
                    if invalid_flags:
                        return self.usage_error("lookup", "mac-vendor", opts, f"Unknown MAC vendor option: {sorted(invalid_flags)[0]}", "netops lookup mac online <mac> [--refresh|--offline]", VALIDATION)
                    use_online = subaction == "online" or "--online" in flags or "--refresh" in flags
                    if use_online:
                        if opts.dry_run:
                            command = [self.paths.tool("netops"), "lookup", "mac", subaction, self.canonical_mac(clean, "colon")]
                            command.extend(sorted(flags))
                            self.emit({"ok": True, "dry_run": True, "command": shlex.join(command)}, opts, f"Dry run: {shlex.join(command)}")
                            return SUCCESS
                        try:
                            payload = lookup_ieee_mac(
                                self.paths.mac_registry_dir,
                                clean,
                                refresh="--refresh" in flags,
                                offline="--offline" in flags,
                                timeout=opts.timeout or 15,
                            )
                        except ValueError as exc:
                            return self.usage_error("lookup", "mac-online", opts, str(exc), "netops lookup mac online 00:00:5e:00:53:01", VALIDATION)
                        payload["local_fallback"] = lookup_oui(clean)
                        organization = payload.get("organization") or "Unknown"
                        detail = (
                            f"{self.canonical_mac(clean, 'dotted')}: {organization}\n"
                            f"Registry: {payload.get('registry') or 'no assignment'} | Assignment: {payload.get('assignment') or 'unknown'} /{payload.get('prefix_bits') or '?'} | Block size: {payload.get('block_size') or 'unknown'}\n"
                            f"Organization address: {payload.get('organization_address') or 'not published'}\n"
                            f"Registry recorded: {payload.get('registry_updated_at_iso') or 'unknown'}\n"
                            f"Source: {payload.get('provider')} ({payload.get('provider_url')})\n{payload.get('note') or ''}"
                        )
                        self.emit(payload, opts, detail)
                        return SUCCESS if payload.get("ok") else PARTIAL
                    payload={"ok":True,"mac":self.canonical_mac(clean,"dotted"),"oui":lookup_oui(clean),"note":"Local OUI data identifies the registered organization, not an exact model. Use 'netops lookup mac online <mac>' for the cached IEEE MA-L/MA-M/MA-S registries."}
                    self.emit(payload,opts,f"{payload['mac']}: {payload['oui'].get('vendor') or 'Unknown'} ({payload['oui'].get('prefix') or 'no prefix match'})\n{payload['note']}"); return SUCCESS
                if subaction=="history":
                    try: payload=self.mac_cached_payload(mac,opts.limit)
                    except ValueError as exc: return self.usage_error("lookup","mac-history",opts,str(exc),"netops lookup mac history 0200.0000.0025",VALIDATION)
                    combined=(payload.get("relationship_history") or [])+(payload.get("inventory_history") or [])
                    combined.sort(key=lambda row:(int(row.get("created_at") or 0),int(row.get("id") or 0)),reverse=True)
                    payload={**payload,"rows":combined[:opts.limit],"count":len(combined)}
                    self.emit(payload,opts,self.render_table(payload["rows"],["version_label","created_at","event_type","rel_type","subject_id","object_id","switch_ip","switch_port","source"])); return SUCCESS if combined else PARTIAL
                scope=rest[2] if len(rest)>2 and not rest[2].startswith("--") else "all"
                return self.locate_mac_live(mac,opts,scope,profile=subaction=="profile")
            if len(rest)==1 and norm_mac(rest[0]):
                payload=self.mac_cached_payload(rest[0],opts.limit)
                self.emit(payload,opts,self.render_mac_cached(payload)); return SUCCESS if payload.get("ok") else PARTIAL
            if rest[0].lower() == "all":
                if len(rest) < 2: return self.usage_error("lookup","mac",opts,"Missing MAC address after all.","netops lookup mac all 0200.0000.0025")
                return self.lookup_mac_all(rest[1], opts)
            if opts.all:
                return self.lookup_mac_all(rest[-1], opts, " ".join(rest[:-1]).strip())
            cmd=self.legacy_cmd("netops-control","mac-lookup",*rest); rc,out,err=self.capture(cmd,opts.timeout or 120); text=(out or "")+(err or "")
            with contextlib.suppress(Exception): self.state.record_core_lookup(" ".join(rest),text,rc)
            if opts.json: self.emit({"ok":rc==0,"target":" ".join(rest),"exit_code":rc,"output":out,"stderr":err},opts)
            else:
                if out: print(out,end="")
                if err: eprint(err.rstrip())
            return rc
        return self.unknown_action("lookup", verb, opts)

    def cmd_diagnose(self,args:List[str],opts:GlobalOptions)->int:
        if self.handle_help("diagnose", args, opts): return SUCCESS
        verb=args[0] if args else "latency"; rest=args[1:]
        if verb in {"core-ping","point-ping","truth-ping"}:
            if not rest: return self.usage_error("diagnose","core-ping",opts,"Missing destination device/IP.","netops diagnose core-ping 192.0.2.50 --count 5")
            target=rest[0]; core=opts.source; count=5; packet_timeout=2; i=1
            while i<len(rest):
                if rest[i] in {"--core","--source"} and i+1<len(rest): core=rest[i+1]; i+=2
                elif rest[i] in {"--count","-c"} and i+1<len(rest):
                    try: count=int(rest[i+1])
                    except ValueError: return self.usage_error("diagnose","core-ping",opts,"Count must be an integer.","netops diagnose core-ping 192.0.2.50 --count 5",VALIDATION)
                    i+=2
                elif rest[i]=="--packet-timeout" and i+1<len(rest):
                    try: packet_timeout=int(rest[i+1])
                    except ValueError: return self.usage_error("diagnose","core-ping",opts,"Packet timeout must be an integer.","netops diagnose core-ping 192.0.2.50 --packet-timeout 2",VALIDATION)
                    i+=2
                else: return self.usage_error("diagnose","core-ping",opts,f"Unknown option: {rest[i]}","netops help diagnose core-ping",VALIDATION)
            return self.point_of_truth_ping(target,opts,core,count,packet_timeout)
        if verb=="latency":
            if not rest: return self.usage_error("diagnose","latency",opts,"Missing target.","netops diagnose latency 1.1.1.1")
            target=normalize_target_literal(rest[0]); extra=[]; i=1
            while i < len(rest):
                if rest[i] in {"--count","-c"} and i+1<len(rest): extra += ["-c",rest[i+1]]; i+=2
                elif rest[i] in {"--port","-p"} and i+1<len(rest): extra += ["-p",rest[i+1]]; i+=2
                else: extra.append(rest[i]); i+=1
            if opts.json and "--json" not in extra: extra.append("--json")
            return self.run_subprocess(self.legacy_cmd("netops-probe",target,*extra),opts)
        if verb=="speed":
            runs=None; ca_file=""; profile="balanced"; i=0
            while i < len(rest):
                if rest[i] in {"--runs","--speed-runs"} and i+1<len(rest):
                    try: runs=int(rest[i+1])
                    except ValueError: return self.usage_error("diagnose","speed",opts,"Runs must be an integer from 1 to 5.","netops diagnose speed --profile quick",VALIDATION)
                    i+=2
                elif rest[i]=="--profile" and i+1<len(rest): profile=rest[i+1].lower(); i+=2
                elif rest[i]=="--quick": profile="quick"; i+=1
                elif rest[i]=="--thorough": profile="thorough"; i+=1
                elif rest[i]=="--ca-file" and i+1<len(rest): ca_file=rest[i+1]; i+=2
                else: return self.usage_error("diagnose","speed",opts,f"Unknown option: {rest[i]}","netops help diagnose speed",VALIDATION)
            if profile not in {"quick","balanced","thorough"}: return self.usage_error("diagnose","speed",opts,"Profile must be quick, balanced, or thorough.","netops diagnose speed --profile quick",VALIDATION)
            if runs is None: runs={"quick":1,"balanced":2,"thorough":3}[profile]
            if not 1 <= runs <= 5: return self.usage_error("diagnose","speed",opts,"Runs must be from 1 to 5.","netops diagnose speed --profile quick",VALIDATION)
            if profile != "quick" and runs < 2: return self.usage_error("diagnose","speed",opts,"Balanced/thorough profiles require at least 2 runs; use --profile quick for a one-server check.","netops diagnose speed --profile quick",VALIDATION)
            return self.internet_speed_diagnostic(runs,ca_file,opts,profile)
        if verb in {"throughput","iperf","iperf3"}:
            if not rest: return self.usage_error("diagnose","throughput",opts,"Missing controlled iperf3 server.","netops diagnose throughput 203.0.113.20",VALIDATION)
            server=rest[0]; port=5201; seconds=10; parallel=1; direction="both"; bind=opts.source; i=1
            while i<len(rest):
                if rest[i] in {"--port","-p"} and i+1<len(rest):
                    try: port=int(rest[i+1])
                    except ValueError: return self.usage_error("diagnose","throughput",opts,"Port must be an integer.","netops diagnose throughput 203.0.113.20 --port 5201",VALIDATION)
                    i+=2
                elif rest[i] in {"--seconds","--time","-t"} and i+1<len(rest):
                    try: seconds=int(rest[i+1])
                    except ValueError: return self.usage_error("diagnose","throughput",opts,"Seconds must be an integer.","netops diagnose throughput 203.0.113.20 --seconds 10",VALIDATION)
                    i+=2
                elif rest[i] in {"--parallel","-P"} and i+1<len(rest):
                    try: parallel=int(rest[i+1])
                    except ValueError: return self.usage_error("diagnose","throughput",opts,"Parallel streams must be an integer.","netops diagnose throughput 203.0.113.20 --parallel 2",VALIDATION)
                    i+=2
                elif rest[i]=="--direction" and i+1<len(rest): direction=rest[i+1].lower(); i+=2
                elif rest[i] in {"--bind","--source"} and i+1<len(rest): bind=rest[i+1]; i+=2
                else: return self.usage_error("diagnose","throughput",opts,f"Unknown option: {rest[i]}","netops help diagnose throughput",VALIDATION)
            return self.throughput_diagnostic(server,port,seconds,parallel,direction,bind,opts)
        if verb in {"port-health","port","interface-health"}:
            if len(rest)<3 or rest[1] != "on": return self.usage_error("diagnose","port-health",opts,"Use: netops diagnose port-health <device> on <interface>","netops diagnose port-health ZONE34 on Gi1/0/7",VALIDATION)
            target=rest[0]; interface=rest[2]; sample_seconds=5; expected_speed=0; i=3
            while i<len(rest):
                if rest[i] in {"--sample-seconds","--sample","--interval"} and i+1<len(rest):
                    try: sample_seconds=int(rest[i+1])
                    except ValueError: return self.usage_error("diagnose","port-health",opts,"Sample seconds must be an integer.","netops diagnose port-health ZONE34 on Gi1/0/7 --sample-seconds 5",VALIDATION)
                    i+=2
                elif rest[i] in {"--expected-speed","--speed"} and i+1<len(rest):
                    try: expected_speed=int(rest[i+1])
                    except ValueError: return self.usage_error("diagnose","port-health",opts,"Expected speed must be integer Mbps.","netops diagnose port-health ZONE34 on Gi1/0/7 --expected-speed 1000",VALIDATION)
                    i+=2
                else: return self.usage_error("diagnose","port-health",opts,f"Unknown option: {rest[i]}","netops help diagnose port-health",VALIDATION)
            return self.port_health_diagnostic(target,interface,sample_seconds,expected_speed,opts)
        if verb in {"cable","tdr","cable-test"}:
            if len(rest)<3 or rest[1] != "on": return self.usage_error("diagnose","cable",opts,"Use: netops diagnose cable <device> on <interface>","netops diagnose cable ZONE34 on Gi1/0/7",VALIDATION)
            target=rest[0]; interface=rest[2]; start_test=verb in {"tdr","cable-test"}; wait_seconds=8; i=3
            while i<len(rest):
                if rest[i] in {"--test","--start"}: start_test=True; i+=1
                elif rest[i]=="--wait" and i+1<len(rest):
                    try: wait_seconds=int(rest[i+1])
                    except ValueError: return self.usage_error("diagnose","cable",opts,"Wait must be an integer number of seconds.","netops diagnose cable ZONE34 on Gi1/0/7 --test --wait 8 --dry-run",VALIDATION)
                    i+=2
                else: return self.usage_error("diagnose","cable",opts,f"Unknown option: {rest[i]}","netops help diagnose cable",VALIDATION)
            return self.cable_diagnostic(target,interface,start_test,wait_seconds,opts)
        if verb=="doctor":
            online=False
            for item in rest:
                if item=="--online": online=True
                else: return self.usage_error("diagnose","doctor",opts,f"Unknown option: {item}","netops help diagnose doctor",VALIDATION)
            return self.diagnostics_doctor(online,opts)
        if verb=="filtering":
            target=rest[0] if rest else "google.com"; cmd=[self.paths.tool("netops-legacy"),"check"]
            if opts.json: cmd.append("--json")
            if target: cmd.append(target)
            return self.run_subprocess(cmd,opts)
        if verb=="interface":
            if len(rest)<3 or rest[1] != "on": return self.usage_error("diagnose","interface",opts,"Use: netops diagnose interface <device> on <interface>","netops diagnose interface ZONE34 on Gi1/0/7")
            device, choices = self._diagnostic_device(rest[0])
            if not device:
                labels = ", ".join(str(row.get("hostname") or row.get("ip")) for row in choices[:8])
                return self.usage_error("diagnose", "interface", opts, f"Device could not be resolved: {rest[0]}" + (f" ({labels})" if labels else ""), "netops diagnose interface <device> on <interface>", VALIDATION)
            cmd=[self.paths.tool("netops-legacy"),"interface",str(device.get("ip") or rest[0]),*rest[1:]]
            if opts.json and "--json" not in cmd: cmd.append("--json")
            return self.run_subprocess(cmd,opts)
        return self.unknown_action("diagnose", verb, opts)

    def extract_site_or_target(self,q:str)->str:
        text = str(q or "")
        direct = re.search(r"\b(?:ip(?: address)?|address|mac(?: address)?|hostname)\s+(?:of\s+)?(?:the\s+)?([A-Za-z0-9_.:/-]{2,80})\b", text, re.I)
        if direct:
            return re.sub(r"(?:switch|ap|device|router)$", "", direct.group(1), flags=re.I).strip(".,;:()[]{}")
        quoted = re.search(r'[\'"]([A-Za-z0-9_.:/ -]{2,80})[\'"]', text)
        if quoted:
            return quoted.group(1).strip(".,;:()[]{}")
        loc = re.search(r"\b(?:list|show|count|find|give me|how many)?\s*(?:the\s+)?(?:switches|devices|aps|access points)?\s*(?:in|at|for|site|building|location)\s+(?:the\s+)?([A-Za-z0-9_.:/ -]{2,80})\b", text, re.I)
        if loc:
            captured = loc.group(1).strip(".,;:()[]{}")
            captured = re.sub(r"\b(?:switches|switch|devices|device|aps|ap|routers|router)$", "", captured, flags=re.I).strip()
            return captured
        m=re.search(r"\b([A-Za-z]{1,10}\d{1,10}[A-Za-z0-9_.:-]{0,32})\b",text)
        if m: return m.group(1).strip(".,;:()[]{}")
        words=[w.strip(".,;:()[]{}").strip() for w in text.strip().split() if w.strip(".,;:()[]{}").lower() not in {"switch","switches","device","devices","ap","aps","router","routers","the","a","an","ip","address","of","what","is","are","give","me","list","show","mac","on","in","at","for"}]
        return " ".join(words[-2:]) if len(words) >= 2 else (words[-1] if words else "")
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
    def ui_options(self)->Dict[str,Any]:
        targets=[{"label":r.get("hostname") or r.get("ip"),"value":r.get("ip"),"kind":"device"} for r in self.state.rows("SELECT ip,hostname,status FROM devices ORDER BY hostname LIMIT 30")]
        return {"targets":targets or [{"label":"Localhost","value":"127.0.0.1","kind":"host"}],"domains":[{"label":"Google","value":"google.com"},{"label":"Cloudflare","value":"cloudflare.com"},{"label":"Example","value":"example.com"}],"speed_profiles":["quick","balanced","thorough"],"speed_runs":["1","2","3","4","5"],"core_iperf_server":self.config.public.get("core_iperf_server") or "","quick_actions":[{"id":"health-check","label":"Fast health"},{"id":"workflow-refresh-inventory","label":"Refresh inventory"},{"id":"diagnose-doctor","label":"Diagnostic readiness"},{"id":"diagnose-speed","label":"Internet speed"}]}
    def create_job(self,action:str,args:Dict[str,Any],context:Optional[Dict[str,Any]]=None)->Dict[str,Any]:
        if self.stopping.is_set(): raise RuntimeError("NetOps is stopping and cannot accept another job.")
        context = dict(context or {})
        spec = self.command_spec(action)
        if not spec: raise ValueError(f"Unknown action: {action}")
        if not spec.run_supported or spec.risk_level == "danger": raise PermissionError("This action is preview-only and cannot run as a background job.")
        if spec.risk_level == "config":
            preview = self.preview_for_action(action, args)
            expected_hash = self.preview_hash_for_action(action, args, preview)
            target = str(args.get("target") or args.get("device") or "TARGET").strip()
            interface = str(args.get("interface") or args.get("port") or "").strip()
            expected_phrase = " ".join(part for part in ("APPLY", target, interface) if part)
            if str(context.get("preview_hash") or "") != expected_hash or not str(context.get("reason") or "") or not str(context.get("ticket") or "") or str(context.get("typed_confirmation") or "") != expected_phrase:
                raise PermissionError("Configuration jobs require the matching preview, reason, ticket, and exact typed confirmation.")
        if spec.output_type == "terminal": raise PermissionError("Interactive terminal actions cannot run as background jobs.")
        cmd,ro,wl=self.command_for_action(action,args)
        if context.get("structured") and "--json" not in cmd:
            cmd.append("--json")
        jid=uuid.uuid4().hex[:12]
        request_payload=redact_for_api({"action":action,"args":args,"context":context})
        job={
            "id":jid,"action":action,"command":shlex.join(cmd),"status":"queued","created_at":now(),
            "started_at":None,"finished_at":None,"exit_code":None,"read_only":ro,"writes_local":wl,
            "request_json":json.dumps(request_payload,sort_keys=True,default=str),"result_json":None,"summary":None,"duration_ms":None,
            "actor":str(context.get("actor") or "local"),"actor_uid":context.get("uid"),"session_id":str(context.get("session_id") or ""),
            "reason":str(context.get("reason") or ""),"ticket":str(context.get("ticket") or ""),"preview_hash":str(context.get("preview_hash") or ""),
            "parent_job_id":str(context.get("parent_job_id") or ""),"workflow_step":str(context.get("workflow_step") or ""),
            "logs":[],"process":None,"thread":None,"done":threading.Event(),"cancel_requested":False,"stream_closed":False,
        }
        with self.lock: self.jobs[jid]=job; self.log_queues[jid]=queue.Queue()
        with self.state.connect() as con:
            con.execute(
                "INSERT INTO jobs(id,action,command,status,created_at,read_only,writes_local,request_json,actor,actor_uid,session_id,reason,ticket,preview_hash,parent_job_id,workflow_step) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (jid,action,job["command"],"queued",job["created_at"],1 if ro else 0,1 if wl else 0,job["request_json"],job["actor"],job["actor_uid"],job["session_id"],job["reason"],job["ticket"],job["preview_hash"],job["parent_job_id"],job["workflow_step"]),
            )
        self.state.record_audit_event(
            "job_submitted",action,actor=job["actor"],actor_uid=job["actor_uid"],session_id=job["session_id"],
            target=str(args.get("target") or args.get("device") or ""),result="queued",reason=job["reason"],ticket=job["ticket"],
            preview_hash=job["preview_hash"],job_id=jid,detail={"args":args,"read_only":ro,"writes_local":wl},
        )
        worker=threading.Thread(target=self.run_job,args=(jid,cmd,action,ro),name=f"netops-job-{jid}",daemon=True)
        with self.lock: job["thread"]=worker
        worker.start(); return self.public_job(job)
    def public_job(self,job:Dict[str,Any])->Dict[str,Any]: return timestamp_row({k:v for k,v in job.items() if k not in {"process","thread","done","cancel_requested","stream_closed"}})
    def jobs_list(self)->List[Dict[str,Any]]:
        db=self.state.rows("SELECT id,action,command,status,created_at,started_at,finished_at,exit_code,read_only,writes_local,summary,duration_ms,actor,reason,ticket,preview_hash,parent_job_id,workflow_step FROM jobs ORDER BY COALESCE(created_at,started_at,0) DESC LIMIT 100"); live={jid:self.public_job(job) for jid,job in self.jobs.items()}
        return [timestamp_row(live.get(j.get("id"),j)) for j in db]
    def add_job_log(self,jid:str,stream:str,line:str,event_type:str="",payload:Optional[Dict[str,Any]]=None)->None:
        created_at=now()
        progress_match=re.search(r"\b(\d+)\s*/\s*(\d+)\b",line)
        phase_match=re.match(r"\[([A-Za-z0-9_-]+)\]",line)
        inferred_type=event_type or ("progress" if phase_match or progress_match else "log")
        phase=(phase_match.group(1).lower() if phase_match else "")
        progress_current=int(progress_match.group(1)) if progress_match else None
        progress_total=int(progress_match.group(2)) if progress_match else None
        payload_json=json.dumps(redact_for_api(payload or {}),sort_keys=True,default=str)
        with self.state.connect() as con:
            cursor=con.execute("INSERT INTO job_logs(job_id,created_at,stream,line,event_type,phase,progress_current,progress_total,payload_json) VALUES(?,?,?,?,?,?,?,?,?)",(jid,created_at,stream,line,inferred_type,phase,progress_current,progress_total,payload_json))
            log_id=int(cursor.lastrowid)
        item={"id":log_id,"created_at":created_at,"created_at_iso":fmt_time(created_at),"stream":stream,"line":line,"event_type":inferred_type,"phase":phase,"progress_current":progress_current,"progress_total":progress_total,"payload":payload or {}}
        with self.lock:
            job=self.jobs.get(jid); job.setdefault("logs",[]).append(item) if job is not None else None; q=self.log_queues.get(jid); q.put(item) if q is not None else None
    def set_job_status(self,jid:str,status:str,exit_code:Optional[int]=None)->bool:
        ts=now()
        with self.lock:
            job=self.jobs.get(jid)
            if job:
                current=str(job.get("status") or "")
                if current in {"completed","partial","failed","cancelled","stale"} and status != current:
                    return False
                job["status"]=status
                if status=="running": job["started_at"]=ts
                if status in {"completed","partial","failed","cancelled","stale"}: job["finished_at"]=ts; job["exit_code"]=exit_code
        with self.state.connect() as con:
            if status=="running": con.execute("UPDATE jobs SET status=?,started_at=? WHERE id=?",(status,ts,jid))
            elif status in {"completed","partial","failed","cancelled","stale"}: con.execute("UPDATE jobs SET status=?,finished_at=?,exit_code=? WHERE id=?",(status,ts,exit_code,jid))
            else: con.execute("UPDATE jobs SET status=? WHERE id=?",(status,jid))
        return True

    def _close_job_stream(self,jid:str)->None:
        with self.lock:
            job=self.jobs.get(jid)
            if not job or job.get("stream_closed"):
                return
            job["stream_closed"]=True
            q=self.log_queues.get(jid)
            if q is not None: q.put(None)

    def cancel_job(self,jid:str,reason:str="cancelled by operator",wait:float=2.0)->Tuple[bool,str]:
        with self.lock:
            job=self.jobs.get(jid)
            if not job:
                return False,"Job is not active in this NetOps process."
            status=str(job.get("status") or "")
            if status in {"completed","partial","failed","cancelled","stale"}:
                return False,f"Job is already {status}."
            if job.get("cancel_requested"):
                return True,"Cancellation is already in progress."
            job["cancel_requested"]=True
            proc=job.get("process")
        self.add_job_log(jid,"system",reason)
        self.set_job_status(jid,"cancelling")
        if proc is not None:
            self._terminate_process_group(proc,signal.SIGTERM,wait)
        self.set_job_status(jid,"cancelled",143)
        with self.lock:
            job=self.jobs.get(jid) or {}
        self.state.record_audit_event("job_cancelled",str(job.get("action") or "job"),actor=str(job.get("actor") or "local"),actor_uid=job.get("actor_uid"),session_id=str(job.get("session_id") or ""),result="cancelled",reason=reason,ticket=str(job.get("ticket") or ""),preview_hash=str(job.get("preview_hash") or ""),job_id=jid)
        return True,"cancelled"

    def shutdown_jobs(self,reason:str="cancelled because NetOps is stopping",wait:float=5.0)->int:
        self.stopping.set()
        with self.lock:
            active=[jid for jid,job in self.jobs.items() if str(job.get("status") or "") not in {"completed","partial","failed","cancelled","stale"}]
        for jid in active:
            self.cancel_job(jid,reason,min(1.5,max(0.1,wait)))
        deadline=time.monotonic()+max(0.0,wait)
        for jid in active:
            with self.lock:
                job=self.jobs.get(jid); worker=job.get("thread") if job else None
            if worker and worker is not threading.current_thread():
                worker.join(timeout=max(0.0,deadline-time.monotonic()))
        return len(active)
    def _read_stream(self,jid:str,pipe:Any,stream:str,captured:Optional[List[str]]=None)->None:
        if pipe is None: return
        try:
            for raw in iter(pipe.readline,""):
                line=raw.rstrip("\n")
                if captured is not None: captured.append(line)
                if line: self.add_job_log(jid,stream,line)
        finally:
            with contextlib.suppress(Exception): pipe.close()
    def run_job(self,jid:str,cmd:List[str],action:str,ro:bool)->None:
        with self.sem:
            proc=None
            started_monotonic=time.monotonic()
            captured_stdout:List[str]=[]; captured_stderr:List[str]=[]
            try:
                with self.lock:
                    job=self.jobs.get(jid)
                    if not job or job.get("cancel_requested") or str(job.get("status") or "") in {"cancelled","stale"}:
                        return
                if not self.set_job_status(jid,"running"):
                    return
                self.add_job_log(jid,"system","started: "+shlex.join(cmd)); proc=subprocess.Popen(cmd,cwd=str(self.paths.install_dir),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1,start_new_session=True)
                with self.lock:
                    job=self.jobs.get(jid)
                    if job is not None: job["process"]=proc
                    cancel_requested=bool(job and job.get("cancel_requested"))
                if cancel_requested:
                    self._terminate_process_group(proc,signal.SIGTERM,1.5)
                ts=[threading.Thread(target=self._read_stream,args=(jid,pipe,stream,captured),daemon=True) for stream,pipe,captured in (("stdout",proc.stdout,captured_stdout),("stderr",proc.stderr,captured_stderr))]
                [t.start() for t in ts]; code=normalized_exit_code(proc.wait()); self._terminate_process_group(proc,signal.SIGTERM,0.25); [t.join(timeout=1) for t in ts]
                with self.lock:
                    job=self.jobs.get(jid); cancelled=bool(job and job.get("cancel_requested"))
                if not cancelled and action in {"inventory-import-flat","inventory-scan","health-check","ap-scan","topology-scan","memory-refresh","backup-run","workflow-morning-check","workflow-refresh-inventory","workflow-backup-online","workflow-ap-audit"}:
                    try:
                        domains = (
                            ("device",) if action == "inventory-scan" else
                            ("ap",) if action == "ap-scan" else
                            ("topology",) if action == "topology-scan" else
                            ("device", "ap", "topology")
                        )
                        refresh = self.import_flat_state(domains, f"job:{action}")
                        self.add_job_log(jid,"system","canonical state refreshed",payload=refresh)
                    except Exception as exc:
                        self.add_job_log(jid,"stderr",f"canonical state refresh failed: {exc}","error")
                        if code==SUCCESS: code=PARTIAL
                with self.state.connect() as con: con.execute("INSERT INTO command_history(created_at,action,command,exit_code,read_only) VALUES(?,?,?,?,?)",(now(),action,shlex.join(cmd),code,1 if ro else 0))
                if not cancelled:
                    result_payload:Any=None
                    stdout_text="\n".join(captured_stdout).strip()
                    if stdout_text:
                        with contextlib.suppress(json.JSONDecodeError): result_payload=json.loads(stdout_text)
                    result_json=json.dumps(redact_for_api(result_payload),sort_keys=True,default=str) if result_payload is not None else None
                    if isinstance(result_payload,dict):
                        summary=str(result_payload.get("summary") or result_payload.get("answer") or result_payload.get("status") or "")
                    else: summary=""
                    duration_ms=max(0,int((time.monotonic()-started_monotonic)*1000))
                    with self.state.connect() as con:
                        con.execute("UPDATE jobs SET result_json=?,summary=?,duration_ms=? WHERE id=?",(result_json,summary,duration_ms,jid))
                    with self.lock:
                        job=self.jobs.get(jid)
                        if job is not None: job.update({"result_json":result_json,"summary":summary,"duration_ms":duration_ms})
                    self.add_job_log(jid,"system",f"finished with exit code {code}")
                    final_status = "completed" if code == SUCCESS else "partial" if code == PARTIAL else "failed"
                    self.set_job_status(jid,final_status,code)
                    with self.lock: audit_job=dict(self.jobs.get(jid) or {})
                    self.state.record_audit_event("job_finished",action,actor=str(audit_job.get("actor") or "local"),actor_uid=audit_job.get("actor_uid"),session_id=str(audit_job.get("session_id") or ""),result=final_status,reason=str(audit_job.get("reason") or ""),ticket=str(audit_job.get("ticket") or ""),preview_hash=str(audit_job.get("preview_hash") or ""),job_id=jid,detail={"exit_code":code,"duration_ms":duration_ms,"summary":summary})
            except Exception as exc:
                self._terminate_process_group(proc, signal.SIGKILL, 1)
                with self.lock:
                    job=self.jobs.get(jid); cancelled=bool(job and job.get("cancel_requested"))
                if not cancelled:
                    self.add_job_log(jid,"stderr",str(exc)); self.set_job_status(jid,"failed",INTERNAL)
                    with self.lock: audit_job=dict(self.jobs.get(jid) or {})
                    self.state.record_audit_event("job_failed",action,actor=str(audit_job.get("actor") or "local"),actor_uid=audit_job.get("actor_uid"),session_id=str(audit_job.get("session_id") or ""),result="failed",reason=str(audit_job.get("reason") or ""),ticket=str(audit_job.get("ticket") or ""),preview_hash=str(audit_job.get("preview_hash") or ""),job_id=jid,detail={"error":str(exc)})
            finally:
                with self.lock:
                    job=self.jobs.get(jid)
                    if job is not None:
                        job["process"]=None
                        done=job.get("done")
                        if done is not None: done.set()
                self._close_job_stream(jid)
    def cmd_serve(self,args:List[str],opts:GlobalOptions)->int:
        if self.handle_help("serve", args, opts): return SUCCESS
        host="127.0.0.1"; port=8787; i=0
        while i<len(args):
            if args[i]=="--host" and i+1<len(args): host=args[i+1]; i+=2
            elif args[i]=="--port" and i+1<len(args):
                try: port=int(args[i+1])
                except (TypeError,ValueError): return self.usage_error("serve","start",opts,"Port must be an integer.","netops serve --port 8787",VALIDATION)
                i+=2
            elif args[i] in {"--host","--port"}: return self.usage_error("serve","start",opts,f"Missing value for {args[i]}.","netops serve --host 127.0.0.1 --port 8787",USAGE)
            else: return self.usage_error("serve","start",opts,f"Unknown option: {args[i]}","netops serve --host 127.0.0.1 --port 8787",USAGE)
        if not 1 <= port <= 65535:
            return self.usage_error("serve","start",opts,"Port must be between 1 and 65535.","netops serve --port 8787",VALIDATION)
        try:
            loopback = host.lower() == "localhost" or ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = False
        if not loopback:
            return self.usage_error(
                "serve", "start", opts,
                "Non-loopback API binding is disabled until authenticated remote access is implemented.",
                "netops serve --host 127.0.0.1 --port 8787", AUTH,
            )
        stale = self.state.mark_stale_jobs()
        server=ThreadingHTTPServer((host,port),self.make_handler()); server.daemon_threads=True
        print(f"NetOps service: http://{host}:{port}" + (f" ({stale} stale job(s) reconciled)" if stale else ""),flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            return 130
        finally:
            server.server_close()
            self.shutdown_jobs()
        return SUCCESS
    def make_handler(self):
        app=self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,fmt:str,*args:Any)->None: return
            def send_json(self,obj:Any,status:int=200)->None:
                data=json.dumps(redact_for_api(obj),separators=(",",":")).encode(); self.send_response(status); self.send_header("Content-Type","application/json; charset=utf-8"); self.send_header("Cache-Control","no-store"); self.send_header("Content-Length",str(len(data))); self.end_headers(); self.wfile.write(data)
            def read_body_json(self)->Dict[str,Any]:
                length=int(self.headers.get("Content-Length","0") or "0"); return json.loads(self.rfile.read(length).decode()) if length>0 else {}
            def do_GET(self)->None:
                p=urlparse(self.path); path=p.path; qs=parse_qs(p.query)
                try:
                    if path=="/": self.send_html(); return
                    if not path.startswith("/api/") and self.send_static(path): return
                    if path=="/api/health": self.send_json({"ok":True,"version":VERSION,"paths":{"db":str(app.paths.sqlite_db),"cache_dir":str(app.paths.cache_dir),"config_file":str(app.paths.config_file)},"counts":app.state.counts(),"config":app.config.public_safe()}); return
                    if path=="/api/webui/status": self.send_json(app.webui_status_payload()); return
                    if path=="/api/health/timeline": self.send_json({"ok":True,"rows":app.state.rows("SELECT * FROM health_events ORDER BY created_at DESC,id DESC LIMIT ?",(clean_limit(qs.get("limit",[100])[0],100,300),))}); return
                    if path=="/api/inventory/detail": self.send_json(app.inventory_detail_payload(qs.get("kind",["device"])[0], qs.get("target",[""])[0], clean_limit(qs.get("limit",[80])[0],80,300))); return
                    if path=="/api/inventory/history": self.send_json(app.inventory_history_payload(qs.get("q",[""])[0], clean_limit(qs.get("limit",[100])[0],100,300))); return
                    if path=="/api/devices": q=(qs.get("q",[""])[0] or "").lower(); rows=app.state.rows("SELECT * FROM devices ORDER BY status DESC,hostname,ip"); self.send_json([r for r in rows if not q or q in json.dumps(r).lower()]); return
                    if path=="/api/aps":
                        q=(qs.get("q",[""])[0] or "").strip()
                        status=(qs.get("status",[""])[0] or "").strip().upper()
                        limit=clean_limit(qs.get("limit",[500])[0],500,2000)
                        self.send_json(app.reconciled_ap_rows(q, GlobalOptions(limit=limit,status=status)))
                        return
                    if path=="/api/neighbors": self.send_json(app.state.rows("SELECT * FROM neighbors ORDER BY local_name,local_port")); return
                    if path in {"/api/topology","/api/topology/graph"}: self.send_json(app.topology_graph_payload(clean_limit(qs.get("limit",[500])[0],500,1500))); return
                    if path=="/api/topology/changes": self.send_json(app.state.rows("SELECT * FROM topology_events ORDER BY created_at DESC,id DESC LIMIT ?",(clean_limit(qs.get("limit",[100])[0],100,300),))); return
                    if path=="/api/history": self.send_json(app.version_rows(app.state.rows("SELECT * FROM relationship_events ORDER BY created_at DESC,id DESC LIMIT ?",(clean_limit(qs.get("limit",[100])[0],100,300),)))); return
                    if path=="/api/memory/switch": target=(qs.get("target",qs.get("q",[""]))[0] or "").strip(); self.send_json(app.memory_switch_payload(target,GlobalOptions(limit=clean_limit(qs.get("limit",[100])[0],100,300))) if target else {"ok":False,"error":"missing target"},200 if target else 400); return
                    if path=="/api/memory/timeline": q=(qs.get("q",[""])[0] or "").strip(); self.send_json(app.relationship_timeline_payload(q, clean_limit(qs.get("limit",[100])[0],100,300))); return
                    if path=="/api/memory/query": self.send_json(app.memory_query_payload(qs.get("mode",["switch"])[0], qs.get("target",qs.get("q",[""]))[0], qs.get("port",[""])[0], clean_limit(qs.get("limit",[100])[0],100,300))); return
                    if path=="/api/attention": self.send_json(app.attention_payload(clean_limit(qs.get("limit",[80])[0],80,300))); return
                    if path=="/api/backups": self.send_json(app.state.rows("SELECT * FROM backup_history ORDER BY created_at DESC,id DESC LIMIT ?",(clean_limit(qs.get("limit",[100])[0],100,300),))); return
                    if path=="/api/workflows": self.send_json(app.workflows_payload()); return
                    if path=="/api/diagnostics": self.send_json(app.diagnostics_payload(clean_limit(qs.get("limit",[80])[0],80,300))); return
                    if path=="/api/automation": self.send_json(app.automation_payload()); return
                    if path=="/api/jobs": self.send_json(app.jobs_list()); return
                    if path.startswith("/api/jobs/") and path.endswith("/events"):
                        try: after=max(0,int(qs.get("after",[0])[0] or 0))
                        except (TypeError,ValueError): after=0
                        self.send_events(path.split("/")[3],after); return
                    if path.startswith("/api/jobs/"):
                        jid=path.split("/")[3]; job=app.state.one("SELECT * FROM jobs WHERE id=?",(jid,)); logs=timestamp_rows(app.state.rows("SELECT id,created_at,stream,line FROM job_logs WHERE job_id=? ORDER BY id",(jid,))); self.send_json({"job":timestamp_row(job),"logs":logs} if job else {"error":"job not found"},200 if job else 404); return
                    if path=="/api/options": self.send_json(app.ui_options()); return
                    if path=="/api/commands": self.send_json(app.command_payload()); return
                    if path=="/api/settings": self.send_json(app.config.public_safe()); return
                    self.send_json({"error":"not found"},404)
                except Exception as exc: self.send_json({"error":str(exc)},500)
            def do_POST(self)->None:
                path=urlparse(self.path).path
                try:
                    if path=="/api/ask":
                        body=self.read_body_json()
                        limit=clean_limit(body.get("limit",100),100,500)
                        opts=GlobalOptions(limit=limit)
                        session=body.get("session") if isinstance(body.get("session"),dict) else {}
                        question=body.get("question",body.get("q",""))
                        payload=app.ask_payload(question,opts,session=session)
                        app.natural_ask.update_session(question,payload,session)
                        payload["session"]=session
                        self.send_json(payload,200)
                        return
                    if path=="/api/jobs":
                        body=self.read_body_json()
                        try: self.send_json(app.create_job(body.get("action",""),body.get("args",{}) or {}),201)
                        except PermissionError as exc: self.send_json({"ok":False,"error":str(exc)},403)
                        except ValueError as exc: self.send_json({"ok":False,"error":str(exc)},400)
                        return
                    if path=="/api/preview":
                        body=self.read_body_json(); action=body.get("action",""); args=body.get("args",{}) or {}
                        try: self.send_json(app.preview_for_action(action,args))
                        except ValueError as exc: self.send_json({"ok":False,"error":str(exc)},400)
                        return
                    if path.startswith("/api/jobs/") and path.endswith("/cancel"):
                        jid=path.split("/")[3]
                        cancelled,message=app.cancel_job(jid)
                        self.send_json({"ok":cancelled,"id":jid,"status":"cancelled" if cancelled else "unchanged","message":message},200 if cancelled else 409)
                        return
                    self.send_json({"error":"not found"},404)
                except PermissionError as exc: self.send_json({"blocked":True,"reason":str(exc)},200)
                except Exception as exc: self.send_json({"error":str(exc)},400)
            def topology_nodes(self)->List[Dict[str,str]]:
                seen={}
                for r in app.state.rows("SELECT local_ip,local_name,remote_ip,remote_name FROM neighbors"):
                    if r.get("local_ip"): seen[r["local_ip"]]=r.get("local_name") or r["local_ip"]
                    if r.get("remote_ip") and r.get("remote_ip")!="?.?.?.?": seen[r["remote_ip"]]=r.get("remote_name") or r["remote_ip"]
                return [{"id":k,"label":v} for k,v in sorted(seen.items(),key=lambda x:x[1].lower())]
            def send_events(self,jid:str,after_id:int=0)->None:
                self.send_response(200); self.send_header("Content-Type","text/event-stream"); self.send_header("Cache-Control","no-store"); self.send_header("Connection","close"); self.end_headers(); self.close_connection=True
                def emit(o:Any)->None: self.wfile.write(("data: "+json.dumps(o,separators=(",",":"))+"\n\n").encode()); self.wfile.flush()
                last_id=max(0,int(after_id or 0)); heartbeat_at=time.monotonic()+20
                try:
                    while True:
                        rows=app.state.rows("SELECT id,created_at,stream,line FROM job_logs WHERE job_id=? AND id>? ORDER BY id",(jid,last_id))
                        for item in rows:
                            last_id=max(last_id,int(item.get("id") or 0)); emit(timestamp_row(item))
                        job=app.state.one("SELECT status FROM jobs WHERE id=?",(jid,))
                        if not job:
                            emit({"stream":"system","line":"job not found","created_at":now(),"created_at_iso":fmt_time(now())}); break
                        if str(job.get("status") or "") in {"completed","partial","failed","cancelled","stale"}: break
                        if time.monotonic()>=heartbeat_at:
                            stamp=now(); emit({"stream":"system","line":"heartbeat","created_at":stamp,"created_at_iso":fmt_time(stamp)}); heartbeat_at=time.monotonic()+20
                        time.sleep(0.25)
                except (BrokenPipeError,ConnectionResetError,ConnectionAbortedError):
                    return
            def send_static(self,path:str)->bool:
                root=app.paths.webui_dist_dir; rel=os.path.normpath(path.lstrip("/"))
                if not root.is_dir() or not rel or rel.startswith("..") or os.path.isabs(rel): return False
                full=root/rel
                if full.is_dir(): full=full/"index.html"
                if not full.is_file(): return False
                data=full.read_bytes(); ctype=mimetypes.guess_type(str(full))[0] or "application/octet-stream"; self.send_response(200); self.send_header("Content-Type",ctype); self.send_header("Cache-Control","no-store"); self.send_header("Content-Length",str(len(data))); self.end_headers(); self.wfile.write(data); return True
            def send_html(self)->None:
                built=app.paths.webui_dist_dir/"index.html"; data=built.read_bytes() if built.is_file() else b"<!doctype html><title>NetOps</title><main style='font:14px system-ui;padding:40px'><h1>NetOps API is running</h1><p>The packaged WebUI is unavailable. Reinstall NetOps or rebuild <code>webui/dist</code>.</p></main>"; self.send_response(200); self.send_header("Content-Type","text/html; charset=utf-8"); self.send_header("Cache-Control","no-store"); self.send_header("Content-Length",str(len(data))); self.end_headers(); self.wfile.write(data)
        return Handler

def main(argv: Optional[List[str]] = None) -> int:
    raw_args = list(argv if argv is not None else sys.argv[1:])
    try:
        opts, args = parse_global(raw_args)
        interactive_default = (
            not args
            and not opts.plain
            and not opts.no_tui
            and os.environ.get("NETOPS_TUI", "1").strip().lower() not in {"0", "false", "no", "off"}
            and os.environ.get("TERM", "").strip().lower() != "dumb"
            and sys.stdin.isatty()
            and sys.stdout.isatty()
        )
        if args and args[0] == "tui" and any(arg in {"-h", "--help"} for arg in args[1:]):
            helper = App.__new__(App)
            helper.cmd_help("tui", "open" if args[1:2] == ["open"] else "", opts)
            return SUCCESS
        if args and args[0] == "tui" and (not sys.stdin.isatty() or not sys.stdout.isatty() or os.environ.get("TERM", "").lower() == "dumb"):
            eprint("NetOps TUI requires an interactive terminal. Use a noun-first command or --plain for non-interactive output.")
            return 5
        if interactive_default or (args and args[0] == "tui"):
            app = App(installation_root(), profile=opts.profile)
            from netops_platform.tui.main import launch_tui
            tui_args = args[1:] if args and args[0] == "tui" else []
            if tui_args[:1] == ["open"]:
                tui_args = tui_args[1:]
            return launch_tui(app, tui_args)
        if not args or args[0] in {"-h", "--help", "help", "--version", "version"}:
            if args and args[0] in {"--version", "version"}:
                if opts.json:
                    print(json_dumps({"name": "NetOps", "version": VERSION, "schema_version": SCHEMA_VERSION}))
                else:
                    print(f"NetOps {VERSION}")
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
        eprint(f"NetOps startup failed: {exc}")
        return INTERNAL


if __name__ == "__main__":
    raise SystemExit(main())
