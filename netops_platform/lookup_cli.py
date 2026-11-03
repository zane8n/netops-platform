"""Command surface for the lookup domain.

Kept out of core.py as a mixin for the same reason vlan_cli.py/topology_cli.py
are: helpers shared with other domains (cached_switch_neighbors and friends
with vlan, _default_stp_jobs with topology, capture_batch/vault_session_scope
more broadly) stay in core.py rather than moving here.

locate_endpoint_live sits between mac_history_rows and lookup_mac_all in the
original file but does not move with this domain: it is called from
netops_platform/path_inspector.py via self.app.locate_endpoint_live(...),
not from anything in this file, so per the shared-helper rule it stays in
core.py even though nothing here reaches it anymore.
"""

from __future__ import annotations

import concurrent.futures
import contextlib
import json
import re
import shlex
import signal
import subprocess
import threading
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

from netops_platform.devices import format_mac
from netops_platform.mac_registry import IeeeMacRegistry, lookup_ieee_mac
from netops_platform.network import (
    clean_network_output,
    extract_ip_candidates,
    lookup_oui,
    normalize_interface,
    parse_arp_output,
    parse_aruba_mac_lookup,
    parse_mac_table_output,
    parse_neighbor_detail_output,
    parse_port_mode,
)


# A forwarding-table read is a few lines per switch, so this many logins at
# once is light work for the switches and halves the old wall time.
MAC_SWEEP_JOBS = 16
# The SSH wrapper waits for two quiet windows after login and between
# commands, because AOS-Switch redraws its screen and swallows a command typed
# into the redraw. IOS and NX-OS never redraw, so a one-second window is
# enough there; measured live, it takes a Cisco read from 11 s to 7 s.
QUIET_SETTLE_FAMILIES = {"cisco-ios", "cisco-nxos"}
QUIET_SETTLE_ENV = {"NETOPS_SSH_SETTLE_TIMEOUT": "1", "NETRUNE_SSH_SETTLE_TIMEOUT": "1"}
# A login costs about 7 s on Cisco and 15 s on AOS-Switch. Starting the slow
# ones first keeps them from being the stragglers that set the finish time.
SLOW_LOGIN_FAMILIES = {"aruba-aos-switch", "aruba-aos-cx", "ruckus-fastiron"}
PORT_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9./:_-]{0,63}")
SWEEP_FAILURE_RE = re.compile(
    r"(?im)SSH transport failed|Permission denied|Host key verification failed|"
    r"Connection (?:timed out|refused|closed)|No route to host|Could not resolve|"
    r"No registered switch driver|authentication fail\w*|^\s*timeout\s*$"
)
# Where a hit counts as the device's attachment, best first. The rest are
# ports the address only passes through.
ATTACHED_PLACEMENTS = ("access", "ap-self", "ap-trunk", "unverified")
# Placements that settle where the device is plugged in; --quick stops on them.
DEFINITIVE_PLACEMENTS = {"access", "ap-self"}
SWITCH_SELF_PORTS = {"cpu", "router", "switch", "sup-eth1"}


def place_mac_hit(port: Any, mode: str, switch_facing: bool, ap_name: str, is_the_ap: bool = False) -> Tuple[str, str]:
    """Say what one forwarding-table hit means: (placement, reason).

    The live port mode decides it. A port facing another switch is an uplink
    whatever its mode, since a switch-to-switch link can be an access port. A
    trunk with an AP on the far end is where a wireless client is seen -- or,
    when the MAC searched for is that AP's own, where the AP is plugged in.
    """
    key = normalize_interface(port)
    if key in SWITCH_SELF_PORTS or re.fullmatch(r"vl(?:an)?\d+", key):
        return "self", "the switch's own address"
    if switch_facing:
        return "uplink", "link to another switch"
    if is_the_ap:
        return "ap-self", f"this MAC is AP {ap_name}"
    if mode == "trunk":
        return ("ap-trunk", f"trunk to AP {ap_name}") if ap_name else ("trunk", "trunk port")
    if mode == "access":
        return "access", "access port"
    if ap_name:
        return "ap-trunk", f"AP {ap_name} on this port"
    return "unverified", "port mode could not be read"


class KeepFreshPing:
    """Ping one address every second for as long as a search runs.

    A switch forgets a MAC a few minutes after the device last sent a frame
    (300 s by default on Cisco and Aruba), and a quiet device is then in no
    forwarding table at all. Each reply refreshes the entry on every switch
    between the device and its gateway, which is the path being searched.
    """

    def __init__(self, address: str) -> None:
        self.address = address
        self.sent = 0
        self.received = 0
        self.process: Optional[subprocess.Popen] = None
        self._reader: Optional[threading.Thread] = None
        self._answered = threading.Event()

    def start(self, settle: float = 2.0) -> bool:
        """Start pinging, and give the first reply up to `settle` seconds to land."""
        try:
            # Its own session, so Ctrl+C reaches the search and stop() decides
            # when ping ends.
            self.process = subprocess.Popen(
                ["ping", "-n", "-i", "1", "-W", "1", self.address],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, start_new_session=True,
            )
        except OSError:
            return False
        self._reader = threading.Thread(target=self._read, name="macping", daemon=True)
        self._reader.start()
        self._answered.wait(settle)
        return True

    def _read(self) -> None:
        if not self.process or not self.process.stdout:
            return
        for line in self.process.stdout:
            summary = re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received", line)
            if summary:
                self.sent, self.received = int(summary.group(1)), int(summary.group(2))
            elif "bytes from" in line:
                self.received += 1
                self._answered.set()

    def stop(self) -> Dict[str, Any]:
        if self.process and self.process.poll() is None:
            # SIGINT, not SIGTERM: ping prints its sent/received summary on it.
            with contextlib.suppress(OSError):
                self.process.send_signal(signal.SIGINT)
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=2)
        if self._reader:
            self._reader.join(timeout=2)
        return {"address": self.address, "sent": max(self.sent, self.received), "received": self.received}


class LookupCommandsMixin:

    def canonical_mac(self, value: Any, style: str = "dotted") -> str:
        from netops_platform.core import norm_mac
        clean = norm_mac(value)
        if len(clean) != 12:
            return ""
        if style == "plain":
            return clean
        if style == "colon":
            return ":".join(clean[index:index + 2] for index in range(0, 12, 2))
        return ".".join(clean[index:index + 4] for index in range(0, 12, 4))


    def mac_cached_payload(self, mac_value: str, limit: int = 100) -> Dict[str, Any]:
        from netops_platform.core import CHRONOLOGY, IP_RE, TIME_FORMAT, fmt_time, norm_mac, timestamp_rows
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
        requested = self._mac_profile_commands(str(hit.get("platform") or ""), port, str(hit.get("mac") or ""))
        # One SSH login for every command this profile needs (four to six),
        # rather than one per command -- locate_mac_live can call this once
        # per switch a MAC was seen on, so the unbatched cost multiplied by
        # both the command count and the switch count.
        outputs = dict(self.capture_batch(switch_ip, [command for _, command in requested], opts.timeout or 90))
        for evidence_type, command in requested:
            text = outputs.get(command, "")
            clean_text = clean_network_output(text)
            excerpt = "\n".join(line for line in clean_text.splitlines() if line.strip())[-1600:]
            evidence.append({"type": evidence_type, "command": command, "exit_code": 0 if text.strip() else 1, "excerpt": excerpt})
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
        from netops_platform.core import PARTIAL, SUCCESS, VALIDATION, fmt_time, is_all_keyword, norm_mac, now
        clean = norm_mac(mac_value)
        if not clean:
            return self.usage_error("lookup", "mac-locate", opts, "MAC must be a valid physical unicast address.", "netrune lookup mac locate 0200.0000.0025", VALIDATION)
        dotted = self.canonical_mac(clean, "dotted")
        if scope and not is_all_keyword(scope):
            row, choices = self.resolve_device_record(scope)
            if not row:
                labels = ", ".join(str(item.get("hostname") or item.get("ip")) for item in choices[:8])
                return self.usage_error("lookup", "mac-locate", opts, f"Switch scope could not be resolved uniquely: {scope}" + (f" ({labels})" if labels else ""), "netrune inventory list <switch>", VALIDATION)
            targets = [row]
        else:
            targets = self.current_switch_targets(opts, opts.site)
        if opts.dry_run:
            rows = self.sweep_plan_rows(clean, targets)
            self.emit({"ok": True, "dry_run": True, "mac": dotted, "scope": scope, "targets": rows, "count": len(rows)}, opts, self.render_table(rows, ["target", "ip", "commands"]))
            return SUCCESS
        if not targets:
            self.emit({"ok": False, "mac": dotted, "rows": [], "error": "no current online switch targets matched"}, opts, "No current online switch targets matched.")
            return PARTIAL

        self.live_log("mac", f"locating {dotted} across {len(targets)} switch(es)")
        core_output = ""
        core_ip = str(self.config.public.get("core_switch_ip") or "").strip()
        if core_ip:
            self.live_log("mac", f"query core ARP/MAC evidence on {core_ip}")
            core_rc, core_stdout, core_stderr = self.capture(self.legacy_cmd("netrune-control", "core-lookup", self.canonical_mac(clean, "colon")), opts.timeout or 120)
            core_output = (core_stdout or "") + (core_stderr or "")
            with contextlib.suppress(Exception):
                self.state.record_core_lookup(dotted, core_output, core_rc)

        hits: List[Dict[str, Any]] = []
        observed = now()
        devices = {str(row.get("ip") or ""): row for row in targets}
        sweep = self.sweep_mac(clean, opts, targets, label="locate mac")
        errors = [{"switch_name": row["switch"], "switch_ip": row["switch_ip"], "error": row["error"]} for row in sweep["errors"]]
        rank = {placement: index for index, placement in enumerate(ATTACHED_PLACEMENTS)}
        for hit in sorted(sweep["hits"], key=lambda row: rank.get(row["placement"], len(rank))):
            device = devices.get(hit["switch_ip"], {})
            neighbor = self._neighbor_on_port(self.cached_switch_neighbors(device), hit["port"]) if device else None
            item = {
                "mac": clean, "mac_dotted": dotted,
                "vlan": hit["vlan"], "entry_type": hit["entry_type"], "port": hit["port"],
                "switch_ip": hit["switch_ip"],
                "switch_name": hit["switch"],
                "platform": device.get("platform") or "Unknown",
                "port_mode": hit["port_mode"],
                "placement": hit["placement"],
                "role": "edge-candidate" if hit["placement"] in ATTACHED_PLACEMENTS else "switch-link",
                "neighbor_name": (neighbor or {}).get("remote_name") or "",
                "neighbor_ip": (neighbor or {}).get("remote_ip") or "",
                "observed_at": observed,
                "observed_at_iso": fmt_time(observed),
            }
            hits.append(item)
            self.live_log("mac", f"hit {item['switch_name']} {item['port']} VLAN {item['vlan'] or '?'} {item['placement']}")
        self.record_mac_attachment(clean, sweep["hits"])

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
        table = self.render_table(hits, ["placement", "switch_name", "switch_ip", "vlan", "port", "port_mode", "entry_type", "neighbor_name", "observed_at"])
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

    def current_switch_targets(self, opts: GlobalOptions, pattern: str = "") -> List[Dict[str, Any]]:
        """Every online switch matching `pattern`.

        Not capped by --limit: that caps rows printed, and applied here it
        silently left every switch after the hundredth out of the search.
        """
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
        return self.state.rows(f"SELECT ip,hostname,platform,model,status,last_seen FROM devices WHERE {where} ORDER BY hostname,ip", tuple(args))

    def core_lookup_workflow(self, target: str, opts: GlobalOptions) -> int:
        from netops_platform.core import PARTIAL, SUCCESS, UNSUPPORTED, VALIDATION, fmt_time, is_ipv4_literal, norm_mac, normalize_target_literal, now
        raw_target = str(target or "").strip()
        target_mac = norm_mac(raw_target)
        target_ip = normalize_target_literal(raw_target)
        if not target_mac and not is_ipv4_literal(target_ip):
            return self.usage_error("lookup", "core", opts, "Target must be an IP address or physical unicast MAC.", "netrune lookup core 198.51.100.92", VALIDATION)

        configured_core = str(self.config.public.get("core_switch_ip") or self.config.public.get("core_switch") or "").strip()
        if not configured_core:
            return self.usage_error("lookup", "core", opts, "No core switch is configured.", "Set core_switch_ip, then run: netrune lookup core 198.51.100.92", VALIDATION)
        core, choices = self.resolve_device_record(configured_core)
        if not core:
            normalized_core = normalize_target_literal(configured_core)
            if is_ipv4_literal(normalized_core):
                core = {"ip": normalized_core, "hostname": configured_core, "platform": "Unknown", "model": "", "status": "UNKNOWN"}
            else:
                labels = ", ".join(str(row.get("hostname") or row.get("ip")) for row in choices[:8])
                return self.usage_error("lookup", "core", opts, "Core switch could not be resolved safely." + (f" Matches: {labels}" if labels else ""), "netrune inventory list <core>", VALIDATION)

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
            version_rc, version_out, version_err = self.capture(self.legacy_cmd("netrune-control", "show", core_ip, "show version"), opts.timeout or 90)
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
        arp_rc, arp_out, arp_err = self.capture(self.legacy_cmd("netrune-control", "show", core_ip, arp_command), opts.timeout or 120)
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
                self.legacy_cmd("netrune-control", "mac-lookup", core_ip, self.canonical_mac(found_mac, "dotted")),
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
        # The port name came from parsed device output. Every other site that
        # feeds such a value back into a device command validates it first;
        # without that a malformed table row could append a second CLI command.
        if port and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9./:_-]{0,63}", port):
            port = ""
        if port and driver.command_templates.get("interface_health"):
            interface_command = driver.command_templates["interface_health"][0].format(interface=port)
            interface_rc, interface_out, interface_err = self.capture(
                self.legacy_cmd("netrune-control", "show", core_ip, interface_command),
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
            # Naming the manufacturer is most of the value of finding a MAC.
            "oui": lookup_oui(found_mac) if found_mac else {},
            "vendor": (lookup_oui(found_mac).get("vendor") if found_mac else "") or "Unknown",
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
            f"Vendor/OUI: {payload['vendor']}\n"
            f"Description: {description or 'not available'}\nRecorded: {payload['observed_at_iso']}"
        )
        self.emit(payload, opts, text)
        return SUCCESS if payload["complete"] else PARTIAL

    def switch_facing_ports(self) -> Dict[str, set]:
        """Ports per switch with another switch on the far end.

        Only neighbour evidence counts: an LLDP/CDP neighbour that is a switch
        in inventory, or a CDP neighbour advertising only the switch
        capability. The spanning-tree sweep's own uplink list is not used: it
        also counts every forwarding port without portfast, which is most
        access ports on some switches, and so hid the very devices searched for.
        """
        switches = {str(row.get("ip") or "") for row in self.state.rows("SELECT ip FROM devices WHERE COALESCE(ip,'')!=''")}
        facing: Dict[str, set] = {}

        def add(switch_ip: Any, port: Any) -> None:
            key = normalize_interface(port)
            if switch_ip and key:
                facing.setdefault(str(switch_ip), set()).add(key)

        for row in self.state.rows("SELECT local_ip,local_port,remote_ip,remote_port FROM neighbors"):
            local, remote = str(row.get("local_ip") or ""), str(row.get("remote_ip") or "")
            if remote in switches:
                add(local, row.get("local_port"))
                if local in switches:
                    add(remote, row.get("remote_port"))
        latest: Dict[str, Dict[str, Any]] = {}
        for row in self.state.rows(
            "SELECT device_id,facts_json FROM capability_evidence WHERE capability='stp' AND state='supported' "
            "ORDER BY observed_at ASC"
        ):
            with contextlib.suppress(json.JSONDecodeError):
                latest[str(row.get("device_id") or "")] = json.loads(str(row.get("facts_json") or "{}"))
        for switch_ip, facts in latest.items():
            for port, verdict in (facts.get("uplink_evidence") or {}).items():
                if "cdp-switch-only" in (verdict.get("reasons") or []):
                    add(switch_ip, port)
            for neighbor in facts.get("uplink_neighbors") or []:
                if str(neighbor.get("remote_ip") or "") in switches:
                    add(switch_ip, neighbor.get("local_port"))
        return facing

    def ap_ports(self) -> Dict[str, Dict[str, Dict[str, str]]]:
        """The AP (name, MAC) on each switch port, from the last AP attachment scan."""
        from netops_platform.core import norm_mac
        ports: Dict[str, Dict[str, Dict[str, str]]] = {}
        for row in self.state.rows("SELECT switch_ip,switch_port,name,ip,mac FROM aps WHERE COALESCE(switch_ip,'')!='' AND COALESCE(switch_port,'')!=''"):
            key = normalize_interface(row.get("switch_port"))
            if key:
                ports.setdefault(str(row.get("switch_ip")), {})[key] = {
                    "name": str(row.get("name") or row.get("ip") or "AP"), "mac": norm_mac(row.get("mac")),
                }
        return ports

    def mac_spelling(self, clean: str, family: str) -> str:
        """The MAC the way `family`'s own show commands print it."""
        return {
            "cisco-ios": self.canonical_mac(clean, "dotted"),
            "aruba-aos-switch": f"{clean[:6]}-{clean[6:]}",
            "aruba-aos-cx": self.canonical_mac(clean, "colon"),
            "ruckus-fastiron": clean,
        }.get(family, self.canonical_mac(clean, "colon"))

    def mac_ping_address(self, clean: str, opts: GlobalOptions) -> Tuple[str, str]:
        """An IP that reaches this MAC: (ip, where it came from), or ("", "").

        The core switch's ARP table is asked first because it is current; an
        ARP entry outlives the forwarding-table entry by hours, so it still
        names a device that has gone quiet. Inventory is the fallback.
        """
        configured = str(self.config.public.get("core_switch_ip") or self.config.public.get("core_switch") or "").strip()
        if configured:
            core, _ = self.resolve_device_record(configured)
            core = core or {"ip": configured, "hostname": configured, "platform": "", "model": ""}
            driver = self.driver_for(platform=core.get("platform"), model=core.get("model"), hostname=core.get("hostname"))
            template = (driver.command_templates.get("arp_lookup") or ("",))[0]
            core_ip = str(core.get("ip") or "")
            if template and core_ip:
                self.live_log("mac", f"asking {core.get('hostname') or core_ip} for this MAC's IP")
                command = template.format(lookup=self.mac_spelling(clean, driver.family))
                env = QUIET_SETTLE_ENV if driver.family in QUIET_SETTLE_FAMILIES else None
                output = dict(self.capture_batch(core_ip, [command], min(opts.timeout or 30, 30), extra_env=env)).get(command, "")
                for row in parse_arp_output(output, clean):
                    if row.get("ip"):
                        return str(row["ip"]), f"ARP on {core.get('hostname') or core_ip}"
        expression = "lower(replace(replace(replace(replace(COALESCE(mac,''),':',''),'.',''),'-',''),' ',''))"
        for table in ("devices", "aps"):
            row = self.state.one(f"SELECT ip FROM {table} WHERE {expression}=? AND COALESCE(ip,'')!='' ORDER BY last_seen DESC LIMIT 1", (clean,))
            if row and row.get("ip"):
                return str(row["ip"]), "inventory"
        return "", ""

    def mac_template_values(self, clean: str) -> Dict[str, str]:
        """The spellings a driver's mac_lookup template may ask for."""
        return {
            "mac_plain": clean,
            "mac_dotted": format_mac(clean, "dotted"),
            "mac_colon": format_mac(clean, "colon"),
            "mac_hyphen": format_mac(clean, "hyphen-six"),
        }

    def sweep_plan_rows(self, clean: str, targets: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """What sweep_mac would send each switch, for --dry-run."""
        from netops_platform.core import clean_display_name
        values = self.mac_template_values(clean)
        rows = []
        for row in targets:
            templates = self.driver_for(platform=row.get("platform"), model=row.get("model"), hostname=row.get("hostname")).command_templates
            lookup = (templates.get("mac_lookup") or ("",))[0]
            rows.append({"target": clean_display_name(row.get("hostname") or row.get("ip")), "ip": row.get("ip"),
                         "commands": lookup.format(**values) if lookup else "skipped: no switch driver for this platform"})
        return rows

    def record_mac_attachment(self, clean: str, hits: Sequence[Dict[str, Any]]) -> None:
        """Record where the MAC is plugged in, and nowhere else.

        A MAC has one current location, and each recorded port replaces the
        last. Recording every switch that merely forwards it made the core's
        uplink its "location" and logged a move on every search.
        """
        for placement in ATTACHED_PLACEMENTS:
            best = [hit for hit in hits if hit["placement"] == placement]
            if best:
                for hit in best:
                    with contextlib.suppress(Exception):
                        self.state.record_mac_observation(clean, hit["switch_ip"], hit["switch"], hit["port"], hit["vlan"], hit["entry_type"])
                return

    def sweep_mac(
        self,
        clean: str,
        opts: GlobalOptions,
        targets: Sequence[Dict[str, Any]],
        *,
        jobs: int = 0,
        quick: bool = False,
        label: str = "lookup mac",
    ) -> Dict[str, Any]:
        """Search these switches' forwarding tables for one MAC and place every hit.

        One login per switch reads the forwarding-table entry and, where the
        platform has one, the switch's trunk list. A switch that reports the
        MAC on a port the trunk list does not settle gets one more read for
        just that port. With `quick`, the search stops at the first access
        port: queued switches are dropped and those already running finish.
        """
        from netops_platform.core import clean_display_name
        values = self.mac_template_values(clean)
        facing = self.switch_facing_ports()
        ap_ports = self.ap_ports()
        timeout = opts.timeout or 90
        workers = max(1, min(int(jobs or MAC_SWEEP_JOBS), 32, len(targets) or 1))

        def probe(row: Dict[str, Any]) -> Dict[str, Any]:
            ip = str(row.get("ip") or "").strip()
            name = clean_display_name(row.get("hostname") or ip)
            answer: Dict[str, Any] = {"ip": ip, "name": name, "hits": [], "modes": {}, "text": "", "error": "", "skipped": ""}
            driver = self.driver_for(platform=row.get("platform"), model=row.get("model"), hostname=row.get("hostname"))
            templates = driver.command_templates
            if not templates.get("mac_lookup"):
                answer["skipped"] = f"no switch driver for platform {row.get('platform') or 'Unknown'}"
                return answer
            lookup = templates["mac_lookup"][0].format(**values)
            env = QUIET_SETTLE_ENV if driver.family in QUIET_SETTLE_FAMILIES else None
            answer["text"] = dict(self.capture_batch(ip, [lookup], timeout, extra_env=env)).get(lookup, "")
            parser = parse_aruba_mac_lookup if driver.family == "aruba-aos-switch" else parse_mac_table_output
            answer["hits"] = parser(answer["text"], clean)
            if not answer["hits"]:
                failure = SWEEP_FAILURE_RE.search(clean_network_output(answer["text"]))
                answer["error"] = failure.group(0).strip() if failure else ""
                return answer
            # Most hits are on links to other switches, which are placed
            # without asking. Only the rest -- the few candidate access ports --
            # cost a second login, on the one or two switches that have them.
            unsettled: Dict[str, str] = {}
            for hit in answer["hits"]:
                port = str(hit.get("port") or "")
                key = normalize_interface(port)
                if PORT_NAME_RE.fullmatch(port) and key not in SWITCH_SELF_PORTS and key not in facing.get(ip, set()):
                    unsettled[key] = port
            if unsettled and templates.get("port_mode"):
                ports = list(unsettled.values())[:8]
                commands = [templates["port_mode"][0].format(interface=port) for port in ports]
                for (_, output), port in zip(self.capture_batch(ip, commands, timeout, extra_env=env), ports):
                    answer["modes"][normalize_interface(port)] = parse_port_mode(output)["mode"]
            return answer

        # Switches that have held this MAC before go first, so a quick search
        # usually ends in the first wave.
        previously = [str(row.get("switch_ip") or "") for row in self.mac_history_rows(clean, 20)]
        rank = {ip: index for index, ip in reversed(list(enumerate(previously)))}

        def start_order(row: Dict[str, Any]) -> Tuple[int, int]:
            family = self.driver_for(platform=row.get("platform"), model=row.get("model"), hostname=row.get("hostname")).family
            return rank.get(str(row.get("ip") or ""), len(rank)), 0 if family in SLOW_LOGIN_FAMILIES else 1

        ordered = sorted(targets, key=start_order)

        answers: List[Dict[str, Any]] = []
        completed = 0
        stopped = False
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers, thread_name_prefix="macfan") as pool:
                futures = {pool.submit(probe, row): row for row in ordered}
                try:
                    for future in concurrent.futures.as_completed(futures):
                        if future.cancelled():
                            continue
                        row = futures[future]
                        try:
                            answer = future.result()
                        except Exception as exc:  # one switch's surprise must not sink the search
                            answer = {"ip": str(row.get("ip") or ""), "name": clean_display_name(row.get("hostname") or row.get("ip")),
                                      "hits": [], "modes": {}, "text": "", "error": str(exc)[:200], "skipped": ""}
                        for hit in answer["hits"]:
                            key = normalize_interface(hit.get("port"))
                            hit["port_mode"] = answer["modes"].get(key, "")
                            ap = ap_ports.get(answer["ip"], {}).get(key, {})
                            hit["placement"], hit["reason"] = place_mac_hit(
                                hit.get("port"), hit["port_mode"], key in facing.get(answer["ip"], set()),
                                ap.get("name", ""), is_the_ap=bool(ap) and ap.get("mac") == clean,
                            )
                        answers.append(answer)
                        completed += 1
                        self._progress_step(label, answer["name"], completed, len(ordered), opts)
                        if quick and not stopped and any(hit["placement"] in DEFINITIVE_PLACEMENTS for hit in answer["hits"]):
                            stopped = True
                            for pending in futures:
                                pending.cancel()
                except KeyboardInterrupt:
                    for pending in futures:
                        pending.cancel()
                    raise
        finally:
            self._progress_clear(opts)

        order = {str(row.get("ip") or ""): index for index, row in enumerate(targets)}
        answers.sort(key=lambda item: order.get(item["ip"], 0))
        hits: List[Dict[str, Any]] = []
        for answer in answers:
            for hit in answer["hits"]:
                hits.append({
                    "switch": answer["name"], "switch_ip": answer["ip"],
                    "port": str(hit.get("port") or ""), "vlan": str(hit.get("vlan") or ""),
                    "entry_type": str(hit.get("entry_type") or ""),
                    "port_mode": hit["port_mode"], "placement": hit["placement"], "reason": hit["reason"],
                })
        return {
            "hits": hits,
            "answers": answers,
            "errors": [{"switch": a["name"], "switch_ip": a["ip"], "error": a["error"]} for a in answers if a["error"]],
            "skipped": [{"switch": a["name"], "switch_ip": a["ip"], "reason": a["skipped"]} for a in answers if a["skipped"]],
            "searched": sum(1 for a in answers if not a["skipped"]),
            "targets": len(targets),
            "parallel_jobs": workers,
            "stopped_early": stopped,
            "neighbor_data_available": bool(facing),
        }

    def mac_history_rows(self, mac: str, limit: int = 10) -> List[Dict[str, Any]]:
        from netops_platform.core import clean_display_name, norm_mac
        """Where this MAC has been recorded before, newest first."""
        clean = norm_mac(mac)
        if not clean:
            return []
        expression = "lower(replace(replace(replace(replace(COALESCE(subject_id,''),':',''),'.',''),'-',''),' ',''))"
        rows = self.state.rows(
            f"SELECT switch_name,switch_ip,switch_port,source,confidence,status,last_seen,updated_at,attrs_json "
            f"FROM relationships_current WHERE rel_type='mac_location' AND {expression}=? "
            "ORDER BY COALESCE(last_seen,updated_at,0) DESC LIMIT ?",
            (clean, limit),
        )
        history: List[Dict[str, Any]] = []
        for row in rows:
            attributes: Dict[str, Any] = {}
            with contextlib.suppress(json.JSONDecodeError):
                attributes = json.loads(str(row.get("attrs_json") or "{}"))
            history.append({
                "switch": clean_display_name(row.get("switch_name") or row.get("switch_ip") or ""),
                "switch_ip": row.get("switch_ip") or "",
                "port": row.get("switch_port") or "",
                "vlan": str(attributes.get("vlan") or ""),
                "source": row.get("source") or "",
                "status": row.get("status") or "",
                "last_seen": int(row.get("last_seen") or row.get("updated_at") or 0),
            })
        return history

    def lookup_mac_all(self, mac: str, opts: GlobalOptions, pattern: str = "", jobs: int = 0,
                       ping: str = "auto", quick: bool = False) -> int:
        """Find the access port a MAC is plugged into, searching every switch.

        Every switch between the device and the core lists the MAC, so a plain
        fan-out reports it many times. Reading each reporting port's mode live
        separates the one access port the device is on from the trunks and
        switch links it only passes through. A ping to the device runs for the
        whole search, so a quiet device is not missed because its entry aged
        out of the tables. `ping` is "auto" (find the IP), "" (off), or an IP.
        """
        from netops_platform.core import PARTIAL, SUCCESS, VALIDATION, is_ipv4_literal, norm_mac, timestamp_rows
        clean = norm_mac(mac)
        if not clean:
            return self.usage_error("lookup", "mac", opts, "MAC must be a valid physical unicast address.", "netrune lookup mac all 0200.0000.0025", VALIDATION)
        if ping not in {"", "auto"} and not is_ipv4_literal(ping):
            return self.usage_error("lookup", "mac", opts, f"--ping needs an IPv4 address, not {ping!r}.", "netrune lookup mac all 0200.0000.0025 --ping 192.0.2.25", VALIDATION)
        mac = self.canonical_mac(clean, "dotted")
        targets = self.current_switch_targets(opts, pattern)
        if opts.dry_run:
            rows = self.sweep_plan_rows(clean, targets)
            keep_fresh = "off" if not ping else (ping if ping != "auto" else "the IP the core switch's ARP table gives, else inventory")
            self.emit({"ok": True, "dry_run": True, "scope": "all", "mac": mac, "ping": keep_fresh, "quick": quick, "targets": rows, "count": len(rows)},
                      opts, f"Dry run: search {len(rows)} switch(es) for {mac}; keep fresh by pinging: {keep_fresh}\n" + self.render_table(rows, ["target", "ip", "commands"]))
            return SUCCESS
        if not targets:
            self.emit({"ok": False, "scope": "all", "mac": mac, "rows": [], "count": 0, "error": "no current online switch targets matched"}, opts, "No current online switch targets matched.")
            return PARTIAL

        started = time.monotonic()
        pinger: Optional[KeepFreshPing] = None
        ping_address, ping_source = (ping, "given") if ping not in {"", "auto"} else ("", "")
        ping_result: Dict[str, Any] = {}
        with self.vault_session_scope(opts, minutes=30):
            try:
                if ping == "auto":
                    ping_address, ping_source = self.mac_ping_address(clean, opts)
                if ping_address:
                    pinger = KeepFreshPing(ping_address)
                    if pinger.start():
                        self.live_log("mac", f"pinging {ping_address} ({ping_source}) to keep the address fresh")
                    else:
                        pinger = None
                sweep = self.sweep_mac(clean, opts, targets, jobs=jobs, quick=quick)
            finally:
                if pinger:
                    ping_result = {**pinger.stop(), "source": ping_source}
        elapsed = round(time.monotonic() - started, 1)

        hits = sweep["hits"]
        for answer in sweep["answers"]:
            if not answer["hits"]:
                continue
            # Only switches that had it: a row per searched switch would bury
            # the core lookups this cache also holds.
            with contextlib.suppress(Exception):
                self.state.record_core_lookup(answer["ip"], answer["text"], 0)
        self.record_mac_attachment(clean, hits)
        by_placement = {placement: [hit for hit in hits if hit["placement"] == placement] for placement in (*ATTACHED_PLACEMENTS, "trunk", "uplink", "self")}
        attached = [hit for placement in ATTACHED_PLACEMENTS for hit in by_placement[placement]]
        passing = by_placement["trunk"] + by_placement["uplink"]
        reported = {hit["switch_ip"] for hit in hits}
        history = self.mac_history_rows(clean)
        oui = lookup_oui(clean)
        rows = [{
            "status": "FOUND" if answer["hits"] else ("SKIPPED" if answer["skipped"] else ("ERROR" if answer["error"] else "checked")),
            "target": answer["name"], "ip": answer["ip"], "error": answer["error"] or answer["skipped"],
        } for answer in sweep["answers"]]
        payload = {
            "ok": bool(attached), "scope": "all", "mac": mac, "oui": oui,
            "vendor": oui.get("vendor") or "Unknown",
            "ip": ping_address, "ip_source": ping_source, "ping": ping_result,
            "access": by_placement["access"], "ap_self": by_placement["ap-self"],
            "ap_trunk": by_placement["ap-trunk"], "unverified": by_placement["unverified"],
            "attached": attached, "transit": passing, "hits": hits,
            "history": timestamp_rows(history),
            "rows": rows, "count": len(rows), "found": len(reported),
            "searched": sweep["searched"], "switches": sweep["targets"], "parallel_jobs": sweep["parallel_jobs"],
            "elapsed_seconds": elapsed, "stopped_early": sweep["stopped_early"],
            "errors": sweep["errors"], "skipped": sweep["skipped"],
            "uplink_data_available": sweep["neighbor_data_available"],
        }

        columns = ["switch", "switch_ip", "port", "vlan", "entry_type"]
        lines = [f"MAC {mac} | Vendor/OUI: {payload['vendor']} ({oui.get('prefix') or 'no prefix match'})"]
        if ping_result:
            lines.append(f"Kept fresh by pinging {ping_address} ({ping_source}): {ping_result['received']} of {ping_result['sent']} answered.")
        elif ping == "auto":
            lines.append("No IP is known for this MAC, so nothing kept it fresh. Add --ping <ip> if you know it.")
        lines.append(
            f"Searched {sweep['searched']} switch(es), {sweep['parallel_jobs']} at a time, in {elapsed:g}s; "
            f"{len(reported)} had it in their table."
            + (f" Stopped at the first answer (--quick); {sweep['targets'] - len(sweep['answers'])} switch(es) not asked." if sweep["stopped_early"] else "")
        )
        if by_placement["access"]:
            lines.append("\nOn an access port")
            lines.append(self.render_table(by_placement["access"], columns))
        if by_placement["ap-self"]:
            lines.append(f"\nThis MAC is the AP itself ({by_placement['ap-self'][0]['reason'].split('AP ', 1)[-1]}), plugged in here")
            lines.append(self.render_table(by_placement["ap-self"], columns))
        if by_placement["ap-trunk"]:
            lines.append("\nBehind an AP (a wireless client, or something wired through the AP)")
            lines.append(self.render_table(by_placement["ap-trunk"], columns + ["reason"]))
        if by_placement["unverified"]:
            lines.append("\nNot a known switch link, but the port mode could not be read")
            lines.append(self.render_table(by_placement["unverified"], columns))
        if passing and attached:
            lines.append(f"\nIgnored {len(passing)} trunk/uplink port(s) it only passes through (--json lists them).")
        elif passing:
            lines.append(
                "\nNot on any access port. It only passes through these trunks, so it is plugged in below one of"
                " them: on a switch that is not in inventory, did not answer, or is unmanaged."
            )
            lines.append(self.render_table(passing, columns + ["reason"]))
        if by_placement["self"]:
            lines.append("\nThis is the switch's own address on: " + ", ".join(f"{hit['switch']} {hit['port']}" for hit in by_placement["self"]))
        if not hits:
            if ping_result and not ping_result["received"]:
                lines.append(f"\nNot found on any switch, and {ping_address} did not answer: the device is likely off or disconnected.")
            else:
                lines.append("\nNot found on any switch.")
        if sweep["errors"]:
            names = ", ".join(f"{row['switch']} ({row['error']})" for row in sweep["errors"][:6])
            more = f" and {len(sweep['errors']) - 6} more" if len(sweep["errors"]) > 6 else ""
            lines.append(f"\nCould not search {len(sweep['errors'])} switch(es): {names}{more}.")
        if sweep["skipped"]:
            lines.append(f"Not searched, platform unknown: {', '.join(row['switch'] for row in sweep['skipped'])}.")
        if history and not any(by_placement[placement] for placement in DEFINITIVE_PLACEMENTS):
            lines.append("\nPreviously recorded")
            lines.append(self.render_table(timestamp_rows(history[:5]), ["switch", "port", "vlan", "source", "status", "last_seen"]))
        self.emit(payload, opts, "\n".join(lines))
        return SUCCESS if attached else PARTIAL

    def cmd_lookup(self,args:List[str],opts:GlobalOptions)->int:
        from netops_platform.core import PARTIAL, SUCCESS, VALIDATION, eprint, is_ipv4_literal, norm_mac
        if self.handle_help("lookup", args, opts): return SUCCESS
        verb=args[0] if args else "core"; rest=args[1:]
        if verb=="core":
            if not rest: return self.usage_error("lookup","core",opts,"Missing IP or MAC.","netrune lookup core 198.51.100.92")
            if len(rest) > 1: return self.usage_error("lookup","core",opts,"Core lookup accepts exactly one IP or MAC.","netrune lookup core 198.51.100.92",VALIDATION)
            with self.vault_session_scope(opts, minutes=30):
                return self.core_lookup_workflow(rest[0], opts)
        if verb=="mac":
            if not rest: return self.usage_error("lookup","mac",opts,"Missing MAC address.","netrune lookup mac 0200.0000.0025")
            subaction=rest[0].lower()
            if subaction == "registry":
                action = rest[1].lower() if len(rest) > 1 else "status"
                registry = IeeeMacRegistry(self.paths.mac_registry_dir)
                if action == "refresh":
                    if opts.dry_run:
                        command = [self.paths.tool("netrune"), "lookup", "mac", "registry", "refresh"]
                        self.emit({"ok": True, "dry_run": True, "command": shlex.join(command)}, opts, f"Dry run: {shlex.join(command)}")
                        return SUCCESS
                    payload = registry.refresh(force=True, timeout=opts.timeout or 15)
                    text = f"IEEE MAC registry refresh: {payload['available_registries']}/{payload['required_registries']} registries available\n" + self.render_table(payload["rows"], ["registry", "status", "rows", "fetched_at_iso", "error"])
                    self.emit(payload, opts, text)
                    return SUCCESS if payload.get("complete") else PARTIAL
                if action != "status":
                    return self.usage_error("lookup", "mac-registry", opts, f"Unknown registry action: {action}", "netrune lookup mac registry refresh", VALIDATION)
                manifest = registry._manifest()
                rows = list((manifest.get("registries") or {}).values())
                payload = {"ok": bool(rows), "provider": manifest.get("provider") or "IEEE Registration Authority", "provider_url": manifest.get("provider_url"), "updated_at": manifest.get("updated_at"), "updated_at_iso": manifest.get("updated_at_iso") or "never", "rows": rows, "cache_dir": str(self.paths.mac_registry_dir)}
                self.emit(payload, opts, f"IEEE MAC registry cache: {payload['updated_at_iso']}\n" + (self.render_table(rows, ["registry", "prefix_bits", "rows", "fetched_at_iso", "sha256"]) if rows else "No registry cache exists. Run: netrune lookup mac registry refresh"))
                return SUCCESS if rows else PARTIAL
            if subaction in {"inspect","vendor","online","history","locate","profile"}:
                if len(rest)<2: return self.usage_error("lookup",f"mac-{subaction}",opts,"Missing MAC address.",f"netrune lookup mac {subaction} 0200.0000.0025")
                mac=rest[1]
                if subaction=="inspect":
                    try: payload=self.mac_cached_payload(mac,opts.limit)
                    except ValueError as exc: return self.usage_error("lookup","mac-inspect",opts,str(exc),"netrune lookup mac inspect 0200.0000.0025",VALIDATION)
                    self.emit(payload,opts,self.render_mac_cached(payload)); return SUCCESS if payload.get("ok") else PARTIAL
                if subaction in {"vendor", "online"}:
                    clean=norm_mac(mac)
                    if not clean: return self.usage_error("lookup","mac-vendor",opts,"MAC must be a valid physical unicast address.","netrune lookup mac vendor 00:00:5e:00:53:01",VALIDATION)
                    flags = set(rest[2:])
                    invalid_flags = flags - {"--online", "--refresh", "--offline"}
                    if invalid_flags:
                        return self.usage_error("lookup", "mac-vendor", opts, f"Unknown MAC vendor option: {sorted(invalid_flags)[0]}", "netrune lookup mac online <mac> [--refresh|--offline]", VALIDATION)
                    use_online = subaction == "online" or "--online" in flags or "--refresh" in flags
                    if use_online:
                        if opts.dry_run:
                            command = [self.paths.tool("netrune"), "lookup", "mac", subaction, self.canonical_mac(clean, "colon")]
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
                            return self.usage_error("lookup", "mac-online", opts, str(exc), "netrune lookup mac online 00:00:5e:00:53:01", VALIDATION)
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
                    payload={"ok":True,"mac":self.canonical_mac(clean,"dotted"),"oui":lookup_oui(clean),"note":"Local OUI data identifies the registered organization, not an exact model. Use 'netrune lookup mac online <mac>' for the cached IEEE MA-L/MA-M/MA-S registries."}
                    self.emit(payload,opts,f"{payload['mac']}: {payload['oui'].get('vendor') or 'Unknown'} ({payload['oui'].get('prefix') or 'no prefix match'})\n{payload['note']}"); return SUCCESS
                if subaction=="history":
                    try: payload=self.mac_cached_payload(mac,opts.limit)
                    except ValueError as exc: return self.usage_error("lookup","mac-history",opts,str(exc),"netrune lookup mac history 0200.0000.0025",VALIDATION)
                    combined=(payload.get("relationship_history") or [])+(payload.get("inventory_history") or [])
                    combined.sort(key=lambda row:(int(row.get("created_at") or 0),int(row.get("id") or 0)),reverse=True)
                    payload={**payload,"rows":combined[:opts.limit],"count":len(combined)}
                    self.emit(payload,opts,self.render_table(payload["rows"],["version_label","created_at","event_type","rel_type","subject_id","object_id","switch_ip","switch_port","source"])); return SUCCESS if combined else PARTIAL
                scope=rest[2] if len(rest)>2 and not rest[2].startswith("--") else "all"
                with self.vault_session_scope(opts, minutes=30):
                    return self.locate_mac_live(mac,opts,scope,profile=subaction=="profile")
            if len(rest)==1 and norm_mac(rest[0]):
                payload=self.mac_cached_payload(rest[0],opts.limit)
                self.emit(payload,opts,self.render_mac_cached(payload)); return SUCCESS if payload.get("ok") else PARTIAL
            mac_jobs = 0
            if "--jobs" in rest:
                position = rest.index("--jobs")
                if position + 1 >= len(rest) or not str(rest[position + 1]).isdigit() or not 1 <= int(rest[position + 1]) <= 32:
                    return self.usage_error("lookup","mac",opts,"--jobs requires a number between 1 and 32.","netrune lookup mac all <mac> [--jobs N]",VALIDATION)
                mac_jobs = int(rest[position + 1])
                rest = rest[:position] + rest[position + 2:]
            # --ping alone (or nothing) finds the IP itself; --ping <ip> names it.
            mac_ping = "" if "--no-ping" in rest else "auto"
            if "--ping" in rest:
                position = rest.index("--ping")
                given = rest[position + 1] if position + 1 < len(rest) and is_ipv4_literal(rest[position + 1]) else ""
                mac_ping = given or "auto"
                rest = rest[:position] + rest[position + (2 if given else 1):]
            mac_quick = "--quick" in rest
            rest = [token for token in rest if token not in {"--no-ping", "--quick"}]
            if rest and rest[0].lower() == "all":
                if len(rest) < 2: return self.usage_error("lookup","mac",opts,"Missing MAC address after all.","netrune lookup mac all 0200.0000.0025")
                return self.lookup_mac_all(rest[1], opts, jobs=mac_jobs, ping=mac_ping, quick=mac_quick)
            if opts.all:
                return self.lookup_mac_all(rest[-1], opts, " ".join(rest[:-1]).strip(), jobs=mac_jobs, ping=mac_ping, quick=mac_quick)
            cmd=self.legacy_cmd("netrune-control","mac-lookup",*rest); rc,out,err=self.capture(cmd,opts.timeout or 120); text=(out or "")+(err or "")
            with contextlib.suppress(Exception): self.state.record_core_lookup(" ".join(rest),text,rc)
            if opts.json: self.emit({"ok":rc==0,"target":" ".join(rest),"exit_code":rc,"output":out,"stderr":err},opts)
            else:
                if out: print(out,end="")
                if err: eprint(err.rstrip())
            return rc
        return self.unknown_action("lookup", verb, opts)
