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
import threading
from typing import Any, Dict, List, Optional, Sequence, Tuple

from netops_platform.mac_registry import IeeeMacRegistry, lookup_ieee_mac
from netops_platform.network import (
    clean_network_output,
    extract_ip_candidates,
    lookup_oui,
    normalize_interface,
    parse_arp_output,
    parse_mac_table_output,
    parse_neighbor_detail_output,
)


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
        from netops_platform.core import PARTIAL, SUCCESS, VALIDATION, clean_display_name, fmt_time, is_all_keyword, norm_mac, now
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
            rows = [{"switch": row.get("hostname") or row.get("ip"), "ip": row.get("ip"), "command": shlex.join(self.legacy_cmd("netrune-control", "mac-lookup", str(row.get("ip")), dotted))} for row in targets]
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
            core_rc, core_stdout, core_stderr = self.capture(self.legacy_cmd("netrune-control", "core-lookup", self.canonical_mac(clean, "colon")), opts.timeout or 120)
            core_output = (core_stdout or "") + (core_stderr or "")
            with contextlib.suppress(Exception):
                self.state.record_core_lookup(dotted, core_output, core_rc)

        hits: List[Dict[str, Any]] = []
        errors: List[Dict[str, Any]] = []
        observed = now()
        for index, row in enumerate(targets, 1):
            switch_ip = str(row.get("ip") or "")
            switch_name = clean_display_name(row.get("hostname") or switch_ip)
            rc, stdout, stderr = self.capture(self.legacy_cmd("netrune-control", "mac-lookup", switch_ip, dotted), opts.timeout or 120)
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

    def known_uplink_ports(self) -> Dict[str, set]:
        """Uplink ports per switch, as determined by the last topology sweep.

        A MAC seen on an uplink is only passing through. A MAC seen anywhere
        else is attached to that port, which is the answer an operator wants.
        """
        uplinks: Dict[str, set] = {}
        for row in self.state.rows(
            "SELECT device_id,facts_json FROM capability_evidence WHERE capability='stp' AND state='supported' "
            "ORDER BY observed_at ASC"
        ):
            try:
                facts = json.loads(str(row.get("facts_json") or "{}"))
            except json.JSONDecodeError:
                continue
            ports = {normalize_interface(port) for port in facts.get("uplinks") or []}
            if ports:
                uplinks[str(row.get("device_id") or "")] = ports
        return uplinks

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

    def lookup_mac_all(self, mac: str, opts: GlobalOptions, pattern: str = "", jobs: int = 0) -> int:
        from netops_platform.core import PARTIAL, SUCCESS, VALIDATION, clean_display_name, now, strip_ansi, timestamp_rows
        """Search every switch for a MAC and say where it is attached.

        The forwarding table on each switch along the path lists the MAC, so a
        plain fan-out reports it many times. Correlating each hit against that
        switch's known uplinks separates the one access port the device is
        actually on from the uplinks it merely traverses.
        """
        mac = self.canonical_mac(mac, "dotted") or mac.strip()
        if not mac:
            return self.usage_error("lookup", "mac", opts, "Missing MAC address.", "netrune lookup mac all 0200.0000.0025", VALIDATION)
        targets = self.current_switch_targets(opts, pattern)
        if opts.dry_run:
            rows = [{"target": clean_display_name(r.get("hostname") or r.get("ip")), "ip": r.get("ip"), "command": shlex.join(self.legacy_cmd("netrune-control", "mac-lookup", str(r.get("ip")), mac))} for r in targets]
            self.emit({"ok": True, "dry_run": True, "scope": "all", "mac": mac, "targets": rows, "count": len(rows)}, opts, self.render_table(rows, ["target", "ip", "command"]))
            return SUCCESS
        if not targets:
            self.emit({"ok": False, "scope": "all", "mac": mac, "rows": [], "count": 0, "error": "no current online switch targets matched"}, opts, "No current online switch targets matched.")
            return PARTIAL

        uplinks = self.known_uplink_ports()
        workers = max(1, min(int(jobs or self._default_stp_jobs()), 32, len(targets)))
        results: List[Dict[str, Any]] = []
        hits: List[Dict[str, Any]] = []
        lock = threading.Lock()
        completed = 0

        def probe(row: Dict[str, Any]) -> Dict[str, Any]:
            ip = str(row.get("ip") or "").strip()
            name = clean_display_name(row.get("hostname") or ip)
            rc, out, err = self.capture(self.legacy_cmd("netrune-control", "mac-lookup", ip, mac), opts.timeout or 90)
            text = (out or "") + (err or "")
            return {"ip": ip, "name": name, "exit_code": rc, "text": text, "parsed": parse_mac_table_output(text, mac)}

        with self.vault_session_scope(opts, minutes=30):
            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=workers, thread_name_prefix="macfan") as pool:
                    futures = [pool.submit(probe, row) for row in targets]
                    for future in concurrent.futures.as_completed(futures):
                        answer = future.result()
                        with lock:
                            completed += 1
                            self._progress_step("lookup mac", answer["name"], completed, len(targets), opts)
                        results.append(answer)
            finally:
                self._progress_clear(opts)

        order = {str(row.get("ip") or ""): index for index, row in enumerate(targets)}
        results.sort(key=lambda item: order.get(item["ip"], 0))
        rows: List[Dict[str, Any]] = []
        for answer in results:
            with contextlib.suppress(Exception):
                self.state.record_core_lookup(answer["ip"], answer["text"], answer["exit_code"])
            # A parsed row now always carries a port, which is what separates a
            # real forwarding-table entry from an echo of the request. The exit
            # code is not a reliable signal here: the helper reports non-zero
            # on some switches that answered perfectly well.
            found_here = bool(answer["parsed"])
            for parsed in answer["parsed"]:
                port = str(parsed.get("port") or "")
                with contextlib.suppress(Exception):
                    self.state.record_mac_observation(mac, answer["ip"], answer["name"], port, str(parsed.get("vlan") or ""), str(parsed.get("entry_type") or ""))
                transit = normalize_interface(port) in uplinks.get(answer["ip"], set())
                hits.append({
                    "switch": answer["name"],
                    "switch_ip": answer["ip"],
                    "port": port,
                    "vlan": str(parsed.get("vlan") or ""),
                    "entry_type": str(parsed.get("entry_type") or ""),
                    "placement": "transit" if transit else "attached",
                })
            rows.append({
                "status": "FOUND" if found_here else ("ERROR" if answer["exit_code"] else "checked"),
                "target": answer["name"], "ip": answer["ip"], "exit_code": answer["exit_code"],
                "excerpt": " ".join(strip_ansi(answer["text"]).split())[:240],
            })

        attached = [row for row in hits if row["placement"] == "attached"]
        transit = [row for row in hits if row["placement"] == "transit"]
        history = self.mac_history_rows(mac)
        oui = lookup_oui(mac)
        payload = {
            "ok": bool(hits), "scope": "all", "mac": mac, "oui": oui,
            "vendor": oui.get("vendor") or "Unknown",
            "attached": attached, "transit": transit, "hits": hits,
            "history": timestamp_rows(history),
            "rows": rows, "count": len(rows),
            "found": sum(1 for row in rows if row["status"] == "FOUND"),
            "searched": len(targets), "parallel_jobs": workers,
            "uplink_data_available": bool(uplinks),
        }
        lines = [
            f"MAC {mac} | Vendor/OUI: {payload['vendor']} ({oui.get('prefix') or 'no prefix match'})",
            f"Searched {len(targets)} switch(es) {workers} at a time: {payload['found']} reported it.",
        ]
        if attached:
            lines.append("\nAttached here (not an uplink port)")
            lines.append(self.render_table(attached, ["switch", "switch_ip", "port", "vlan", "entry_type"]))
        elif hits:
            lines.append(
                "\nEvery hit is on a known uplink, so this MAC transits these switches but attaches"
                " below one of them. The access switch may be outside inventory or unreachable."
                if uplinks else
                "\nNo uplink data yet, so attachment cannot be separated from transit."
                " Run 'netrune topology stp' first."
            )
        if transit:
            lines.append("\nSeen in transit (uplink ports)")
            lines.append(self.render_table(transit, ["switch", "switch_ip", "port", "vlan", "entry_type"]))
        if history:
            lines.append("\nPreviously recorded")
            lines.append(self.render_table(timestamp_rows(history), ["switch", "port", "vlan", "source", "status", "last_seen"]))
        if not hits:
            lines.append("\nNot found on any switch. Ping the address first so the switches learn it.")
        self.emit(payload, opts, "\n".join(lines))
        return SUCCESS if hits else PARTIAL

    def cmd_lookup(self,args:List[str],opts:GlobalOptions)->int:
        from netops_platform.core import PARTIAL, SUCCESS, VALIDATION, eprint, norm_mac
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
            if rest and rest[0].lower() == "all":
                if len(rest) < 2: return self.usage_error("lookup","mac",opts,"Missing MAC address after all.","netrune lookup mac all 0200.0000.0025")
                return self.lookup_mac_all(rest[1], opts, jobs=mac_jobs)
            if opts.all:
                return self.lookup_mac_all(rest[-1], opts, " ".join(rest[:-1]).strip(), jobs=mac_jobs)
            cmd=self.legacy_cmd("netrune-control","mac-lookup",*rest); rc,out,err=self.capture(cmd,opts.timeout or 120); text=(out or "")+(err or "")
            with contextlib.suppress(Exception): self.state.record_core_lookup(" ".join(rest),text,rc)
            if opts.json: self.emit({"ok":rc==0,"target":" ".join(rest),"exit_code":rc,"output":out,"stderr":err},opts)
            else:
                if out: print(out,end="")
                if err: eprint(err.rstrip())
            return rc
        return self.unknown_action("lookup", verb, opts)
