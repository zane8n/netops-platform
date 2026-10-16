"""Command surface for the topology domain.

Kept out of core.py as a mixin for the same reason vlan_cli.py is: this
domain shares helpers with other not-yet-extracted domains (_default_stp_jobs
with lookup, capture_batch/vault_session_scope more broadly) that stay in
core.py rather than moving here, and MRO resolves self.foo(...) calls the
same regardless of which file defines a given method.
"""

from __future__ import annotations

import concurrent.futures
import contextlib
import json
import re
import threading
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

from netops_platform.network import (
    classify_uplink_ports,
    clean_network_output,
    normalize_interface,
    parse_cdp_neighbors_table,
    parse_neighbor_detail_output,
    parse_spanning_tree_output,
    parse_trunk_summary,
)


class TopologyCommandsMixin:

    def cmd_topology(self,args:List[str],opts:GlobalOptions)->int:
        from netops_platform.core import PARTIAL, SUCCESS, VALIDATION, eprint, is_all_keyword
        if self.handle_help("topology", args, opts): return SUCCESS
        verb=args[0] if args else "show"; rest=args[1:]
        if verb=="scan":
            rc=self.run_subprocess(self.legacy_cmd("netrune-discovery","--discover-neighbors"),opts)
            if rc==0 and not opts.dry_run:
                try: self.import_flat_state(("topology",), "lldp-cdp-scan")
                except Exception as exc: eprint(f"Observation recording failed: {exc}"); return PARTIAL
            return rc
        if verb=="stp":
            jobs=0
            failed_only=False
            positional=[]
            index=0
            while index < len(rest):
                if rest[index] in {"--failed","--retry-failed"}:
                    failed_only=True; index+=1; continue
                if rest[index]=="--jobs":
                    if index+1>=len(rest) or not str(rest[index+1]).isdigit() or not 1<=int(rest[index+1])<=32:
                        return self.usage_error("topology","stp",opts,"--jobs requires a number between 1 and 32.","netrune topology stp [target] [--jobs N] [--failed]",VALIDATION)
                    jobs=int(rest[index+1]); index+=2; continue
                positional.append(rest[index]); index+=1
            rest=positional
            target=rest[0] if rest and not is_all_keyword(rest[0]) else ""
            devices=None
            if failed_only:
                if target:
                    return self.usage_error("topology","stp",opts,"--failed re-reads every switch that still owes a result, so it takes no target.","netrune topology stp --failed",VALIDATION)
                devices=self.devices_needing_stp()
                if not devices:
                    self.emit({"ok":True,"switches_total":0,"links":[],"note":"every online switch has a parsed spanning-tree read"},opts,"Nothing to retry: every online switch has a parsed spanning-tree read.")
                    return SUCCESS
            if target:
                row,choices=self.resolve_device_record(target)
                if not row:
                    detail=("matched no switch" if not choices else f"matched {len(choices)} switches")
                    return self.usage_error("topology","stp",opts,f"'{target}' {detail}.","netrune topology stp",VALIDATION)
                devices=[row]
            if opts.dry_run:
                count=len(devices) if devices is not None else self.state.one("SELECT COUNT(*) AS count FROM devices")["count"]
                self.emit({"ok":True,"dry_run":True,"switches":count},opts,f"Would read spanning tree from {count} switch(es).")
                return SUCCESS
            payload=self.collect_spanning_tree_topology(opts,devices,jobs)
            lines=[
                f"Inspected {payload['switches_inspected']} of {payload['switches_total']} switch(es); {payload['switches_failed']} could not be read.",
                f"Derived {len(payload['links'])} link(s): {payload['corroborated_links']} also seen by LLDP/CDP, {payload['new_links']} not.",
                f"Read {payload['parallel_jobs']} switch(es) at a time.",
            ]
            if payload["vault_session_held"]:
                lines.append("Vault held open for this run and closed again; one authentication covered every switch.")
            elif payload["switches_inspected"] or payload["switches_failed"]:
                # Silence here reads as "it should not have prompted", so say
                # plainly that it did and what to do about it.
                lines.append(
                    "Vault was NOT held open, so each switch authenticated separately. "
                    "Run 'netrune vault unlock --ttl 60' first, then re-run this command."
                )
            for row in payload.get("reclassified") or []:
                lines.append(
                    f"Reclassified {row['device']}: {row['from']} -> {row['to']} "
                    f"(from {row.get('source') or 'live probe'}); inventory platform set to {row['platform']}. "
                    "Re-run 'netrune topology stp --failed' to read it with the right driver."
                )
            if payload["unresolved_bridges"]:
                lines.append(f"{len(payload['unresolved_bridges'])} designated bridge(s) did not match a known device.")
            for failure in payload["failures"][:5]:
                lines.append(
                    f"  {failure['device']}: {failure['error']} "
                    f"({failure.get('raw_bytes', 0)} bytes returned)"
                )
                if failure.get("raw_excerpt"):
                    lines.append(f"    returned: {failure['raw_excerpt'][:600]}")
            lines.append(self.render_table(
                [{"switch":row["local_name"] or row["local_id"],"port":row["local_port"],"neighbor":row["remote_name"] or row["remote_id"],
                  "role":row["role"],"state":row["state"],"confidence":row["confidence"]} for row in payload["links"]],
                ["switch","port","neighbor","role","state","confidence"],
            ))
            self.emit(payload,opts,"\n".join(line for line in lines if line))
            return SUCCESS if payload["ok"] else PARTIAL
        if verb=="links":
            rows=self.state.rows(
                "SELECT switch_name,switch_ip,switch_port,object_id,confidence,source,status,last_seen,attrs_json "
                "FROM relationships_current WHERE rel_type='stp_link' ORDER BY switch_name,switch_port LIMIT ?",(opts.limit,))
            self.emit({"ok":True,"rows":rows},opts,self.render_table(rows,["switch_name","switch_port","object_id","confidence","source","status"]))
            return SUCCESS
        if verb=="show":
            if rest and not is_all_keyword(rest[0]) and not opts.json: return self.run_subprocess(self.legacy_cmd("netrune-discovery","--topology",rest[0]),opts)
            rows=self.state.rows("SELECT * FROM neighbors ORDER BY local_name,local_port LIMIT ?",(opts.limit,)); self.emit({"ok":True,"rows":rows},opts,self.render_table(rows,["local_ip","local_name","local_port","remote_name","remote_port","remote_ip"])); return SUCCESS
        if verb=="changes": rows=self.state.rows("SELECT * FROM topology_events ORDER BY created_at DESC,id DESC LIMIT ?",(opts.limit,)); self.emit({"ok":True,"rows":rows},opts,self.render_table(rows,["created_at","event_type","local_ip","local_port","remote_name","remote_port","detail"])); return SUCCESS
        if verb=="timeline": return self.relationship_timeline(rest[0] if rest else "neighbor_link",opts,rel_type="neighbor_link")
        return self.unknown_action("topology", verb, opts)

    def inspect_spanning_tree(
        self,
        device: Dict[str, Any],
        opts: GlobalOptions,
        *,
        vlan: int = 0,
        interfaces: Optional[Sequence[str]] = None,
        record: bool = True,
        neighbors: bool = False,
        redetect: bool = True,
    ) -> Dict[str, Any]:
        from netops_platform.core import clean_display_name, now
        """Read spanning-tree state from one switch and store it as evidence.

        The parsed port table is kept whole so callers can ask about any port,
        while `interface`/`state`/`role` describe the first path interface that
        was actually found in the table.
        """
        target = str(device.get("ip") or "")
        driver = self.driver_for(
            platform=device.get("platform"),
            model=device.get("model"),
            hostname=device.get("hostname"),
        )
        # A sweep asks about the whole switch, so prefer the all-instances form;
        # a path check asks about one VLAN and uses the per-VLAN command.
        templates = list(
            driver.command_templates.get("stp_summary" if not vlan else "stp")
            or driver.command_templates.get("stp")
            or ()
        )
        observed_at = now()
        base = {
            "observed_at": observed_at,
            "driver_family": driver.family,
            "parsed": False,
            "state": "unknown",
            "interface": "",
        }
        if not target or not templates or not driver.supports("stp"):
            return {**base, "error": f"No registered spanning-tree command is available for {driver.family}."}

        timeout = min(int(getattr(opts, "timeout", 0) or 120), 180)
        commands: List[str] = []
        parsed: Dict[str, Any] = {}
        raw = ""

        # One login for the whole switch-wide read. Previously spanning tree,
        # CDP and trunks each opened their own session, so a single switch cost
        # three authentications before the per-uplink reads even started.
        batch = [templates[0].format(vlan=vlan or 1)]
        cdp_command = ""
        trunk_command = ""
        if driver.command_templates.get("cdp_neighbors") and driver.supports("cdp"):
            cdp_command = driver.command_templates["cdp_neighbors"][0]
            batch.append(cdp_command)
        if driver.command_templates.get("trunk_summary"):
            trunk_command = driver.command_templates["trunk_summary"][0]
            batch.append(trunk_command)

        batched = dict(self.capture_batch(target, batch, timeout))
        commands.extend(batch)
        raw = batched.get(batch[0], "")
        parsed = parse_spanning_tree_output(raw)
        if not parsed.get("parsed"):
            # Fall back to the remaining templates one at a time; a family may
            # offer a second spelling that the first attempt did not cover.
            for template in templates[1:]:
                command = template.format(vlan=vlan or 1)
                commands.append(command)
                rc, stdout, stderr = self.capture(self.legacy_cmd("netrune-control", "show", target, command), timeout)
                raw = (stdout or "") + (stderr or "")
                candidate = parse_spanning_tree_output(raw)
                if candidate.get("parsed"):
                    parsed = candidate
                    break
        if not parsed.get("parsed") and parsed.get("unsupported") and redetect:
            # The device rejected this family's command, which usually means
            # inventory has the wrong platform for the address. Ask the device
            # what it is and retry once with the driver it actually needs.
            _, version_out, version_err = self.capture(
                self.legacy_cmd("netrune-control", "show", target, "show version"), timeout
            )
            evidence_text = (version_out or "") + (version_err or "")
            detection = self.detect_device_family(
                platform=device.get("platform"), model=device.get("model"),
                sysdescr=evidence_text, hostname=device.get("hostname"),
            )
            if detection.family not in {"", "unknown", driver.family}:
                corrected = dict(device)
                corrected["platform"] = {
                    "cisco-ios": "Cisco IOS", "cisco-nxos": "Cisco NX-OS",
                    "aruba-aos-switch": "Aruba AOS-S", "aruba-aos-cx": "Aruba AOS-CX",
                    "ruckus-fastiron": "Ruckus FastIron",
                }.get(detection.family, detection.family)
                corrected["model"] = ""
                self.live_log("stp", f"{target}: reclassified {driver.family} -> {detection.family}")
                retried = self.inspect_spanning_tree(
                    corrected, opts, vlan=vlan, interfaces=interfaces,
                    record=record, neighbors=neighbors, redetect=False,
                )
                if retried.get("parsed"):
                    retried["reclassified_from"] = driver.family
                    retried["reclassified_to"] = detection.family
                    retried["platform_corrected"] = corrected["platform"]
                    return retried

        if not parsed.get("parsed"):
            unsupported = bool(parsed.get("unsupported"))
            # Carry the excerpt on the returned value, not only into the
            # database, so a caller that defers recording still has the bytes.
            # Without it a parse failure cannot be told from a dead link.
            evidence = {
                **base,
                **parsed,
                "commands": commands,
                "raw_excerpt": " ".join(clean_network_output(raw).split())[:1200],
                "raw_bytes": len(raw or ""),
                "unsupported": unsupported,
                "error": (
                    f"{driver.family} rejected {commands[-1]!r}." if unsupported
                    else "Spanning-tree output could not be parsed."
                ),
            }
            if record:
                self.state.record_capability_evidence(
                    target or str(device.get("hostname") or ""), "stp",
                    "unsupported" if unsupported else "unknown",
                    {"commands": commands, "raw_excerpt": evidence["raw_excerpt"], "raw_bytes": evidence["raw_bytes"]},
                    raw=raw, driver_family=driver.family,
                    confidence=100 if unsupported else 40, observed_at=observed_at,
                )
            return evidence

        ports = list(parsed.get("ports") or [])

        # Spanning tree marks a port as edge whenever the neighbour does not
        # take part in this region's tree, which hides uplinks to switches in
        # another STP domain. The CDP capability column names the neighbour
        # kind outright, so it is read alongside and both are combined.
        cdp_rows: List[Dict[str, Any]] = []
        if cdp_command:
            cdp_rows = parse_cdp_neighbors_table(batched.get(cdp_command, ""))
        # Cisco marks every trunk port forwarding in some VLAN, so spanning tree
        # alone cannot separate an uplink from a trunk down to a phone. The
        # allowed-VLAN list does: an uplink carries the management VLAN.
        trunks: Dict[str, Dict[str, Any]] = {}
        if trunk_command:
            trunks = parse_trunk_summary(batched.get(trunk_command, ""))
        uplink_verdicts = classify_uplink_ports(ports, cdp_rows, trunks, self.management_vlan())
        for port in ports:
            verdict = uplink_verdicts.get(str(port.get("port") or ""), {})
            port["uplink"] = bool(verdict.get("uplink"))
            port["uplink_reasons"] = list(verdict.get("reasons") or [])
            port["uplink_confidence"] = int(verdict.get("confidence") or 0)

        # An uplink port is worth one more round trip: LLDP detail names the
        # device on the far end and its management address outright, which is
        # stronger evidence than correlating a bridge MAC.
        uplink_neighbors: List[Dict[str, Any]] = []
        detail_template = (driver.command_templates.get("neighbor_detail") or ("",))[0]
        if detail_template and neighbors:
            uplink_names = [
                name for name in sorted({n for n, row in uplink_verdicts.items() if row.get("uplink")})
                if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9./:_-]{0,31}", name)
            ][:12]
            detail_commands = [detail_template.format(interface=name) for name in uplink_names]
            detail_output = dict(self.capture_batch(target, detail_commands, timeout)) if detail_commands else {}
            for port_name, detail_command in zip(uplink_names, detail_commands):
                port = next((row for row in ports if str(row.get("port") or "") == port_name), {})
                for record in parse_neighbor_detail_output(detail_output.get(detail_command, "")):
                    name = clean_display_name(record.get("remote_name") or "")
                    remote_ip = str(record.get("remote_ip") or "")
                    if not name and not remote_ip:
                        continue
                    uplink_neighbors.append({
                        "local_port": port_name,
                        "remote_name": name,
                        "remote_ip": remote_ip,
                        "remote_port": str(record.get("remote_port") or ""),
                        "platform": str(record.get("platform") or "")[:120],
                        "protocol": record.get("protocol") or "lldp",
                    })
                if port:
                    port["neighbors"] = [
                        row for row in uplink_neighbors if row["local_port"] == port_name
                    ]

        wanted = [normalize_interface(value) for value in (interfaces or []) if normalize_interface(value)]
        selected: Dict[str, Any] = {}
        for port in ports:
            if normalize_interface(port.get("port")) in wanted:
                selected = port
                break
        facts = {
            "mode": parsed.get("mode") or "",
            "enabled": parsed.get("enabled"),
            "is_root": bool(parsed.get("is_root")),
            "root_port": parsed.get("root_port") or "",
            "switch_mac": parsed.get("switch_mac") or "",
            "root_mac": parsed.get("root_mac") or "",
            "regional_root_mac": parsed.get("regional_root_mac") or "",
            "topology_changes": parsed.get("topology_changes"),
            "interface": str(selected.get("port") or ""),
            "state": str(selected.get("state") or "unknown"),
            "role": str(selected.get("role") or ""),
            "ports": ports,
            "uplinks": sorted({str(port.get("port")) for port in ports if port.get("uplink")}
                              | {name for name, row in uplink_verdicts.items() if row.get("uplink")}),
            "stp_only_uplinks": sorted({str(port.get("port")) for port in ports if port.get("network_facing")}),
            "cdp_neighbors": cdp_rows,
            "trunks": trunks,
            "management_vlan": self.management_vlan(),
            "uplink_evidence": uplink_verdicts,
            "uplink_neighbors": uplink_neighbors,
            "edge_ports": [str(port.get("port")) for port in ports if port.get("role") == "edge"],
            "commands": commands,
        }
        if record:
            self.state.record_capability_evidence(
                target or str(device.get("hostname") or ""), "stp", "supported", facts,
                raw=raw, driver_family=driver.family,
                confidence=95 if ports else 70, observed_at=observed_at,
            )
            # The bridge address a switch states for itself is a strong identity
            # signal, and reconciliation ranks a MAC above a name match.
            facts["bridge_mac_recorded"] = self.state.record_device_bridge_mac(
                target or str(device.get("hostname") or ""), facts["switch_mac"]
            )
        return {**base, **parsed, **facts, "parsed": True}

    def _bridge_mac_index(self, devices: Sequence[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        from netops_platform.core import norm_mac
        """Map every known bridge MAC to the device that owns it.

        Inventory MACs come first, then any spanning-tree read that already
        stated a switch's own bridge address. Both are needed: a switch can be
        in inventory without a MAC, and a bridge can appear as a neighbour's
        designated bridge before it is itself inspected.
        """
        index: Dict[str, Dict[str, Any]] = {}
        for device in devices:
            for value in (device.get("mac"), *(device.get("macs") or [])):
                mac = norm_mac(value)
                if mac:
                    index.setdefault(mac, device)
        for row in self.state.rows(
            "SELECT device_id,facts_json FROM capability_evidence WHERE capability='stp' AND state='supported' "
            "ORDER BY observed_at DESC,id DESC"
        ):
            try:
                facts = json.loads(str(row.get("facts_json") or "{}"))
            except json.JSONDecodeError:
                continue
            mac = norm_mac(facts.get("switch_mac"))
            if not mac or mac in index:
                continue
            owner = next(
                (item for item in devices
                 if str(item.get("ip") or "") == str(row.get("device_id") or "")
                 or str(item.get("hostname") or "") == str(row.get("device_id") or "")),
                None,
            )
            if owner:
                index[mac] = owner
        return index

    def devices_needing_stp(self) -> List[Dict[str, Any]]:
        """Online switches whose most recent spanning-tree read did not parse."""
        return self.state.rows(
            "SELECT d.ip,d.hostname,d.platform,d.model,d.serial,d.mac,d.status,d.last_seen FROM devices d "
            "LEFT JOIN (SELECT device_id, state, MAX(observed_at) AS observed_at "
            "           FROM capability_evidence WHERE capability='stp' GROUP BY device_id) e "
            "  ON e.device_id = d.ip "
            "WHERE UPPER(COALESCE(d.status,'')) != 'OFFLINE' "
            "  AND (e.state IS NULL OR e.state != 'supported') "
            "ORDER BY d.hostname, d.ip"
        )

    def management_vlan(self) -> int:
        """The VLAN that carries switch management, used to identify uplinks."""
        try:
            value = int(self.config.public.get("management_vlan") or 4)
        except (TypeError, ValueError):
            return 4
        return value if 1 <= value <= 4094 else 4


    def collect_spanning_tree_topology(
        self,
        opts: GlobalOptions,
        devices: Optional[Sequence[Dict[str, Any]]] = None,
        jobs: int = 0,
    ) -> Dict[str, Any]:
        from netops_platform.core import clean_display_name, fmt_time, norm_mac, now
        """Read spanning tree from switches and derive switch-to-switch links.

        A port that reports a designated bridge other than this switch is on a
        segment owned by that bridge, which identifies the device at the far
        end. That covers root ports and blocked alternate ports, so redundant
        links are discovered too. A port whose designated bridge is this switch
        faces downstream and names nobody, so it yields no link here; the
        downstream switch reports that same link from its own side.
        """
        rows = list(devices) if devices is not None else self.state.rows(
            # Offline devices cannot answer and each one costs a full SSH
            # timeout, so a sweep skips them the way backup does.
            "SELECT ip,hostname,platform,model,serial,mac,status,last_seen FROM devices "
            "WHERE UPPER(COALESCE(status,'')) != 'OFFLINE' ORDER BY hostname,ip"
        )
        started = now()
        reads: Dict[str, Dict[str, Any]] = {}
        failures: List[Dict[str, Any]] = []
        reclassified: List[Dict[str, Any]] = []
        targets = [row for row in rows if str(row.get("ip") or row.get("hostname") or "")]
        total = len(targets)
        session_held = False
        workers = max(1, min(int(jobs or self._default_stp_jobs()), 32, total or 1))

        def read_one(device: Dict[str, Any]) -> Tuple[str, Dict[str, Any], Optional[str]]:
            identity = str(device.get("ip") or device.get("hostname") or "")
            try:
                # Recording is deferred to the main thread so every database
                # write stays on one connection and in a stable order.
                return identity, self.inspect_spanning_tree(device, opts, record=False, neighbors=True), None
            except Exception as exc:
                return identity, {}, str(exc)

        # One authentication for the whole sweep instead of one per switch. The
        # session must be open before any worker starts, or each one races to
        # authenticate on its own.
        with self.vault_session_scope(opts, minutes=30) as opened:
            session_held = bool(opened)
            completed = 0
            lock = threading.Lock()
            results: List[Tuple[str, Dict[str, Any], Optional[str]]] = []
            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=workers, thread_name_prefix="stp") as pool:
                    futures = {pool.submit(read_one, device): device for device in targets}
                    for future in concurrent.futures.as_completed(futures):
                        identity, parsed, error = future.result()
                        results.append((identity, parsed, error))
                        with lock:
                            completed += 1
                            label = clean_display_name(
                                futures[future].get("hostname") or identity
                            )
                            self._progress_step("topology stp", f"{label} | {workers} parallel", completed, total, opts)
            except KeyboardInterrupt:
                self._progress_clear(opts)
                raise
            finally:
                self._progress_clear(opts)

            # Keep the report ordered by inventory, not by completion order.
            order = {str(row.get("ip") or row.get("hostname") or ""): index for index, row in enumerate(targets)}
            for identity, parsed, error in sorted(results, key=lambda item: order.get(item[0], 0)):
                if error:
                    failures.append({"device": identity, "error": error})
                    continue
                if parsed.get("parsed"):
                    reads[identity] = parsed
                    if parsed.get("platform_corrected"):
                        reclassified.append({
                            "device": identity,
                            "from": parsed.get("reclassified_from") or "",
                            "to": parsed.get("reclassified_to") or "",
                            "platform": parsed.get("platform_corrected") or "",
                        })
                        self.state.execute(
                            "UPDATE devices SET platform=? WHERE ip=?",
                            (parsed["platform_corrected"], identity),
                        )
                    self.state.record_capability_evidence(
                        identity, "stp", "supported",
                        {key: value for key, value in parsed.items() if key not in {"observed_at", "parsed"}},
                        driver_family=str(parsed.get("driver_family") or ""),
                        confidence=95 if parsed.get("ports") else 70,
                        observed_at=int(parsed.get("observed_at") or started),
                    )
                    self.state.record_device_bridge_mac(identity, parsed.get("switch_mac"))
                else:
                    # Record the failure too, with what the switch actually
                    # returned, so an unparsed sweep is diagnosable afterwards.
                    self.state.record_capability_evidence(
                        identity, "stp",
                        "unsupported" if parsed.get("unsupported") else "unknown",
                        {
                            "commands": parsed.get("commands") or [],
                            "raw_excerpt": str(parsed.get("raw_excerpt") or ""),
                            "raw_bytes": int(parsed.get("raw_bytes") or 0),
                        },
                        raw=str(parsed.get("raw_excerpt") or identity),
                        driver_family=str(parsed.get("driver_family") or ""),
                        confidence=100 if parsed.get("unsupported") else 40,
                        observed_at=int(parsed.get("observed_at") or started),
                    )
                    failures.append({
                        "device": identity,
                        "error": str(parsed.get("error") or "unparsed"),
                        "raw_bytes": int(parsed.get("raw_bytes") or 0),
                        "raw_excerpt": str(parsed.get("raw_excerpt") or ""),
                    })

        # Inspecting a switch states its own bridge MAC, so build the index
        # after the reads and every inspected switch becomes resolvable.
        enriched = [dict(row) for row in rows]
        by_identity = {str(row.get("ip") or row.get("hostname") or ""): row for row in enriched}
        for identity, parsed in reads.items():
            device = by_identity.get(identity)
            if device is not None and norm_mac(parsed.get("switch_mac")):
                device.setdefault("macs", [])
                device["macs"] = sorted({*(device.get("macs") or []), norm_mac(parsed["switch_mac"])})
        # Resolve neighbours against the whole inventory, not just the switches
        # being inspected. Targeting one switch must still identify the devices
        # on the far end of its uplinks.
        known = self.state.rows(
            "SELECT ip,hostname,platform,model,serial,mac,status,last_seen FROM devices"
        )
        catalogue = {str(row.get("ip") or ""): dict(row) for row in known}
        for row in enriched:
            catalogue[str(row.get("ip") or "")] = row
        by_address = {key: row for key, row in catalogue.items() if key}
        by_name = {
            clean_display_name(row.get("hostname") or "").lower(): row
            for row in catalogue.values() if row.get("hostname")
        }
        index = self._bridge_mac_index(list(catalogue.values()))

        # Corroboration is per device pair, not per port: LLDP records a link
        # from whichever side has the protocol enabled, and spanning tree names
        # the link from the other side. Matching on the near port alone would
        # count the same physical link twice as "new".
        alias = {}
        for row in enriched:
            for value in (row.get("ip"), row.get("hostname")):
                if str(value or "").strip():
                    alias[str(value).strip().lower()] = str(row.get("ip") or row.get("hostname") or "")
        lldp_pairs: set[Tuple[str, str]] = set()
        for row in self.state.rows("SELECT local_ip,local_name,remote_ip,remote_name FROM neighbors"):
            left = alias.get(str(row.get("local_ip") or "").lower()) or alias.get(str(row.get("local_name") or "").lower())
            right = alias.get(str(row.get("remote_ip") or "").lower()) or alias.get(str(row.get("remote_name") or "").lower())
            if left and right:
                lldp_pairs.add((left, right))
                lldp_pairs.add((right, left))
        links: List[Dict[str, Any]] = []
        unresolved: List[Dict[str, Any]] = []
        seen_links: set[Tuple[str, str, str]] = set()

        # LLDP on an uplink port states the neighbour's name and management
        # address, so it identifies both ends without any MAC correlation.
        for identity, parsed in reads.items():
            device = by_identity.get(identity) or {}
            for neighbor in parsed.get("uplink_neighbors") or []:
                remote = by_address.get(neighbor.get("remote_ip") or "")
                if remote is None:
                    remote = by_name.get(str(neighbor.get("remote_name") or "").lower())
                if remote is None:
                    unresolved.append({
                        "device": identity,
                        "port": neighbor.get("local_port") or "",
                        "remote_name": neighbor.get("remote_name") or "",
                        "remote_ip": neighbor.get("remote_ip") or "",
                        "source": "lldp-uplink",
                    })
                    continue
                remote_id = str(remote.get("ip") or remote.get("hostname") or "")
                key = (identity, str(neighbor.get("local_port") or ""), remote_id)
                if not remote_id or remote_id == identity or key in seen_links:
                    continue
                seen_links.add(key)
                links.append({
                    "local_id": identity,
                    "local_ip": device.get("ip") or "",
                    "local_name": device.get("hostname") or "",
                    "local_port": str(neighbor.get("local_port") or ""),
                    "remote_id": remote_id,
                    "remote_name": remote.get("hostname") or neighbor.get("remote_name") or "",
                    "remote_ip": remote.get("ip") or "",
                    "remote_port": str(neighbor.get("remote_port") or ""),
                    "role": "uplink",
                    "state": "forwarding",
                    "designated_bridge": "",
                    "corroborates_lldp": True,
                    # Both ends named by the neighbour protocol on the port itself.
                    "confidence": 97,
                })

        for identity, parsed in reads.items():
            device = by_identity.get(identity) or {}
            own = norm_mac(parsed.get("switch_mac"))
            for port in parsed.get("ports") or []:
                bridge = norm_mac(port.get("designated_bridge"))
                if not bridge or (own and bridge == own):
                    continue
                if port.get("state") == "disabled":
                    continue
                remote = index.get(bridge)
                if not remote:
                    unresolved.append({
                        "device": identity,
                        "port": str(port.get("port") or ""),
                        "designated_bridge": bridge,
                    })
                    continue
                remote_id = str(remote.get("ip") or remote.get("hostname") or "")
                if not remote_id or remote_id == identity:
                    continue
                if (identity, str(port.get("port") or ""), remote_id) in seen_links:
                    continue
                corroborated = (identity, remote_id) in lldp_pairs
                links.append({
                    "local_id": identity,
                    "local_ip": device.get("ip") or "",
                    "local_name": device.get("hostname") or "",
                    "local_port": str(port.get("port") or ""),
                    "remote_id": remote_id,
                    "remote_name": remote.get("hostname") or "",
                    "remote_ip": remote.get("ip") or "",
                    "role": port.get("role") or "",
                    "state": port.get("state") or "",
                    "designated_bridge": bridge,
                    "corroborates_lldp": corroborated,
                    # Two independent protocols agreeing on a link is stronger
                    # evidence than either alone; spanning tree by itself is
                    # solid on the near port but names no far-end port.
                    "confidence": 96 if corroborated else 82,
                })
        # A switch that will not answer can still be identified by its
        # neighbours: LLDP carries the far end's system description. Where that
        # disagrees with inventory, inventory is what is wrong, and correcting
        # it lets the next attempt pick the right driver.
        described: Dict[str, str] = {}
        # Include neighbour descriptions recorded by earlier runs, so a retry of
        # only the failures can still identify them from evidence already held.
        for row in self.state.rows(
            "SELECT facts_json FROM capability_evidence WHERE capability='stp' AND state='supported' "
            "ORDER BY observed_at DESC LIMIT 500"
        ):
            try:
                facts = json.loads(str(row.get("facts_json") or "{}"))
            except json.JSONDecodeError:
                continue
            for neighbor in facts.get("uplink_neighbors") or []:
                address = str(neighbor.get("remote_ip") or "")
                platform = str(neighbor.get("platform") or "")
                if address and platform:
                    described.setdefault(address, platform)
        for parsed in reads.values():
            for neighbor in parsed.get("uplink_neighbors") or []:
                address = str(neighbor.get("remote_ip") or "")
                platform = str(neighbor.get("platform") or "")
                if address and platform:
                    described[address] = platform
        for failure in failures:
            address = str(failure.get("device") or "")
            description = described.get(address)
            if not description:
                continue
            current = by_identity.get(address) or catalogue.get(address) or {}
            detection = self.detect_device_family(sysdescr=description, hostname=current.get("hostname"))
            existing = self.detect_device_family(
                platform=current.get("platform"), model=current.get("model"), hostname=current.get("hostname")
            )
            if detection.family in {"", "unknown"} or detection.family == existing.family:
                continue
            corrected = {
                "cisco-ios": "Cisco IOS", "cisco-nxos": "Cisco NX-OS",
                "aruba-aos-switch": "Aruba AOS-S", "aruba-aos-cx": "Aruba AOS-CX",
                "ruckus-fastiron": "Ruckus FastIron",
            }.get(detection.family, detection.family)
            self.state.execute("UPDATE devices SET platform=?, model='' WHERE ip=?", (corrected, address))
            reclassified.append({
                "device": address,
                "from": existing.family,
                "to": detection.family,
                "platform": corrected,
                "source": "neighbor-lldp",
            })
            failure["reclassified_to"] = corrected

        if reclassified:
            # netrune-control selects its driver from the flat inventory file,
            # so a correction confined to SQLite would keep sending the wrong
            # vendor's commands on the next attempt.
            with contextlib.suppress(Exception):
                self.state.export_flat_files()

        recorded = self.state.record_stp_links(links, started)
        return {
            "ok": not failures or bool(reads),
            "observed_at": started,
            "observed_at_iso": fmt_time(started),
            "vault_session_held": session_held,
            "reclassified": reclassified,
            "parallel_jobs": workers,
            "switches_total": total,
            "switches_inspected": len(reads),
            "switches_failed": len(failures),
            "links": links,
            "links_recorded": recorded,
            "corroborated_links": sum(1 for link in links if link["corroborates_lldp"]),
            "new_links": sum(1 for link in links if not link["corroborates_lldp"]),
            "unresolved_bridges": unresolved,
            "failures": failures,
        }

