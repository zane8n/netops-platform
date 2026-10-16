"""Command surface for the vlan domain.

Kept out of core.py as a mixin, not free functions, because vlan_change_request
is called directly from command_for_action (the shared CLI/ask registry
engine), not just from cmd_vlan -- self.vlan_change_request(...) resolves the
same via MRO regardless of which file defines it, so that caller needed no
rewrite. Helpers shared with other not-yet-extracted domains (cached_switch_
neighbors/_switch_neighbor_evidence with lookup, capture_batch/
vault_session_scope more broadly) stay in core.py rather than moving here.
"""

from __future__ import annotations

import contextlib
import os
import re
import shlex
from typing import Any, Dict, List, Optional, Sequence, Tuple

from netops_platform.network import (
    clean_network_output,
    interface_matches,
    normalize_interface,
    parse_neighbor_detail_output,
    parse_trunk_summary,
    parse_vlan_control_output,
)


class VlanCommandsMixin:

    def _neighbor_device(self, neighbor: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        from netops_platform.core import IP_RE, clean_display_name
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


    def live_switch_neighbors(self, device: Dict[str, Any], timeout: int = 90) -> List[Dict[str, Any]]:
        from netops_platform.core import clean_display_name, compact_name
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
        # One SSH login for every neighbor-discovery command this driver has
        # (typically LLDP and CDP), rather than one per command -- this runs
        # once per switch during a topology scan, so the unbatched cost
        # multiplied by the size of the whole inventory.
        if len(commands) > 1:
            results = self.capture_batch(target, commands, timeout)
        elif commands:
            _, stdout, stderr = self.capture(self.legacy_cmd("netrune-control", "show", target, commands[0]), timeout)
            results = [(commands[0], (stdout or "") + (stderr or ""))]
        else:
            results = []
        for _command, text in results:
            for parsed in parse_neighbor_detail_output(text):
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


    def inspect_vlan_node(self, device: Dict[str, Any], vlan: int, mode: str, opts: GlobalOptions) -> Dict[str, Any]:
        from netops_platform.core import PARTIAL, clean_display_name, now
        target = str(device.get("ip") or "")
        display_name = clean_display_name(device.get("hostname") or target)
        helper_mode = "propagated" if mode == "propagation" else "locate-vlan"
        command = self.legacy_cmd("netrune-control", helper_mode, target, str(vlan))
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

        # The awk report can leave a trunk uncorrelated, which surfaces as
        # TRUNK_EVIDENCE_UNKNOWN even when the switch knows the answer. The
        # structured trunk summary states the allowed VLANs per port outright,
        # so it settles those cases and adds any trunk the report omitted.
        driver = self.driver_for(
            platform=device.get("platform"), model=device.get("model"), hostname=device.get("hostname"),
        )
        summary_templates = driver.command_templates.get("trunk_summary") or ()
        if summary_templates:
            with contextlib.suppress(Exception):
                summary_rc, summary_out, summary_err = self.capture(
                    self.legacy_cmd("netrune-control", "show", target, summary_templates[0]),
                    min(opts.timeout or 90, 180),
                )
                summary = parse_trunk_summary((summary_out or "") + (summary_err or ""))
                known = {normalize_interface(row.get("port")) for row in trunks}
                for port_name, row in summary.items():
                    allowed = list(row.get("allowed_vlans") or [])
                    if not allowed:
                        continue
                    carries = int(vlan) in allowed
                    key = normalize_interface(port_name)
                    existing = next((item for item in trunks if normalize_interface(item.get("port")) == key), None)
                    if existing is None:
                        trunks.append({
                            "port": port_name, "carries_vlan": carries,
                            "neighbor_name": "", "neighbor_ip": "",
                            "evidence_source": "trunk-summary",
                            "allowed_vlan_count": len(allowed),
                        })
                    elif existing.get("carries_vlan") is None:
                        existing["carries_vlan"] = carries
                        existing["evidence_source"] = "trunk-summary"
                    known.add(key)

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
        from netops_platform.core import PARTIAL, SUCCESS, VALIDATION, clean_display_name, fmt_time, now, timestamp_rows
        root, choices = self.resolve_device_record(target)
        if not root:
            labels = ", ".join(str(row.get("hostname") or row.get("ip")) for row in choices[:8])
            message = f"Ambiguous switch target {target!r}: {labels}" if choices else f"Switch target not found: {target}"
            return self.usage_error("vlan", mode, opts, message, f"netrune inventory list {shlex.quote(target)}", VALIDATION)

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
        from netops_platform.core import PARTIAL, SUCCESS, fmt_time, now
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
        from netops_platform.core import normalize_target_literal
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

    def _vlan_change_gate(self, request: Dict[str, Any], opts: GlobalOptions) -> Dict[str, Any]:
        """Resolve one VLAN-change target and evaluate its write-capability
        gate, without executing anything against the device. Always
        returns a dict with 'request', 'resolved', 'approved', and --
        whenever either is False -- 'reason'; 'device' carries the
        resolved row once found. Shared by the single-target path and the
        --file batch path so both reject a bad target/unsupported driver
        identically, and so a batch can validate every line before
        writing to any of them (same shape as device_cli's
        _device_config_gate)."""
        device, choices = self.resolve_device_record(request["target"])
        if not device:
            labels = ", ".join(str(row.get("hostname") or row.get("ip")) for row in choices[:8])
            reason = f"VLAN change target must resolve to exactly one inventory device: {request['target']}"
            if labels:
                reason += f" ({labels})"
            return {"request": request, "device": None, "resolved": False, "approved": False, "reason": reason}
        driver = self.driver_for(platform=device.get("platform"), model=device.get("model"), hostname=device.get("hostname"))
        detection = self.detect_device_family(
            platform=device.get("platform"),
            model=device.get("model"),
            hostname=device.get("hostname"),
        )
        writes_enabled = str(self.config.public.get("device_writes_enabled") or "").lower() in {"1", "true", "yes", "on"}
        write_support = driver.capability("vlan_write")
        # firmware_write_certified also honors the operator's own
        # device_certified_firmware config override, not just the built-in
        # firmware_profiles allow-list (see core.py for the full rationale).
        firmware_certified, firmware_certified_via = self.firmware_write_certified(
            driver, detection,
            platform=device.get("platform"), model=device.get("model"), hostname=device.get("hostname"),
        )
        write_approved = (
            driver.source == "built-in"
            and write_support == "firmware-gated"
            and writes_enabled
            and firmware_certified
        )
        if not write_approved:
            reason = f"VLAN writes require an explicitly enabled, certified built-in {driver.family} firmware profile; no network command was executed."
            if driver.source == "built-in" and write_support == "firmware-gated" and not firmware_certified:
                evidence = " ".join(str(v or "") for v in (device.get("platform"), device.get("model"), device.get("hostname"))).upper()
                reason += (
                    " Two ways to certify this device's firmware yourself: an exact match -- netrune config set "
                    f"device_certified_firmware \"{driver.family}:<regex>\" (match a short, distinctive substring of "
                    f"the evidence below, not a pattern bridging across it -- any character in between, e.g. the '3' "
                    f"in a model number, can break a [^0-9]*-style pattern like the built-in ones use); or a version "
                    f"floor, if this driver's commands don't meaningfully change across a whole range -- netrune "
                    f"config set device_certified_firmware_min \"{driver.family}:<major.minor>\". Evidence: {evidence}"
                )
            return {
                "request": request, "device": device, "resolved": True, "approved": False, "reason": reason,
                "driver_family": driver.family, "firmware_profile": detection.firmware_profile,
                "firmware_certified": firmware_certified, "firmware_certified_via": firmware_certified_via,
                "writes_enabled": writes_enabled, "support": write_support,
            }
        return {"request": request, "device": device, "resolved": True, "approved": True, "reason": ""}

    def apply_vlan_change(self, request: Dict[str, Any], opts: GlobalOptions) -> int:
        from netops_platform.core import PARTIAL, SUCCESS, UNSUPPORTED, VALIDATION
        public_command = [self.paths.tool("netrune"), "vlan", "set", request["target"], request["interface"], f"--{request['vlan_mode']}", request["vlan"]]
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
        gate = self._vlan_change_gate(request, opts)
        if not gate["resolved"]:
            return self.usage_error("vlan", "set", opts, gate["reason"], "netrune vlan set <target> <interface> --access 131 --dry-run", VALIDATION)
        if not gate["approved"]:
            payload = {
                "ok": False, "status": "UNSUPPORTED",
                "request": {k:v for k,v in request.items() if k != "helper_args"},
                "device": gate["device"], "driver_family": gate.get("driver_family"),
                "firmware_profile": gate.get("firmware_profile"), "firmware_certified": gate.get("firmware_certified"),
                "firmware_certified_via": gate.get("firmware_certified_via"), "writes_enabled": gate.get("writes_enabled"),
                "support": gate.get("support"), "error": gate["reason"],
            }
            self.emit(payload, opts, payload["error"])
            return UNSUPPORTED
        payload = self._run_guarded_vlan_change(gate["device"], request, opts)
        if payload["status"] in {"BLOCKED", "FAILED"}:
            self.emit(payload, opts, payload["error"])
            return PARTIAL
        device = gate["device"]
        name = str(device.get("hostname") or device.get("ip") or request["target"])
        ip = str(device.get("ip") or "")
        text = f"Guarded VLAN change: {payload['status']}\nDevice: {name} ({ip}) {request['interface']}\n" + self.render_table(payload["phases"], ["phase", "status", "exit_code", "detail"]) + f"\nRecorded: {payload['finished_at_iso']}\n{payload['rollback']}"
        self.emit(payload, opts, text)
        return SUCCESS if payload["verified"] else PARTIAL

    def _run_guarded_vlan_change(self, device: Dict[str, Any], request: Dict[str, Any], opts: GlobalOptions) -> Dict[str, Any]:
        """Backup, apply, verify one device's VLAN change and return the
        result payload -- does not emit output or return an exit code, so
        both the single-target wrapper (apply_vlan_change) and the --file
        batch path (apply_vlan_change_batch) can share the network calls
        and the audit-event bookkeeping without duplicating them (same
        split as device_cli's _run_guarded_device_config_change)."""
        from netops_platform.core import fmt_time, now
        ip = str(device.get("ip") or "")
        name = str(device.get("hostname") or ip)
        platform = f"{device.get('platform') or ''} {device.get('model') or ''}".lower()
        preflight_command = f"show vlan ports {request['interface']} detail" if any(token in platform for token in ("aruba", "procurve", "hp")) else f"show interfaces {request['interface']} switchport"
        started = now()
        phase_results: List[Dict[str, Any]] = []
        self.live_log("change", f"1/4 preflight {name} {request['interface']}")
        pre_rc, pre_out, pre_err = self.capture(self.legacy_cmd("netrune-control", "show", ip, preflight_command), opts.timeout or 180, opts)
        pre_excerpt = " ".join(clean_network_output((pre_out or "") + (pre_err or "")).split())[:1600]
        phase_results.append({"phase": "preflight", "status": "PASS" if pre_rc == 0 and pre_excerpt else "FAIL", "exit_code": pre_rc, "detail": pre_excerpt})
        if pre_rc != 0 or not pre_excerpt:
            return {"ok": False, "status": "BLOCKED", "request": request, "device": device, "phases": phase_results, "error": "Pre-change interface evidence could not be captured; no configuration was applied.", "started_at": started, "finished_at": now()}
        self.live_log("change", f"2/4 backup {name}")
        backup_rc, backup_out, backup_err = self.capture(self.legacy_cmd("netrune-control", "backup", ip, "--online-only", "--changed-only", "--summary"), opts.timeout or 300, opts)
        backup_excerpt = " ".join(clean_network_output((backup_out or "") + (backup_err or "")).split())[:1200]
        phase_results.append({"phase": "backup", "status": "PASS" if backup_rc == 0 else "FAIL", "exit_code": backup_rc, "detail": backup_excerpt})
        if backup_rc != 0:
            return {"ok": False, "status": "BLOCKED", "request": request, "device": device, "phases": phase_results, "error": "Configuration backup failed; no VLAN change was applied.", "started_at": started, "finished_at": now()}
        self.live_log("change", f"3/4 apply {request['vlan_mode']} VLAN {request['vlan']} on {name} {request['interface']}")
        apply_rc, apply_out, apply_err = self.capture(self.legacy_cmd("netrune-control", *request["helper_args"]), opts.timeout or 300, opts)
        apply_excerpt = " ".join(clean_network_output((apply_out or "") + (apply_err or "")).split())[:1600]
        phase_results.append({"phase": "apply", "status": "PASS" if apply_rc == 0 else "FAIL", "exit_code": apply_rc, "detail": apply_excerpt})
        if apply_rc != 0:
            return {"ok": False, "status": "FAILED", "request": request, "device": device, "phases": phase_results, "error": "Device rejected the VLAN change. Review pre-change evidence before any manual rollback.", "started_at": started, "finished_at": now()}
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
            verify_rc, verify_out, verify_err = self.capture(self.legacy_cmd("netrune-control", "locate-vlan", ip, str(verification_vlan)), opts.timeout or 180, opts)
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
        return payload

    def apply_vlan_change_batch(self, requests: List[Dict[str, Any]], opts: GlobalOptions, *, skip_unverified: bool = False) -> int:
        """`vlan set --file <path>`: run the same guarded lifecycle across
        many device+interface VLAN changes, one line = one fully
        independent change (own target, interface, mode, vlan). Every
        line is resolved and gate-checked up front (see _vlan_change_gate)
        before any of them touch a device -- same batch-abort-by-default,
        --skip-unverified-softens-it shape as device_cli's
        apply_device_config_batch, applied to VLAN instead of raw config.

        Devices are written to one at a time inside one vault session, not
        in parallel -- no existing precedent for concurrent device writes
        in this codebase, same reasoning as the device-config batch.
        """
        from netops_platform.core import PARTIAL, SUCCESS, UNSUPPORTED, VALIDATION, fmt_time, now

        gates = [self._vlan_change_gate(request, opts) for request in requests]

        skipped: List[Dict[str, Any]] = []
        if skip_unverified:
            runnable = [g for g in gates if g["resolved"] and g["approved"]]
            skipped = [g for g in gates if not (g["resolved"] and g["approved"])]
        else:
            unresolved = [g for g in gates if not g["resolved"]]
            if unresolved:
                reason = "VLAN batch not started; the following lines did not resolve to exactly one device:\n" + "\n".join(f"  {g['request']['target']} {g['request']['interface']}: {g['reason']}" for g in unresolved) + "\nRe-run with --skip-unverified to proceed with the rest instead."
                return self.usage_error("vlan", "set", opts, reason, "netrune inventory list <target>", VALIDATION)
            unsupported = [g for g in gates if not g["approved"]]
            if unsupported:
                reason = "VLAN batch not started; the following lines are not approved for this write:\n" + "\n".join(f"  {g['request']['target']} {g['request']['interface']}: {g['reason']}" for g in unsupported) + "\nRe-run with --skip-unverified to proceed with the rest instead."
                payload = {"ok": False, "status": "UNSUPPORTED", "devices": unsupported, "reason": reason}
                self.emit(payload, opts, reason)
                return UNSUPPORTED
            runnable = gates

        if not runnable:
            reason = "VLAN batch not started; every line was skipped (none resolved and approved):\n" + "\n".join(f"  {g['request']['target']} {g['request']['interface']}: {g['reason']}" for g in skipped)
            payload = {"ok": False, "status": "UNSUPPORTED", "devices": skipped, "reason": reason}
            self.emit(payload, opts, reason)
            return UNSUPPORTED

        if opts.dry_run:
            preview_rows = [{"target": g["request"]["target"], "interface": g["request"]["interface"], "change": f"{g['request']['vlan_mode']} {g['request']['vlan']}"} for g in runnable]
            skipped_rows = [{"target": g["request"]["target"], "interface": g["request"]["interface"], "reason": g["reason"]} for g in skipped]
            payload = {"ok": True, "dry_run": True, "devices": preview_rows, "skipped": skipped_rows}
            text = f"Would apply {len(runnable)} VLAN change(s):\n" + self.render_table(preview_rows, ["target", "interface", "change"])
            if skipped_rows:
                text += f"\n\nSkipped {len(skipped_rows)} line(s):\n" + self.render_table(skipped_rows, ["target", "interface", "reason"])
            self.emit(payload, opts, text)
            return SUCCESS

        started = now()
        results: List[Dict[str, Any]] = []
        with self.vault_session_scope(opts, minutes=30):
            for index, gate in enumerate(runnable, 1):
                device = gate["device"]; request = gate["request"]
                self.live_log("change", f"line {index}/{len(runnable)}: {request['target']} {request['interface']}")
                results.append(self._run_guarded_vlan_change(device, request, opts))
        finished = now()

        status_key = {"SUCCESS": "success", "ATTENTION": "attention", "BLOCKED": "blocked", "FAILED": "failed"}
        counts = {"total": len(results), "success": 0, "attention": 0, "blocked": 0, "failed": 0, "skipped": len(skipped)}
        for result in results:
            counts[status_key[result["status"]]] += 1
        summary_rows = [
            {"target": result["request"]["target"], "interface": result["request"]["interface"], "status": result["status"], "verified": result.get("verified", False), "detail": result.get("error") or (result["phases"][-1]["detail"] if result.get("phases") else "")}
            for result in results
        ] + [
            {"target": g["request"]["target"], "interface": g["request"]["interface"], "status": "SKIPPED", "verified": False, "detail": g["reason"]}
            for g in skipped
        ]
        all_succeeded = counts["success"] == counts["total"] and not skipped
        payload = {
            "ok": all_succeeded, "devices": results, "skipped_devices": skipped, "counts": counts,
            "started_at": started, "started_at_iso": fmt_time(started),
            "finished_at": finished, "finished_at_iso": fmt_time(finished),
        }
        headline = f"Guarded VLAN batch: {counts['success']}/{counts['total']} attempted succeeded"
        if not all_succeeded:
            headline += f" ({counts['attention']} attention, {counts['blocked']} blocked, {counts['failed']} failed, {counts['skipped']} skipped)"
        text = headline + "\n" + self.render_table(summary_rows, ["target", "interface", "status", "verified", "detail"])
        self.emit(payload, opts, text)
        return SUCCESS if all_succeeded else PARTIAL

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
        from netops_platform.core import CONFIRM_REQUIRED, SUCCESS, VALIDATION
        if self.handle_help("vlan", args, opts): return SUCCESS
        verb=args[0] if args else "locate"; rest=args[1:]
        if verb=="locate":
            try: targets, vlans = self.parse_vlan_scan_request(rest)
            except ValueError as exc: return self.usage_error("vlan","locate",opts,str(exc),"netrune vlan locate SW1,SW2 10,20 --depth 2",VALIDATION)
            if opts.depth or len(targets)>1 or len(vlans)>1: return self.vlan_cascade_many(targets,vlans,"locate",opts)
            return self.run_subprocess(self.legacy_cmd("netrune-control","locate-vlan",targets[0],str(vlans[0])),opts)
        if verb=="propagation":
            try: targets, vlans = self.parse_vlan_scan_request(rest)
            except ValueError as exc: return self.usage_error("vlan","propagation",opts,str(exc),"netrune vlan propagation SW1,SW2 10,20 --depth 2",VALIDATION)
            if opts.depth or len(targets)>1 or len(vlans)>1: return self.vlan_cascade_many(targets,vlans,"propagation",opts)
            return self.run_subprocess(self.legacy_cmd("netrune-control","propagated",targets[0],str(vlans[0])),opts)
        if verb=="set":
            # --file fans the same guarded lifecycle out across many lines,
            # each one a fully independent "<target> <interface> --access|
            # --trunk <vlan> [--native N] [--replace]" -- same syntax as the
            # single-target form below, one per line, so a line is exactly
            # what you'd type on the command line for that one change.
            file_path=None; skip_unverified=("--skip-unverified" in rest)
            positional=[x for x in rest if x!="--skip-unverified"]
            i=0
            while i<len(positional):
                if positional[i]=="--file" and i+1<len(positional): file_path=positional[i+1]; del positional[i:i+2]
                else: i+=1
            if file_path:
                if not (opts.dry_run or opts.confirm): return self.usage_error("vlan","set",opts,"VLAN changes require --dry-run or --confirm.","netrune vlan set --file changes.txt --dry-run",CONFIRM_REQUIRED)
                try:
                    with open(file_path,"r",encoding="utf-8") as handle: raw_lines=handle.readlines()
                except OSError as exc:
                    return self.usage_error("vlan","set",opts,f"Could not read {file_path}: {exc}","netrune vlan set --file changes.txt --dry-run",VALIDATION)
                requests: List[Dict[str, Any]]=[]
                for line_number, raw_line in enumerate(raw_lines,1):
                    line=raw_line.split("#",1)[0].strip()
                    if not line: continue
                    try:
                        parsed=self._parse_vlan_set_tokens(shlex.split(line))
                        requests.append(self.vlan_change_request(parsed))
                    except ValueError as exc:
                        return self.usage_error("vlan","set",opts,f"{file_path}:{line_number}: {exc}","netrune vlan set --file changes.txt --dry-run",VALIDATION)
                if not requests:
                    return self.usage_error("vlan","set",opts,f"{file_path} has no VLAN change lines.","netrune vlan set --file changes.txt --dry-run",VALIDATION)
                return self.apply_vlan_change_batch(requests,opts,skip_unverified=skip_unverified)
            rest=positional
            if len(rest)<2: return self.usage_error("vlan","set",opts,"Missing target or interface.","netrune vlan set ZONE34 Gi1/0/7 --access 120 --dry-run")
            if not (opts.dry_run or opts.confirm): return self.usage_error("vlan","set",opts,"VLAN changes require --dry-run or --confirm.","netrune vlan set ZONE34 Gi1/0/7 --access 120 --dry-run",CONFIRM_REQUIRED)
            try: parsed = self._parse_vlan_set_tokens(rest)
            except ValueError as exc: return self.usage_error("vlan", "set", opts, str(exc), "netrune vlan set ZONE34 Gi1/0/7 --access 120 --dry-run", VALIDATION)
            try: request = self.vlan_change_request(parsed)
            except ValueError as exc: return self.usage_error("vlan", "set", opts, str(exc), "netrune vlan set ZONE34 Gi1/0/7 --access 120 --dry-run", VALIDATION)
            with self.vault_session_scope(opts, minutes=30):
                return self.apply_vlan_change(request,opts)
        return self.unknown_action("vlan", verb, opts)

    def _parse_vlan_set_tokens(self, tokens: List[str]) -> Dict[str, Any]:
        """Parse '<target> <interface> --access|--trunk <vlan> [--native N]
        [--replace]' into vlan_change_request's raw args shape. Shared by
        the single CLI invocation and each line of a --file batch so both
        accept exactly the same syntax."""
        if len(tokens) < 2:
            raise ValueError("Missing target or interface.")
        parsed: Dict[str, Any] = {"target": tokens[0], "interface": tokens[1]}
        index = 2
        while index < len(tokens):
            item = tokens[index]
            if item in {"--access", "--trunk"} and index + 1 < len(tokens):
                parsed["vlan_mode"] = item[2:]; parsed["vlan"] = tokens[index + 1]; index += 2
            elif item == "--native" and index + 1 < len(tokens):
                parsed["native_vlan"] = tokens[index + 1]; index += 2
            elif item == "--replace":
                parsed["replace"] = True; index += 1
            else:
                raise ValueError(f"Unknown or incomplete VLAN option: {item}")
        return parsed

