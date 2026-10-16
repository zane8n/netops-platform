"""Bounded Layer 2/Layer 3 path inspection with chronological evidence."""

from __future__ import annotations

import ipaddress
import json
import re
import time
import uuid
from collections import deque
from dataclasses import dataclass, replace
from typing import Any, Mapping

from netops_platform.contracts import (
    SCHEMA_VERSION,
    PathFindingV1,
    PathHopV1,
    PathRequestV1,
    PathResultV1,
    _rfc3339,
)


def _key(value: Any) -> str:
    return re.sub(r"[^a-z0-9.]", "", str(value or "").lower())


def _mac(value: Any) -> str:
    text = re.sub(r"[^0-9a-f]", "", str(value or "").lower())
    return text if len(text) == 12 else ""


def _ip(value: Any) -> str:
    try:
        return str(ipaddress.ip_address(str(value or "").strip()))
    except ValueError:
        return ""


def _interface(value: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value or "").lower())


@dataclass(frozen=True)
class GraphEdge:
    source: str
    destination: str
    source_port: str
    destination_port: str
    observed_at: int
    source_kind: str = "topology-cache"


class PathInspector:
    def __init__(self, app: Any):
        self.app = app
        self.state = app.state

    def _devices(self) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
        devices: dict[str, dict[str, Any]] = {}
        aliases: dict[str, str] = {}
        for raw in self.state.rows("SELECT ip,hostname,platform,model,serial,mac,status,last_seen FROM devices"):
            row = dict(raw)
            identity = _ip(row.get("ip")) or _key(row.get("hostname"))
            if not identity:
                continue
            devices[identity] = row
            for value in (identity, row.get("ip"), row.get("hostname")):
                if _key(value):
                    aliases[_key(value)] = identity
        for raw in self.state.rows(
            "SELECT identity_value,ip,name FROM inventory_identity_state WHERE entity_type='device'"
        ):
            identity = aliases.get(_key(raw.get("ip"))) or aliases.get(_key(raw.get("name")))
            if identity and _key(raw.get("identity_value")):
                aliases[_key(raw.get("identity_value"))] = identity
        return devices, aliases

    def _topology(self, aliases: Mapping[str, str]) -> tuple[dict[str, list[GraphEdge]], int]:
        graph: dict[str, list[GraphEdge]] = {}
        rows = self.state.rows(
            "SELECT local_ip,local_name,local_port,remote_name,remote_port,remote_ip FROM neighbors "
            "ORDER BY local_ip,local_port,remote_name,remote_port"
        )
        topology_stamp = self.state.one(
            "SELECT MAX(COALESCE(finished_at,started_at,0)) AS stamp FROM scan_runs WHERE domain='topology'"
        )
        newest = int((topology_stamp or {}).get("stamp") or 0)
        if not newest:
            neighbors_file = getattr(getattr(self.app, "paths", None), "neighbors_file", None)
            if neighbors_file:
                try:
                    newest = int(neighbors_file.stat().st_mtime)
                except OSError:
                    newest = 0
        for row in rows:
            source = aliases.get(_key(row.get("local_ip"))) or aliases.get(_key(row.get("local_name")))
            destination = aliases.get(_key(row.get("remote_ip"))) or aliases.get(_key(row.get("remote_name")))
            if not source or not destination or source == destination:
                continue
            edge = GraphEdge(source, destination, str(row.get("local_port") or ""), str(row.get("remote_port") or ""), newest)
            reverse = GraphEdge(destination, source, str(row.get("remote_port") or ""), str(row.get("local_port") or ""), newest)
            graph.setdefault(source, []).append(edge)
            graph.setdefault(destination, []).append(reverse)
        # Spanning-tree links extend the graph where LLDP/CDP is silent. They
        # are added only for pairs LLDP did not already cover, and never
        # replace an LLDP edge, which knows both ends of the link.
        known_pairs = {
            (edge.source, edge.destination)
            for edges in graph.values() for edge in edges
        }
        for row in self.state.rows(
            "SELECT subject_id,object_id,switch_ip,switch_name,switch_port,confidence,last_seen,updated_at "
            "FROM relationships_current WHERE rel_type='stp_link' AND COALESCE(status,'')!='disappeared' "
            "ORDER BY subject_id,switch_port"
        ):
            source = aliases.get(_key(row.get("switch_ip"))) or aliases.get(_key(row.get("subject_id")))
            destination = aliases.get(_key(row.get("object_id")))
            if not source or not destination or source == destination:
                continue
            if (source, destination) in known_pairs:
                continue
            stamp = int(row.get("last_seen") or row.get("updated_at") or newest or 0)
            # A spanning-tree read is a topology observation too, so it counts
            # toward how fresh the graph is.
            newest = max(newest, stamp)
            port = str(row.get("switch_port") or "")
            # The far-end port is genuinely unknown from spanning tree, so it
            # is left empty rather than guessed. Downstream trunk validation
            # treats an empty port as "no evidence" instead of a claim.
            graph.setdefault(source, []).append(
                GraphEdge(source, destination, port, "", stamp, "spanning-tree")
            )
            graph.setdefault(destination, []).append(
                GraphEdge(destination, source, "", port, stamp, "spanning-tree")
            )
            known_pairs.add((source, destination))
            known_pairs.add((destination, source))
        for edges in graph.values():
            edges.sort(key=lambda item: (item.destination, item.source_port, item.destination_port))
        return graph, newest

    def _resolve_switch(self, value: str, aliases: Mapping[str, str]) -> str:
        if not value:
            return ""
        normalized = _ip(value) or _key(value)
        if normalized in aliases:
            return aliases[normalized]
        row, choices = self.app.resolve_device_record(value)
        if row and len(choices) <= 1:
            return _ip(row.get("ip")) or _key(row.get("hostname"))
        return ""

    def _endpoint_attachment(self, endpoint: str, aliases: Mapping[str, str], vlan: int = 0) -> tuple[str, str, dict[str, Any]]:
        clean_mac = _mac(endpoint)
        endpoint_ip = _ip(endpoint)
        candidates: list[dict[str, Any]] = []
        if clean_mac:
            expression = "lower(replace(replace(replace(replace(COALESCE(subject_id,''),':',''),'.',''),'-',''),' ',''))"
            candidates = self.state.rows(
                f"SELECT switch_ip,switch_name,switch_port,confidence,last_seen,updated_at,attrs_json,source FROM relationships_current "
                f"WHERE rel_type='mac_location' AND {expression}=? AND COALESCE(status,'')!='disappeared' "
                "ORDER BY COALESCE(last_seen,updated_at,0) DESC",
                (clean_mac,),
            )
        elif endpoint_ip:
            candidates = self.state.rows(
                "SELECT switch_ip,switch_name,switch_port,95 AS confidence,last_seen,last_seen AS updated_at,'{}' AS attrs_json,source "
                "FROM aps WHERE ip=? AND COALESCE(switch_ip,switch_name,'')!='' ORDER BY last_seen DESC",
                (endpoint_ip,),
            )
            if not candidates:
                candidates = self.state.rows(
                    "SELECT switch_ip,switch_name,switch_port,confidence,last_seen,updated_at,attrs_json,source "
                    "FROM relationships_current WHERE lower(COALESCE(attrs_json,'')) LIKE ? "
                    "AND rel_type IN ('ap_attachment','mac_location','port_occupancy') ORDER BY COALESCE(last_seen,updated_at,0) DESC",
                    (f'%"{endpoint_ip.lower()}"%',),
                )
        else:
            ap = self.state.one(
                "SELECT switch_ip,switch_name,switch_port,last_seen,source FROM aps WHERE lower(name)=lower(?) ORDER BY last_seen DESC LIMIT 1",
                (endpoint,),
            )
            if ap:
                candidates = [{**ap, "confidence": 90, "updated_at": ap.get("last_seen"), "attrs_json": "{}"}]
        resolved: list[tuple[str, dict[str, Any]]] = []
        for row in candidates:
            identity = aliases.get(_key(row.get("switch_ip"))) or aliases.get(_key(row.get("switch_name")))
            if identity:
                evidence = dict(row)
                with_json = str(evidence.pop("attrs_json", "") or "")
                if with_json:
                    try:
                        evidence["attributes"] = json.loads(with_json)
                    except json.JSONDecodeError:
                        evidence["attributes"] = {}
                attributes = evidence.get("attributes") if isinstance(evidence.get("attributes"), Mapping) else {}
                evidence["observed_vlan"] = str(attributes.get("vlan") or evidence.get("vlan") or "")
                resolved.append((identity, evidence))
        if resolved:
            eligible = resolved
            if vlan:
                matching = [item for item in resolved if str(item[1].get("observed_vlan") or "") == str(vlan)]
                unknown = [item for item in resolved if not str(item[1].get("observed_vlan") or "")]
                if matching:
                    eligible = matching
                elif unknown:
                    eligible = unknown
                else:
                    observed_vlans = sorted({
                        str(item.get("observed_vlan") or "") for _, item in resolved
                        if str(item.get("observed_vlan") or "")
                    })
                    return "", "", {
                        "candidates": len(resolved),
                        "vlan_mismatch": True,
                        "requested_vlan": int(vlan),
                        "observed_vlans": observed_vlans,
                        "alternatives": [
                            {
                                "device_id": item_identity,
                                "switch_port": item.get("switch_port"),
                                "observed_vlan": item.get("observed_vlan"),
                                "last_seen": item.get("last_seen"),
                            }
                            for item_identity, item in resolved[:8]
                        ],
                    }
            identity, evidence = eligible[0]
            locations = {
                (item_identity, str(item.get("switch_port") or ""))
                for item_identity, item in eligible
            }
            if len(locations) > 1:
                evidence["ambiguous"] = True
                evidence["alternatives"] = [
                    {
                        "device_id": item_identity,
                        "switch_port": item.get("switch_port"),
                        "observed_vlan": item.get("observed_vlan"),
                        "last_seen": item.get("last_seen"),
                    }
                    for item_identity, item in eligible[:8]
                ]
            return identity, str(evidence.get("switch_port") or ""), evidence
        return "", "", {"candidates": len(candidates)}

    @staticmethod
    def _bfs(
        graph: Mapping[str, list[GraphEdge]], source: str, destination: str, depth: int, max_nodes: int
    ) -> tuple[list[str], list[GraphEdge], int, bool]:
        queue: deque[str] = deque([source])
        parent: dict[str, tuple[str, GraphEdge] | None] = {source: None}
        levels = {source: 0}
        visited = 0
        budget_hit = False
        while queue:
            node = queue.popleft()
            visited += 1
            if node == destination:
                break
            if visited >= max_nodes:
                budget_hit = bool(queue or graph.get(node))
                break
            if levels[node] >= depth:
                continue
            for edge in graph.get(node, []):
                if edge.destination in parent:
                    continue
                if len(parent) >= max_nodes:
                    budget_hit = True
                    break
                parent[edge.destination] = (node, edge)
                levels[edge.destination] = levels[node] + 1
                queue.append(edge.destination)
        if destination not in parent:
            return [], [], visited, budget_hit
        nodes: list[str] = []
        edges: list[GraphEdge] = []
        current = destination
        while current:
            nodes.append(current)
            relation = parent[current]
            if relation is None:
                break
            previous, edge = relation
            edges.append(edge)
            current = previous
        nodes.reverse()
        edges.reverse()
        return nodes, edges, visited, budget_hit

    def _capabilities(self, device: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
        identities = [str(device.get("ip") or ""), str(device.get("hostname") or "")]
        rows = self.state.rows(
            "SELECT * FROM capability_evidence WHERE device_id IN (?,?) "
            "ORDER BY observed_at DESC,id DESC",
            tuple(identities),
        )
        output: dict[str, dict[str, Any]] = {}
        for row in rows:
            item = dict(row)
            capability = str(item.get("capability") or "")
            if not capability or capability in output:
                continue
            try:
                item["facts"] = json.loads(str(item.get("facts_json") or "{}"))
            except json.JSONDecodeError:
                item["facts"] = {}
            output[capability] = item
        return output

    @staticmethod
    def _find_trunk(inspected: Mapping[str, Any], next_device: Mapping[str, Any], cached_edge: GraphEdge | None) -> Mapping[str, Any] | None:
        next_ip = _ip(next_device.get("ip"))
        next_name = _key(next_device.get("hostname"))
        for link in inspected.get("links") or []:
            neighbor = link.get("neighbor") if isinstance(link.get("neighbor"), Mapping) else {}
            if (
                (next_ip and _ip(neighbor.get("remote_ip") or link.get("neighbor_ip")) == next_ip)
                or (next_name and _key(neighbor.get("remote_name") or link.get("neighbor_name")) == next_name)
                or (cached_edge and cached_edge.source_port and str(link.get("port") or "").lower() == cached_edge.source_port.lower())
            ):
                return link
        return None

    @staticmethod
    def _find_link_on_port(inspected: Mapping[str, Any], port: str) -> Mapping[str, Any] | None:
        wanted = _interface(port)
        if not wanted:
            return None
        return next(
            (link for link in inspected.get("links") or [] if _interface(link.get("port")) == wanted),
            None,
        )

    def _live_mac_walk(
        self,
        source: str,
        endpoint: str,
        vlan: int,
        depth: int,
        max_nodes: int,
        devices: dict[str, dict[str, Any]],
        aliases: dict[str, str],
        options: Any,
    ) -> dict[str, Any]:
        """Follow one MAC from the core through switch-facing FDB ports."""
        nodes: list[str] = []
        edges: list[GraphEdge] = []
        probes: dict[str, dict[str, Any]] = {}
        findings: list[PathFindingV1] = []
        current = source
        endpoint_port = ""
        attachment: dict[str, Any] = {}
        complete = False
        seen: set[str] = set()

        for layer in range(depth + 1):
            if current in seen:
                findings.append(PathFindingV1(
                    "error", "FORWARDING_LOOP_DETECTED",
                    "The MAC forwarding walk returned to an already visited switch.",
                    device_id=current, confidence=98,
                ))
                break
            if len(nodes) >= max_nodes:
                findings.append(PathFindingV1(
                    "warning", "NODE_BUDGET_REACHED",
                    "Live forwarding inspection reached the maximum node budget.",
                    device_id=current, confidence=100, evidence={"max_nodes": max_nodes},
                ))
                break
            seen.add(current)
            nodes.append(current)
            device = devices[current]
            if hasattr(self.app, "live_log"):
                self.app.live_log(
                    "path",
                    f"{layer}/{depth} trace {device.get('hostname') or current} for MAC {endpoint} VLAN {vlan}",
                )
            try:
                probe = dict(self.app.inspect_path_forwarding_node(device, endpoint, vlan, options))
            except Exception as exc:
                probe = {"observed_at": int(time.time()), "error": str(exc)}
            probes[current] = probe
            port = str(probe.get("port") or "")
            if probe.get("error") or not port:
                mismatch = str(probe.get("error_code") or "") == "MAC_VLAN_MISMATCH"
                findings.append(PathFindingV1(
                    "error" if mismatch else "warning",
                    "MAC_VLAN_MISMATCH" if mismatch else "FDB_EVIDENCE_UNAVAILABLE",
                    str(probe.get("error") or "The endpoint MAC was not found in this switch forwarding table."),
                    device_id=current, confidence=85,
                    evidence_observed_at=int(probe.get("observed_at") or 0) or None,
                    evidence={
                        "driver_family": probe.get("driver_family"),
                        "hits": probe.get("hits") or [],
                        "reported_vlans": probe.get("reported_vlans") or [],
                    },
                ))
                break
            if probe.get("ambiguous"):
                findings.append(PathFindingV1(
                    "warning", "AMBIGUOUS_FDB_PORT",
                    "The endpoint MAC was learned on more than one port; the VLAN-matching port was selected.",
                    device_id=current, interface=port, confidence=70,
                    evidence_observed_at=int(probe.get("observed_at") or 0) or None,
                    evidence={"hits": probe.get("hits") or []},
                ))

            next_device = dict(probe.get("next_device") or {})
            neighbor = dict(probe.get("neighbor") or {})
            if not next_device:
                endpoint_port = port
                attachment = {
                    "switch_ip": device.get("ip") or current,
                    "switch_name": device.get("hostname") or current,
                    "switch_port": port,
                    "last_seen": int(probe.get("observed_at") or time.time()),
                    "updated_at": int(probe.get("observed_at") or time.time()),
                    "confidence": 96,
                    "source": "live-fdb-neighbor-walk",
                    "attributes": {"vlan": str(vlan), "entry_type": (probe.get("selected") or {}).get("entry_type", "")},
                }
                complete = True
                break

            next_identity = _ip(next_device.get("ip")) or _key(next_device.get("hostname"))
            if not next_identity:
                findings.append(PathFindingV1(
                    "warning", "NEXT_SWITCH_UNRESOLVED",
                    "The learned switch-facing port has neighbor evidence, but its device identity could not be resolved.",
                    device_id=current, interface=port, confidence=75, evidence=neighbor,
                ))
                break
            if next_identity not in devices:
                devices[next_identity] = next_device
            for value in (next_identity, next_device.get("ip"), next_device.get("hostname")):
                if _key(value):
                    aliases[_key(value)] = next_identity
            if next_identity in seen:
                findings.append(PathFindingV1(
                    "error", "FORWARDING_LOOP_DETECTED",
                    "The learned MAC points back to a switch already present in this path.",
                    device_id=current, interface=port, confidence=98,
                    evidence={"next_device": next_identity},
                ))
                break
            edges.append(GraphEdge(
                current,
                next_identity,
                port,
                str(neighbor.get("remote_port") or ""),
                int(probe.get("observed_at") or time.time()),
                "live-fdb-lldp-cdp",
            ))
            if layer >= depth:
                findings.append(PathFindingV1(
                    "warning", "DEPTH_LIMIT_REACHED",
                    "The forwarding walk found another switch after reaching the configured depth.",
                    device_id=current, interface=port, confidence=100, evidence={"depth": depth},
                ))
                break
            current = next_identity

        return {
            "nodes": nodes,
            "edges": edges,
            "probes": probes,
            "findings": findings,
            "complete": complete,
            "endpoint_port": endpoint_port,
            "attachment": attachment,
        }

    def _persist(self, result: PathResultV1) -> None:
        payload = result.to_dict()
        request = result.request
        with self.state.connect() as connection:
            connection.execute(
                "INSERT INTO path_runs(run_id,status,endpoint,vlan,source,destination,mode,depth,max_nodes,confidence,started_at,finished_at,summary,request_json,result_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    result.run_id, result.status, request.endpoint, request.vlan, request.source,
                    request.destination, request.mode, request.depth, request.max_nodes, result.confidence,
                    result.started_at, result.finished_at, result.summary,
                    json.dumps(request.to_dict(), sort_keys=True), json.dumps(payload, sort_keys=True),
                ),
            )
            for hop in result.hops:
                connection.execute(
                    "INSERT INTO path_hops(run_id,sequence,device_id,device_name,management_ip,ingress_interface,egress_interface,layer,vlan_state,forwarding_state,confidence,evidence_observed_at,evidence_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        result.run_id, hop.sequence, hop.device_id, hop.device_name, hop.management_ip,
                        hop.ingress_interface, hop.egress_interface, hop.layer, hop.vlan_state,
                        hop.forwarding_state, hop.confidence, hop.evidence_observed_at,
                        json.dumps(hop.evidence, sort_keys=True),
                    ),
                )
            for finding in result.findings:
                connection.execute(
                    "INSERT INTO path_findings(run_id,severity,code,message,device_id,interface,confidence,evidence_observed_at,evidence_json) VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        result.run_id, finding.severity, finding.code, finding.message,
                        finding.device_id, finding.interface, finding.confidence,
                        finding.evidence_observed_at, json.dumps(finding.evidence, sort_keys=True),
                    ),
                )

    def inspect(self, request: PathRequestV1, options: Any) -> PathResultV1:
        started = int(time.time())
        run_id = "path-" + uuid.uuid4().hex
        findings: list[PathFindingV1] = []
        devices, aliases = self._devices()
        graph, topology_at = self._topology(aliases)
        source_name = request.source or str(self.app.config.public.get("core_switch_ip") or self.app.config.public.get("core_switch") or "")
        source = self._resolve_switch(source_name, aliases)
        cached_edge, cached_endpoint_port, cached_attachment = self._endpoint_attachment(
            request.endpoint, aliases, request.vlan
        )
        endpoint_port = cached_endpoint_port
        attachment = cached_attachment
        destination = self._resolve_switch(request.destination, aliases) if request.destination else cached_edge
        if not source:
            findings.append(PathFindingV1("error", "SOURCE_UNRESOLVED", "The path source switch could not be resolved.", confidence=100))
        nodes: list[str] = []
        edges: list[GraphEdge] = []
        live_probes: dict[str, dict[str, Any]] = {}
        live_path = False
        live_walk_used = False
        visited = 0
        budget_hit = False
        if source and _mac(request.endpoint) and not request.destination and request.mode in {"live", "hybrid"}:
            walked = self._live_mac_walk(
                source, request.endpoint, request.vlan, request.depth, request.max_nodes,
                devices, aliases, options,
            )
            findings.extend(walked["findings"])
            live_probes = walked["probes"]
            if walked["complete"]:
                nodes = walked["nodes"]
                edges = walked["edges"]
                endpoint_port = walked["endpoint_port"]
                attachment = walked["attachment"]
                destination = nodes[-1]
                live_path = True
                live_walk_used = True
                selected = live_probes.get(destination, {}).get("selected") or {}
                if hasattr(self.state, "record_mac_observation"):
                    try:
                        self.state.record_mac_observation(
                            request.endpoint,
                            str(devices[destination].get("ip") or destination),
                            str(devices[destination].get("hostname") or destination),
                            endpoint_port,
                            str(selected.get("vlan") or request.vlan),
                            str(selected.get("entry_type") or ""),
                            "path-live-fdb-walk",
                        )
                    except Exception:
                        pass
            elif walked["nodes"] and (request.mode == "live" or len(walked["nodes"]) > 1):
                nodes = walked["nodes"]
                edges = walked["edges"]
                destination = nodes[-1]
                live_walk_used = True
                last_probe = live_probes.get(destination, {})
                endpoint_port = ""
                attachment = {
                    "partial_live_walk": True,
                    "switch_ip": devices[destination].get("ip") or destination,
                    "switch_name": devices[destination].get("hostname") or destination,
                    "last_seen": int(last_probe.get("observed_at") or started),
                    "confidence": 85,
                    "source": "live-fdb-neighbor-walk",
                }

        # The hop-by-hop walk follows one branch and stops where a forwarding
        # table names no next hop, which leaves the endpoint unlocated even
        # though other switches can see it. An exhaustive search settles it.
        if (
            not live_path
            and _mac(request.endpoint)
            and request.mode in {"live", "hybrid"}
            and hasattr(self.app, "locate_endpoint_live")
        ):
            try:
                located = dict(self.app.locate_endpoint_live(request.endpoint, request.vlan, options))
            except Exception as exc:
                located = {}
                findings.append(PathFindingV1(
                    "warning", "ENDPOINT_SEARCH_FAILED", str(exc), confidence=100,
                ))
            best = (located.get("attached") or [None])[0]
            if best:
                resolved = aliases.get(_key(best.get("switch_ip"))) or aliases.get(_key(best.get("switch_name")))
                if resolved:
                    previous = destination
                    destination = resolved
                    endpoint_port = str(best.get("port") or "")
                    nodes, edges = [], []
                    attachment = {
                        "switch_ip": best.get("switch_ip"), "switch_name": best.get("switch_name"),
                        "switch_port": endpoint_port, "vlan": best.get("vlan") or str(request.vlan),
                        "last_seen": started, "confidence": 92, "source": "live-switch-search",
                        "searched_switches": located.get("searched") or 0,
                    }
                    live_walk_used = False
                    findings.append(PathFindingV1(
                        "warning", "ENDPOINT_RELOCATED_BY_SEARCH",
                        f"The forwarding-table walk stopped before the endpoint; a search of "
                        f"{located.get('searched') or 0} switches found it on "
                        f"{best.get('switch_name')} port {endpoint_port}.",
                        device_id=resolved, interface=endpoint_port, confidence=92,
                        evidence_observed_at=started, evidence=attachment,
                    ))
                    if previous and previous != resolved:
                        findings.append(PathFindingV1(
                            "warning", "CACHED_ATTACHMENT_SUPERSEDED",
                            f"Cached evidence placed the endpoint on {previous}; the live search did not find it there.",
                            device_id=previous, confidence=90,
                        ))
            elif located.get("transit"):
                findings.append(PathFindingV1(
                    "warning", "ENDPOINT_ONLY_SEEN_IN_TRANSIT",
                    f"The endpoint was reported by {len(located['transit'])} switch(es), but only on uplink ports, "
                    "so its access switch is outside inventory or unreachable.",
                    confidence=85, evidence={"transit": located["transit"][:10]},
                ))

        if not live_walk_used and not nodes and source and destination:
            nodes, edges, visited, budget_hit = self._bfs(graph, source, destination, request.depth, request.max_nodes)
            if not nodes:
                findings.append(PathFindingV1(
                    "error", "TOPOLOGY_PATH_UNKNOWN",
                    "Cached topology does not contain a bounded path between the selected switches.",
                    device_id=source, confidence=85,
                    evidence={"source": source, "destination": destination, "visited_nodes": visited},
                ))
        if not live_path and not destination:
            if attachment.get("vlan_mismatch"):
                observed = ", ".join(str(item) for item in attachment.get("observed_vlans") or []) or "another VLAN"
                findings.append(PathFindingV1(
                    "error", "CACHED_ENDPOINT_VLAN_MISMATCH",
                    f"Cached endpoint evidence is for VLAN(s) {observed}, not requested VLAN {request.vlan}; it was not used as a path edge.",
                    confidence=95, evidence=attachment,
                ))
            else:
                findings.append(PathFindingV1(
                    "error", "ENDPOINT_LOCATION_UNKNOWN",
                    "No current switch attachment could be resolved for the endpoint.",
                    confidence=90, evidence=attachment,
                ))
        elif not live_path and attachment.get("ambiguous"):
            findings.append(PathFindingV1(
                "warning", "AMBIGUOUS_ENDPOINT_LOCATION",
                "The endpoint has multiple current attachment candidates; the newest candidate was selected.",
                device_id=destination, interface=endpoint_port, confidence=70, evidence=attachment,
            ))
        if budget_hit:
            findings.append(PathFindingV1("warning", "NODE_BUDGET_REACHED", "Path planning reached the maximum node budget.", confidence=100, evidence={"max_nodes": request.max_nodes}))
        stale_seconds = max(60, int(self.app.config.public.get("path_evidence_stale_seconds") or 900))
        # Deliberately the same budget as everything else. Spanning tree
        # decides whether a port forwards *now*, and a link that flapped a
        # minute ago invalidates it, so an older reading must never be used to
        # call a path blocked. Irrelevant readings are filtered below instead.
        topology_stale_seconds = stale_seconds
        if not live_walk_used and topology_at and started - topology_at > stale_seconds:
            findings.append(PathFindingV1(
                "warning", "STALE_TOPOLOGY", "The cached topology is older than the configured freshness limit.",
                confidence=100, evidence_observed_at=topology_at,
                evidence={"age_seconds": started - topology_at, "freshness_limit_seconds": stale_seconds},
            ))
        elif not live_walk_used and graph and not topology_at:
            findings.append(PathFindingV1(
                "warning", "TOPOLOGY_AGE_UNKNOWN",
                "Cached topology has no trustworthy observation timestamp.", confidence=100,
            ))
        elif not live_walk_used and topology_at > started + 60:
            findings.append(PathFindingV1(
                "warning", "FUTURE_TOPOLOGY_TIMESTAMP",
                "Cached topology timestamp is later than the current clock.", confidence=100,
                evidence_observed_at=topology_at,
            ))
        attachment_stamp = int(attachment.get("last_seen") or attachment.get("updated_at") or 0)
        if not live_walk_used and attachment_stamp and started - attachment_stamp > stale_seconds:
            findings.append(PathFindingV1(
                "warning", "STALE_ENDPOINT_ATTACHMENT",
                "The selected endpoint attachment is older than the configured freshness limit.",
                device_id=destination, interface=endpoint_port, confidence=100,
                evidence_observed_at=attachment_stamp,
                evidence={"age_seconds": started - attachment_stamp, "freshness_limit_seconds": stale_seconds},
            ))
        elif not live_walk_used and attachment_stamp > started + 60:
            findings.append(PathFindingV1(
                "warning", "FUTURE_ENDPOINT_TIMESTAMP",
                "Endpoint attachment timestamp is later than the current clock.",
                device_id=destination, interface=endpoint_port, confidence=100,
                evidence_observed_at=attachment_stamp,
            ))

        hops: list[PathHopV1] = []
        live_failures = 0
        unknown_forwarding = 0
        for index, identity in enumerate(nodes):
            device = devices[identity]
            previous_edge = edges[index - 1] if index > 0 else None
            next_edge = edges[index] if index < len(edges) else None
            # The stored graph is core-to-edge. Interfaces are displayed in the
            # packet direction requested by the operator: endpoint-to-core.
            ingress = next_edge.source_port if next_edge else endpoint_port
            egress = previous_edge.destination_port if previous_edge else ""
            vlan_state = "unknown"
            forwarding = "unknown"
            confidence = 88 if live_walk_used else (65 if topology_at else 45)
            evidence: dict[str, Any] = {
                "topology_source": "live-fdb-lldp-cdp" if live_walk_used else "neighbors",
                "topology_observed_at": started if live_walk_used else (topology_at or None),
                "endpoint_attachment": attachment if index == len(nodes) - 1 else {},
            }
            if identity in live_probes:
                evidence["forwarding_table"] = {
                    key: value for key, value in live_probes[identity].items()
                    if key not in {"errors"}
                }
            observed_at = int(live_probes.get(identity, {}).get("observed_at") or 0) or topology_at or None
            layer = "L2"
            inspected: Mapping[str, Any] = {}
            forwarding_probe = live_probes.get(identity, {})
            skip_live_validation = bool(
                live_walk_used
                and forwarding_probe.get("error")
                and not forwarding_probe.get("port")
            )
            if request.mode in {"live", "hybrid"} and skip_live_validation:
                live_failures += 1
                unknown_forwarding += 1
                evidence["vlan_inspection"] = {
                    "skipped": True,
                    "reason": "prior forwarding-table transport failure",
                }
            if request.mode in {"live", "hybrid"} and not skip_live_validation:
                try:
                    inspected = self.app.inspect_vlan_node(device, request.vlan, "propagation", options)
                    observed_at = int(inspected.get("observed_at") or started)
                    if observed_at > int(time.time()) + 60:
                        findings.append(PathFindingV1(
                            "warning", "FUTURE_LIVE_TIMESTAMP",
                            "Live inspection timestamp is later than the current clock.",
                            device_id=identity, confidence=100, evidence_observed_at=observed_at,
                        ))
                    evidence["vlan_inspection"] = {
                        key: value for key, value in inspected.items()
                        if key not in {"raw_excerpt", "neighbors", "links", "trunks"}
                    }
                    if inspected.get("defined") is False:
                        vlan_state = "absent"
                        forwarding = "blocked"
                        findings.append(PathFindingV1(
                            "critical", "VLAN_NOT_DEFINED", f"VLAN {request.vlan} is not defined on this switch.",
                            device_id=identity, confidence=98, evidence_observed_at=observed_at,
                        ))
                    elif inspected.get("defined") is True:
                        vlan_state = "defined"
                        confidence = 90
                    if inspected.get("error"):
                        live_failures += 1
                        findings.append(PathFindingV1(
                            "warning", "LIVE_INSPECTION_FAILED", str(inspected.get("error")),
                            device_id=identity, confidence=100, evidence_observed_at=observed_at,
                        ))
                    switch_ports: list[tuple[str, str]] = []
                    if previous_edge and previous_edge.destination_port:
                        switch_ports.append((previous_edge.destination_port, "toward core"))
                    if next_edge and next_edge.source_port:
                        switch_ports.append((next_edge.source_port, "toward endpoint"))
                    validated_links = 0
                    for switch_port, direction in switch_ports:
                        trunk = self._find_link_on_port(inspected, switch_port)
                        if trunk and trunk.get("carries_vlan") is False:
                            forwarding = "blocked"
                            findings.append(PathFindingV1(
                                "critical", "VLAN_MISSING_ON_TRUNK",
                                f"VLAN {request.vlan} is not carried on the switch link {direction}.",
                                device_id=identity, interface=str(trunk.get("port") or switch_port), confidence=98,
                                evidence_observed_at=observed_at,
                            ))
                        elif trunk and trunk.get("carries_vlan") is True:
                            validated_links += 1
                            confidence = max(confidence, 94)
                        else:
                            unknown_forwarding += 1
                            findings.append(PathFindingV1(
                                "warning", "TRUNK_EVIDENCE_UNKNOWN",
                                f"The {direction} interface could not be correlated with parsed VLAN trunk evidence.",
                                device_id=identity, interface=switch_port, confidence=70,
                                evidence_observed_at=observed_at,
                            ))
                    if switch_ports and hasattr(self.app, "inspect_spanning_tree"):
                        # Read spanning tree for the interfaces this path uses.
                        # Trunk membership proves the VLAN is allowed on a link;
                        # only STP proves the link is the one actually forwarding.
                        try:
                            stp = dict(self.app.inspect_spanning_tree(
                                device, options, vlan=request.vlan,
                                interfaces=[port for port, _ in switch_ports],
                            ))
                            evidence["spanning_tree"] = {
                                key: value for key, value in stp.items() if key != "ports"
                            }
                            by_port = {
                                _interface(row.get("port")): row
                                for row in stp.get("ports") or []
                            }
                            for switch_port, direction in switch_ports:
                                row = by_port.get(_interface(switch_port))
                                if not row:
                                    continue
                                if row.get("state") in {"blocking", "disabled"}:
                                    forwarding = "blocked"
                                    findings.append(PathFindingV1(
                                        "critical", "STP_BLOCKING",
                                        f"Spanning tree is {row.get('state')} on the interface {direction}, "
                                        f"so this link does not forward VLAN {request.vlan}.",
                                        device_id=identity, interface=str(row.get("port") or switch_port),
                                        confidence=97, evidence_observed_at=int(stp.get("observed_at") or observed_at),
                                        evidence={key: row.get(key) for key in ("port", "state", "role", "edge")},
                                    ))
                        except Exception as exc:
                            findings.append(PathFindingV1(
                                "warning", "STP_INSPECTION_FAILED", str(exc),
                                device_id=identity, confidence=100,
                            ))
                    if switch_ports and forwarding != "blocked" and validated_links == len(switch_ports):
                        forwarding = "forwarding"
                    elif not switch_ports and forwarding != "blocked":
                        forwarding = "edge-learned" if endpoint_port else "unknown"
                        if not endpoint_port:
                            unknown_forwarding += 1
                except Exception as exc:
                    live_failures += 1
                    findings.append(PathFindingV1(
                        "warning", "LIVE_INSPECTION_FAILED", str(exc), device_id=identity, confidence=100
                    ))

            if index == 0 and request.mode in {"live", "hybrid"} and hasattr(self.app, "inspect_path_layer3"):
                try:
                    layer3 = dict(self.app.inspect_path_layer3(device, request.vlan, options))
                    evidence["layer3_termination"] = layer3
                    l3_stamp = int(layer3.get("observed_at") or observed_at or started)
                    l3_state = str(layer3.get("state") or "unknown").lower()
                    if layer3.get("parsed") and l3_state == "up":
                        layer = "L2/L3"
                        egress = str(layer3.get("interface") or f"Vlan{request.vlan}")
                        confidence = max(confidence, 94)
                    elif layer3.get("parsed") and l3_state in {"down", "administratively-down"}:
                        layer = "L2/L3"
                        forwarding = "blocked"
                        findings.append(PathFindingV1(
                            "critical", "SVI_DOWN",
                            f"The Layer 3 interface for VLAN {request.vlan} is {l3_state} on the core switch.",
                            device_id=identity, interface=str(layer3.get("interface") or f"Vlan{request.vlan}"),
                            confidence=98, evidence_observed_at=l3_stamp, evidence=layer3,
                        ))
                    else:
                        unknown_forwarding += 1
                        findings.append(PathFindingV1(
                            "warning", "L3_TERMINATION_UNKNOWN",
                            f"The Layer 2 path reaches the core, but VLAN {request.vlan} Layer 3 termination could not be confirmed.",
                            device_id=identity, confidence=75, evidence_observed_at=l3_stamp, evidence=layer3,
                        ))
                except Exception as exc:
                    unknown_forwarding += 1
                    findings.append(PathFindingV1(
                        "warning", "L3_INSPECTION_FAILED", str(exc), device_id=identity, confidence=100,
                    ))

            # Produce the evidence before reading it back. Without this the
            # SVI, LAG, VRF, route and ARP gates below have nothing to judge.
            if request.mode in {"live", "hybrid"} and hasattr(self.app, "collect_path_capabilities"):
                try:
                    collected = dict(self.app.collect_path_capabilities(
                        device, request.vlan, request.endpoint,
                        [value for value in (ingress, egress) if value], options,
                    ))
                    evidence["capability_collection"] = collected.get("recorded") or {}
                except Exception as exc:
                    findings.append(PathFindingV1(
                        "warning", "CAPABILITY_COLLECTION_FAILED", str(exc),
                        device_id=identity, confidence=100,
                    ))

            capabilities = self._capabilities(device)
            evidence["capabilities"] = {
                key: {"state": value.get("state"), "facts": value.get("facts"), "observed_at": value.get("observed_at")}
                for key, value in capabilities.items()
            }
            if layer == "L2" and any(key in capabilities for key in ("svi", "vrf", "routes", "arp_nd")):
                layer = "L2/L3"
            now_ts = int(time.time())
            for capability, row in capabilities.items():
                facts = row.get("facts") or {}
                stamp = int(row.get("observed_at") or 0)

                # Work out relevance first. Warning that evidence is stale when
                # it describes an interface this path never touches is noise,
                # and it buries the findings that do matter.
                fact_interface = _interface(facts.get("interface"))
                path_interfaces = {_interface(ingress), _interface(egress)} - {""}
                fact_vlan = str(facts.get("vlan") or "")
                fact_target = _ip(facts.get("destination") or facts.get("target") or facts.get("endpoint"))
                endpoint_ip = _ip(request.endpoint)
                interface_relevant = bool(fact_interface and fact_interface in path_interfaces)
                vlan_relevant = bool(fact_vlan and fact_vlan == str(request.vlan))
                target_relevant = bool(fact_target and endpoint_ip and fact_target == endpoint_ip)
                judged_live = capability == "stp" and "spanning_tree" in evidence
                relevant = not judged_live and (
                    interface_relevant if capability in {"stp", "lag"}
                    else vlan_relevant if capability in {"svi", "vrf"}
                    else target_relevant if capability in {"routes", "arp_nd"}
                    else True
                )

                budget = topology_stale_seconds if capability in {"stp", "lag"} else stale_seconds
                age = max(0, now_ts - stamp) if stamp else 0
                stale = bool(stamp and age > budget)
                if stale and relevant:
                    findings.append(PathFindingV1(
                        "warning", "STALE_CAPABILITY_EVIDENCE",
                        f"{capability} evidence is {age // 60} minute(s) old, past the {budget // 60} minute limit.",
                        device_id=identity, confidence=100, evidence_observed_at=stamp,
                        evidence={"age_seconds": age, "freshness_limit_seconds": budget},
                    ))
                elif stamp > now_ts + 60:
                    # Compared against the wall clock, not the start of this run:
                    # evidence this run collected is newer than its own start.
                    findings.append(PathFindingV1(
                        "warning", "FUTURE_CAPABILITY_TIMESTAMP",
                        f"{capability} evidence timestamp is {stamp - now_ts} second(s) ahead of this host's clock.",
                        device_id=identity, confidence=100, evidence_observed_at=stamp,
                    ))
                    stale = True
                state = str(row.get("state") or "unknown").lower()
                if state in {"unknown", "error"}:
                    findings.append(PathFindingV1(
                        "warning", "CAPABILITY_EVIDENCE_UNAVAILABLE",
                        f"{capability} evidence is {state} and cannot establish forwarding state.",
                        device_id=identity, confidence=int(row.get("confidence") or 0),
                        evidence_observed_at=stamp or None,
                    ))
                    continue
                if state != "supported" or stale:
                    continue
                block_code = ""
                message = ""
                if judged_live or not relevant:
                    # Already judged against a live spanning-tree read, or the
                    # evidence does not describe anything on this path.
                    continue
                if capability == "stp" and str(facts.get("state") or "").lower() in {"blocking", "discarding", "disabled"}:
                    block_code, message = "STP_BLOCKING", "Spanning Tree is not forwarding on the selected path interface."
                elif capability == "lag" and facts.get("operational") is False:
                    block_code, message = "LAG_DOWN", "The selected link aggregation group is down."
                elif capability == "svi" and str(facts.get("state") or "").lower() in {"down", "administratively-down"}:
                    block_code, message = "SVI_DOWN", "The VLAN interface is not operational."
                elif capability == "vrf" and facts.get("matches") is False:
                    block_code, message = "VRF_MISMATCH", "The observed VRF does not match the requested forwarding context."
                elif capability == "routes" and facts.get("route_present") is False:
                    block_code, message = "ROUTE_MISSING", "No matching route was observed for the Layer 3 destination."
                elif capability == "arp_nd" and facts.get("neighbor_present") is False:
                    block_code, message = "NEIGHBOR_RESOLUTION_MISSING", "ARP/ND resolution is missing for the next hop or endpoint."
                if block_code:
                    forwarding = "blocked"
                    findings.append(PathFindingV1(
                        "critical", block_code, message, device_id=identity,
                        interface=str(facts.get("interface") or egress), confidence=int(row.get("confidence") or 80),
                        evidence_observed_at=stamp or None, evidence=facts,
                    ))
                if capability == "interface_policy" and interface_relevant and facts and not facts.get("semantics_supported", False):
                    findings.append(PathFindingV1(
                        "warning", "POLICY_SEMANTICS_UNKNOWN",
                        "An interface policy is attached, but this driver cannot prove whether it blocks the flow.",
                        device_id=identity, interface=str(facts.get("interface") or egress),
                        confidence=int(row.get("confidence") or 70), evidence_observed_at=stamp or None,
                        evidence={"references": facts.get("references", [])},
                    ))
            evidence_age = max(0, started - observed_at) if observed_at else None
            hops.append(PathHopV1(
                sequence=index + 1,
                device_id=identity,
                device_name=str(device.get("hostname") or identity),
                management_ip=str(device.get("ip") or ""),
                ingress_interface=ingress,
                egress_interface=egress,
                layer=layer,
                vlan_state=vlan_state,
                forwarding_state=forwarding,
                confidence=confidence,
                evidence_observed_at=observed_at,
                evidence_age_seconds=evidence_age,
                evidence=evidence,
            ))

        hops = [replace(hop, sequence=index) for index, hop in enumerate(reversed(hops), 1)]
        blocking = [item for item in findings if item.severity == "critical"]
        if blocking:
            status = "BLOCKED"
        elif not hops:
            status = "UNKNOWN"
        elif live_failures or unknown_forwarding or any(item.severity in {"warning", "error"} for item in findings):
            status = "PARTIAL"
        elif request.mode == "cached":
            status = "PARTIAL"
        else:
            status = "COMPLETE"
        if hops:
            confidence = int(sum(hop.confidence for hop in hops) / len(hops))
            if status in {"PARTIAL", "UNKNOWN"}:
                confidence = min(confidence, 74)
        else:
            confidence = 20 if findings else 0
        finished = int(time.time())
        summary = {
            "COMPLETE": f"Validated {len(hops)} device-to-core switch hops without a confirmed blocker.",
            "BLOCKED": f"Found {len(blocking)} confirmed forwarding blocker(s) across {len(hops)} device-to-core switch hops.",
            "PARTIAL": f"Built a {len(hops)}-switch device-to-core path, but some evidence is stale, missing, or unparsed.",
            "UNKNOWN": "A bounded device-to-core path could not be established from available evidence.",
        }[status]
        result = PathResultV1(run_id, request, status, confidence, started, finished, tuple(hops), tuple(findings), summary)
        self._persist(result)
        return result

    @staticmethod
    def _with_run_references(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        output: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            run_id = str(item.get("run_id") or "")
            token = run_id[5:] if run_id.startswith("path-") else run_id
            item["run_ref"] = ("path-" if run_id.startswith("path-") else "") + token[:12]
            output.append(item)
        return output

    @staticmethod
    def _endpoint_clause(endpoint: str) -> tuple[str, tuple[Any, ...]]:
        clean = _mac(endpoint)
        if clean:
            expression = "lower(replace(replace(replace(replace(COALESCE(endpoint,''),':',''),'.',''),'-',''),' ',''))"
            return f"{expression}=?", (clean,)
        return "lower(endpoint)=lower(?)", (endpoint,)

    def history(self, endpoint: str = "", vlan: int = 0, limit: int = 100) -> list[dict[str, Any]]:
        clauses: list[str] = []
        parameters: list[Any] = []
        if endpoint:
            clause, values = self._endpoint_clause(endpoint)
            clauses.append(clause)
            parameters.extend(values)
        if vlan:
            clauses.append("vlan=?")
            parameters.append(int(vlan))
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        parameters.append(max(1, min(limit, 1000)))
        rows = self.state.rows(
            "SELECT run_id,status,endpoint,vlan,source,destination,mode,depth,confidence,started_at,finished_at,summary "
            f"FROM path_runs{where} ORDER BY started_at DESC,run_id DESC LIMIT ?",
            tuple(parameters),
        )
        return self._with_run_references(rows)

    def show(self, reference: str, vlan: int = 0) -> dict[str, Any] | None:
        value = str(reference or "").strip()
        row = self.state.one("SELECT run_id,result_json FROM path_runs WHERE run_id=?", (value,))
        if not row and value.lower() in {"last", "latest"}:
            clause = " WHERE vlan=?" if vlan else ""
            parameters: tuple[Any, ...] = (int(vlan),) if vlan else ()
            row = self.state.one(
                f"SELECT run_id,result_json FROM path_runs{clause} ORDER BY started_at DESC,run_id DESC LIMIT 1",
                parameters,
            )
        if not row and value.startswith("path-"):
            if not re.fullmatch(r"path-[0-9a-fA-F]{8,32}", value):
                raise ValueError("Path run prefixes must include at least 8 hexadecimal characters after 'path-'.")
            candidates = self.state.rows(
                "SELECT run_id,result_json FROM path_runs WHERE run_id LIKE ? ORDER BY started_at DESC,run_id DESC LIMIT 3",
                (value + "%",),
            )
            if len(candidates) > 1:
                labels = ", ".join(str(item.get("run_id")) for item in candidates)
                raise ValueError(f"Path run prefix is ambiguous: {labels}")
            row = candidates[0] if candidates else None
        if not row and value:
            endpoint_clause, endpoint_values = self._endpoint_clause(value)
            clauses = [endpoint_clause]
            parameters = list(endpoint_values)
            if vlan:
                clauses.append("vlan=?")
                parameters.append(int(vlan))
            row = self.state.one(
                "SELECT run_id,result_json FROM path_runs WHERE " + " AND ".join(clauses)
                + " ORDER BY started_at DESC,run_id DESC LIMIT 1",
                tuple(parameters),
            )
        if not row:
            return None
        return self._compose_result(row)

    def _compose_result(self, run: Mapping[str, Any]) -> dict[str, Any]:
        """Rebuild a run from the normalised tables.

        Hops and findings were written on every run and read on none: every
        lookup went through the run's JSON blob, so the two representations
        could drift with nothing to notice. The tables are now the source of
        truth for reads, and the blob is only a fallback for rows written
        before this change.
        """
        run_id = str(run.get("run_id") or "")
        hop_rows = self.state.rows(
            "SELECT sequence,device_id,device_name,management_ip,ingress_interface,egress_interface,"
            "layer,vlan_state,forwarding_state,confidence,evidence_observed_at,evidence_json "
            "FROM path_hops WHERE run_id=? ORDER BY sequence",
            (run_id,),
        )
        finding_rows = self.state.rows(
            "SELECT severity,code,message,device_id,interface,confidence,evidence_observed_at,evidence_json "
            "FROM path_findings WHERE run_id=? ORDER BY id",
            (run_id,),
        )
        stored = run.get("result_json")
        if not hop_rows and not finding_rows and stored:
            # A run recorded before the tables were authoritative.
            return json.loads(str(stored or "{}"))

        detail = self.state.one(
            "SELECT run_id,status,confidence,started_at,finished_at,summary,request_json "
            "FROM path_runs WHERE run_id=?",
            (run_id,),
        ) or dict(run)
        started = int(detail.get("started_at") or 0)
        try:
            request = json.loads(str(detail.get("request_json") or "{}"))
        except json.JSONDecodeError:
            request = {}
        request["requested_at_iso"] = _rfc3339(request.get("requested_at"))

        def decode(value: Any) -> dict[str, Any]:
            try:
                return json.loads(str(value or "{}"))
            except json.JSONDecodeError:
                return {}

        hops = []
        for row in hop_rows:
            observed = row.get("evidence_observed_at")
            hops.append({
                "sequence": int(row.get("sequence") or 0),
                "device_id": row.get("device_id") or "",
                "device_name": row.get("device_name") or "",
                "management_ip": row.get("management_ip") or "",
                "ingress_interface": row.get("ingress_interface") or "",
                "egress_interface": row.get("egress_interface") or "",
                "layer": row.get("layer") or "L2",
                "vlan_state": row.get("vlan_state") or "unknown",
                "forwarding_state": row.get("forwarding_state") or "unknown",
                "confidence": int(row.get("confidence") or 0),
                "evidence_observed_at": observed,
                # Not a column: derived from when the run started, exactly as
                # the live path computes it.
                "evidence_age_seconds": max(0, started - int(observed)) if observed else None,
                "evidence": decode(row.get("evidence_json")),
                "schema_version": SCHEMA_VERSION,
                "evidence_observed_at_iso": _rfc3339(observed),
            })
        findings = []
        for row in finding_rows:
            observed = row.get("evidence_observed_at")
            findings.append({
                "severity": row.get("severity") or "",
                "code": row.get("code") or "",
                "message": row.get("message") or "",
                "device_id": row.get("device_id") or "",
                "interface": row.get("interface") or "",
                "confidence": int(row.get("confidence") or 0),
                "evidence_observed_at": observed,
                "evidence": decode(row.get("evidence_json")),
                "schema_version": SCHEMA_VERSION,
                "evidence_observed_at_iso": _rfc3339(observed),
            })
        return {
            "run_id": run_id,
            "request": request,
            "status": detail.get("status") or "UNKNOWN",
            "confidence": int(detail.get("confidence") or 0),
            "started_at": started,
            "finished_at": int(detail.get("finished_at") or 0),
            "hops": hops,
            "findings": findings,
            "summary": detail.get("summary") or "",
            "schema_version": SCHEMA_VERSION,
            "started_at_iso": _rfc3339(started),
            "finished_at_iso": _rfc3339(detail.get("finished_at")),
        }
