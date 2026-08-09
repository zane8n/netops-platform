"""Bounded Layer 2/Layer 3 path inspection with chronological evidence."""

from __future__ import annotations

import ipaddress
import json
import re
import time
import uuid
from collections import deque
from dataclasses import dataclass
from typing import Any, Mapping

from netops_platform.contracts import (
    PathFindingV1,
    PathHopV1,
    PathRequestV1,
    PathResultV1,
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

    def _endpoint_attachment(self, endpoint: str, aliases: Mapping[str, str]) -> tuple[str, str, dict[str, Any]]:
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
                resolved.append((identity, evidence))
        if resolved:
            identity, evidence = resolved[0]
            locations = {
                (item_identity, str(item.get("switch_port") or ""))
                for item_identity, item in resolved
            }
            if len(locations) > 1:
                evidence["ambiguous"] = True
                evidence["alternatives"] = [
                    {"device_id": item_identity, "switch_port": item.get("switch_port"), "last_seen": item.get("last_seen")}
                    for item_identity, item in resolved[:8]
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
        edge, endpoint_port, attachment = self._endpoint_attachment(request.endpoint, aliases)
        destination = self._resolve_switch(request.destination, aliases) if request.destination else edge
        if not source:
            findings.append(PathFindingV1("error", "SOURCE_UNRESOLVED", "The path source switch could not be resolved.", confidence=100))
        if not destination:
            findings.append(PathFindingV1("error", "ENDPOINT_LOCATION_UNKNOWN", "No current switch attachment could be resolved for the endpoint.", confidence=90, evidence=attachment))
        elif attachment.get("ambiguous"):
            findings.append(PathFindingV1(
                "warning", "AMBIGUOUS_ENDPOINT_LOCATION",
                "The endpoint has multiple current attachment candidates; the newest candidate was selected.",
                device_id=destination, interface=endpoint_port, confidence=70, evidence=attachment,
            ))
        nodes: list[str] = []
        edges: list[GraphEdge] = []
        visited = 0
        budget_hit = False
        if source and destination:
            nodes, edges, visited, budget_hit = self._bfs(graph, source, destination, request.depth, request.max_nodes)
            if not nodes:
                findings.append(PathFindingV1(
                    "error", "TOPOLOGY_PATH_UNKNOWN",
                    "Cached topology does not contain a bounded path between the selected switches.",
                    device_id=source, confidence=85,
                    evidence={"source": source, "destination": destination, "visited_nodes": visited},
                ))
        if budget_hit:
            findings.append(PathFindingV1("warning", "NODE_BUDGET_REACHED", "Path planning reached the maximum node budget.", confidence=100, evidence={"max_nodes": request.max_nodes}))
        stale_seconds = max(60, int(self.app.config.public.get("path_evidence_stale_seconds") or 900))
        if topology_at and started - topology_at > stale_seconds:
            findings.append(PathFindingV1(
                "warning", "STALE_TOPOLOGY", "The cached topology is older than the configured freshness limit.",
                confidence=100, evidence_observed_at=topology_at,
                evidence={"age_seconds": started - topology_at, "freshness_limit_seconds": stale_seconds},
            ))
        elif graph and not topology_at:
            findings.append(PathFindingV1(
                "warning", "TOPOLOGY_AGE_UNKNOWN",
                "Cached topology has no trustworthy observation timestamp.", confidence=100,
            ))
        elif topology_at > started + 60:
            findings.append(PathFindingV1(
                "warning", "FUTURE_TOPOLOGY_TIMESTAMP",
                "Cached topology timestamp is later than the current clock.", confidence=100,
                evidence_observed_at=topology_at,
            ))
        attachment_stamp = int(attachment.get("last_seen") or attachment.get("updated_at") or 0)
        if attachment_stamp and started - attachment_stamp > stale_seconds:
            findings.append(PathFindingV1(
                "warning", "STALE_ENDPOINT_ATTACHMENT",
                "The selected endpoint attachment is older than the configured freshness limit.",
                device_id=destination, interface=endpoint_port, confidence=100,
                evidence_observed_at=attachment_stamp,
                evidence={"age_seconds": started - attachment_stamp, "freshness_limit_seconds": stale_seconds},
            ))
        elif attachment_stamp > started + 60:
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
            ingress = previous_edge.destination_port if previous_edge else ""
            egress = next_edge.source_port if next_edge else endpoint_port
            vlan_state = "unknown"
            forwarding = "unknown"
            confidence = 65 if topology_at else 45
            evidence: dict[str, Any] = {
                "topology_source": "neighbors",
                "topology_observed_at": topology_at or None,
                "endpoint_attachment": attachment if index == len(nodes) - 1 else {},
            }
            observed_at = topology_at or None
            inspected: Mapping[str, Any] = {}
            if request.mode in {"live", "hybrid"}:
                try:
                    inspected = self.app.inspect_vlan_node(device, request.vlan, "propagation", options)
                    observed_at = int(inspected.get("observed_at") or started)
                    if observed_at > started + 60:
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
                    if next_edge and forwarding != "blocked":
                        trunk = self._find_trunk(inspected, devices[next_edge.destination], next_edge)
                        if trunk and trunk.get("carries_vlan") is False:
                            forwarding = "blocked"
                            findings.append(PathFindingV1(
                                "critical", "VLAN_MISSING_ON_TRUNK",
                                f"VLAN {request.vlan} is not carried toward the next switch.",
                                device_id=identity, interface=str(trunk.get("port") or egress), confidence=98,
                                evidence_observed_at=observed_at,
                            ))
                        elif trunk and trunk.get("carries_vlan") is True:
                            forwarding = "forwarding"
                            confidence = max(confidence, 94)
                        else:
                            unknown_forwarding += 1
                            findings.append(PathFindingV1(
                                "warning", "TRUNK_EVIDENCE_UNKNOWN",
                                "The next topology hop could not be correlated with a parsed trunk entry.",
                                device_id=identity, interface=egress, confidence=70,
                                evidence_observed_at=observed_at,
                            ))
                    elif not next_edge and forwarding != "blocked":
                        forwarding = "edge-learned" if endpoint_port else "unknown"
                        if not endpoint_port:
                            unknown_forwarding += 1
                except Exception as exc:
                    live_failures += 1
                    findings.append(PathFindingV1(
                        "warning", "LIVE_INSPECTION_FAILED", str(exc), device_id=identity, confidence=100
                    ))

            capabilities = self._capabilities(device)
            evidence["capabilities"] = {
                key: {"state": value.get("state"), "facts": value.get("facts"), "observed_at": value.get("observed_at")}
                for key, value in capabilities.items()
            }
            layer = "L3" if any(key in capabilities for key in ("svi", "vrf", "routes", "arp_nd")) else "L2"
            for capability, row in capabilities.items():
                facts = row.get("facts") or {}
                stamp = int(row.get("observed_at") or 0)
                stale = bool(stamp and started - stamp > stale_seconds)
                if stale:
                    findings.append(PathFindingV1(
                        "warning", "STALE_CAPABILITY_EVIDENCE", f"{capability} evidence is stale.",
                        device_id=identity, confidence=100, evidence_observed_at=stamp,
                    ))
                elif stamp > started + 60:
                    findings.append(PathFindingV1(
                        "warning", "FUTURE_CAPABILITY_TIMESTAMP",
                        f"{capability} evidence timestamp is later than the current clock.",
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
                fact_interface = _interface(facts.get("interface"))
                path_interfaces = {_interface(ingress), _interface(egress)} - {""}
                fact_vlan = str(facts.get("vlan") or "")
                fact_target = _ip(facts.get("destination") or facts.get("target") or facts.get("endpoint"))
                endpoint_ip = _ip(request.endpoint)
                interface_relevant = bool(fact_interface and fact_interface in path_interfaces)
                vlan_relevant = bool(fact_vlan and fact_vlan == str(request.vlan))
                target_relevant = bool(fact_target and endpoint_ip and fact_target == endpoint_ip)
                if capability in {"stp", "lag"} and not interface_relevant:
                    continue
                if capability in {"svi", "vrf"} and not vlan_relevant:
                    continue
                if capability in {"routes", "arp_nd"} and not target_relevant:
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
            "COMPLETE": f"Validated {len(hops)} switch hops without a confirmed blocker.",
            "BLOCKED": f"Found {len(blocking)} confirmed forwarding blocker(s) across {len(hops)} switch hops.",
            "PARTIAL": f"Built a {len(hops)}-switch path, but some evidence is stale, missing, or unparsed.",
            "UNKNOWN": "A bounded path could not be established from available evidence.",
        }[status]
        result = PathResultV1(run_id, request, status, confidence, started, finished, tuple(hops), tuple(findings), summary)
        self._persist(result)
        return result

    def history(self, endpoint: str = "", limit: int = 100) -> list[dict[str, Any]]:
        if endpoint:
            return self.state.rows(
                "SELECT run_id,status,endpoint,vlan,source,destination,mode,depth,confidence,started_at,finished_at,summary FROM path_runs WHERE endpoint=? ORDER BY started_at DESC,run_id DESC LIMIT ?",
                (endpoint, max(1, min(limit, 1000))),
            )
        return self.state.rows(
            "SELECT run_id,status,endpoint,vlan,source,destination,mode,depth,confidence,started_at,finished_at,summary FROM path_runs ORDER BY started_at DESC,run_id DESC LIMIT ?",
            (max(1, min(limit, 1000)),),
        )

    def show(self, run_id: str) -> dict[str, Any] | None:
        row = self.state.one("SELECT result_json FROM path_runs WHERE run_id=?", (run_id,))
        if not row:
            return None
        return json.loads(str(row.get("result_json") or "{}"))
