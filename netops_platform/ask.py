#!/usr/bin/env python3
"""Deterministic natural-language query workflows for Netrune."""

from __future__ import annotations

import contextlib
import json
import re
import shlex
import time
from difflib import SequenceMatcher
from typing import Any, Dict, List, Optional, Sequence, Tuple

from netops_platform.identity import ap_name_evidence, normalize_location_label, normalize_mac, reconcile_ap_rows


QUESTION_PATTERNS: List[Dict[str, Any]] = [
    {
        "intent": "ap_on_switch",
        "purpose": "Count or list the canonical APs attached to a described switch.",
        "examples": [
            "How many APs are on the building 9 switch at ZONE10?",
            "List APs connected to SW02 at engineering office",
            "Which access points are attached to the admin office switch?",
            "Show offline APs on SITEAZONE34SW01",
            "AP count for the B6 switch in ZONE10",
            "What APs sit on house 22 switch?",
            "Give me the APs hanging off site a access SW01",
            "Are any APs down on the ZONE34 switch?",
            "Show wireless units attached to the H19 Annex switch",
            "How many access points belong to Nzoro SW03?",
        ],
    },
    {
        "intent": "ap_inventory",
        "purpose": "Count, list, and filter canonical current AP inventory.",
        "examples": [
            "How many APs are offline?",
            "List online APs in ZONE10",
            "Show Cisco APs at camp admin",
            "Which Ruckus APs are down in DRA?",
            "APs in house 19",
            "Count access points at engineering office",
            "Give me every AP in ZONE34",
            "How many C9136 APs do we have?",
            "List reachable wireless units in building 6",
            "Which APs have unknown health?",
        ],
    },
    {
        "intent": "switch_inventory",
        "purpose": "Count, list, and filter current switches or network devices.",
        "examples": [
            "List switches at engineering office",
            "How many switches are in Nzoro?",
            "Which switches are offline in ZONE10?",
            "Show online devices at camp admin",
            "Switch count for house 22",
            "Give me all Cisco switches in ZONE34",
            "What network devices are at DRA?",
            "Are any switches down at building 9?",
            "List reachable switches in camp",
            "How many access switches do we know?",
        ],
    },
    {
        "intent": "entity_details",
        "purpose": "Return current identity, address, platform, aliases, and health.",
        "examples": [
            "What is the IP of site-a-core?",
            "Give me the MAC of ZONE34 switch",
            "Show details for SITEAZONE10BLDG9SW01",
            "What model is SITE-SQ21-AP161?",
            "Is admin office switch online?",
            "Tell me about SQ5",
            "What addresses are known for SITE-A-ZONE34-AP239?",
            "What is SITEAZONE34AP239 called now?",
            "When was this AP last seen?",
            "Show the platform and status of Nzoro SW02",
        ],
    },
    {
        "intent": "switch_summary",
        "purpose": "Summarize one switch with AP, neighbor, health, and memory counts.",
        "examples": [
            "Summarize the admin office switch",
            "Give me an overview of ZONE34 SW01",
            "What do we know about the building 9 switch at ZONE10?",
            "Show the memory summary for engineering office SW02",
            "Give me switch context for SITEACMPDRASW01",
            "What is attached around Nzoro SW03?",
        ],
    },
    {
        "intent": "ap_location",
        "purpose": "Resolve an AP's current or previous switch and port.",
        "examples": [
            "Where is SITE-SQ21-AP161 connected?",
            "Where was SITE-SQ21-AP161 connected before it went offline?",
            "Which switch has SITEAZONE34AP239?",
            "Show the attachment history of SITE-A-ZONE34-AP239",
            "Where did AP239 move from?",
            "Which port currently hosts SITEAZONE10AP172?",
            "Where was this AP last attached?",
            "What switch did SITE-A-House19-AP123 belong to?",
            "Show previous connections for the H19 Annex AP124",
            "Where is AP239 plugged in now?",
        ],
    },
    {
        "intent": "port_memory",
        "purpose": "Show current and historical switch-port occupancy.",
        "examples": [
            "What is connected to Gi1/0/2 on site-a-core?",
            "Who was on port 7 of ZONE34 switch?",
            "Show occupancy history for Gi1/0/1 on SITEAZONE10SW01",
            "Which device is attached to Te1/1/1 of core?",
            "What used to be connected on Gi1/0/24 at ZONE34?",
            "Show current occupant of interface Gi1/0/7 on site a access switch",
            "Has port Gi1/0/3 changed occupants?",
            "List the memory for port 12 of Nzoro SW02",
        ],
    },
    {
        "intent": "ip_memory",
        "purpose": "Show current and previous ownership of an IP.",
        "examples": [
            "Who owns 198.51.100.92?",
            "Which device used 192.0.2.67 before?",
            "Show history for IP 198.51.100.44",
            "What hostname previously had 203.0.113.10?",
            "Has 192.0.2.94 changed APs?",
            "What MACs have used 198.51.100.80?",
            "Tell me the owner timeline for 192.0.2.132",
            "Where did this IP appear before?",
        ],
    },
    {
        "intent": "mac_memory",
        "purpose": "Show identity and movement memory for a MAC address.",
        "examples": [
            "Where is 0200.0000.0025?",
            "Show history for MAC 02:00:00:00:00:25",
            "Which switch last saw 0200.0000.0025?",
            "What IP belongs to MAC 0200.0000.0025?",
            "Has this MAC moved?",
            "What names has 3c26e44ec380 used?",
            "Show the last port for MAC 0200.0000.0025",
            "Who previously owned this MAC?",
        ],
    },
    {
        "intent": "identity_history",
        "purpose": "Show hostname, IP, MAC, model, and attachment changes for an entity.",
        "examples": [
            "What was SITEAZONE34AP239 called before?",
            "Show rename history for SITE-A-ZONE34-AP239",
            "How has SITE-SQ21-AP161 changed?",
            "What IPs has site-a-core used?",
            "Show identity history for SITEACMPDRASW01",
            "Has the serial or model changed on ZONE34 SW01?",
            "What were the older names for this AP?",
            "Show previous versions of the building 9 switch record",
        ],
    },
    {
        "intent": "topology",
        "purpose": "Inspect cached neighbors and current switch relationships.",
        "examples": [
            "What is connected to ZONE34 switch?",
            "List neighbors of site-a-core",
            "Show downstream devices from SITEAZONE10SW01",
            "Which switches connect to core?",
            "Give me LLDP neighbors for Nzoro SW02",
            "What is upstream of the engineering office switch?",
            "Show links around the building 9 switch",
            "List CDP relationships at ZONE10",
        ],
    },
    {
        "intent": "topology_changes",
        "purpose": "Review new, removed, or changed topology links.",
        "examples": [
            "What topology changed today?",
            "Show recent link changes",
            "Which neighbors disappeared?",
            "List new downstream devices",
            "What changed around ZONE34?",
            "Show removed links at engineering office",
            "Were there any upstream changes?",
            "Give me the latest topology events",
        ],
    },
    {
        "intent": "health",
        "purpose": "Summarize current health, outages, staleness, and flapping.",
        "examples": [
            "Show AP health at camp admin",
            "Which switches are flapping?",
            "List stale devices",
            "What is offline in ZONE10?",
            "How many network devices are online in Nzoro?",
            "Show current outages",
            "Which APs have not been seen recently?",
            "Give me the health summary for ZONE34",
        ],
    },
    {
        "intent": "attention",
        "purpose": "List current health, topology, AP-move, and backup items needing review.",
        "examples": [
            "What needs attention?",
            "Show current warnings",
            "Are there any network problems?",
            "What should I review?",
            "Give me outstanding issues",
            "Show alerts for ZONE10",
            "What failed recently?",
            "List important changes",
        ],
    },
    {
        "intent": "ap_moves",
        "purpose": "Review AP switch or port movement history.",
        "examples": [
            "Which APs moved?",
            "Show recent AP moves",
            "Did any access points change switches?",
            "List AP port changes at ZONE10",
            "What APs moved in house 19?",
            "Show wireless attachment changes",
            "Which AP changed port most recently?",
            "Give me the AP movement timeline",
        ],
    },
    {
        "intent": "ap_aliases",
        "purpose": "Show canonical AP identities, aliases, duplicate observations, and addresses.",
        "examples": [
            "Show AP aliases",
            "Which AP records were merged?",
            "List duplicate AP names",
            "Are SITE-A-ZONE34-AP239 and SITEAZONE34AP239 the same AP?",
            "Show alternate names for SITEAZONE34AP239",
            "Which APs have multiple IPs?",
            "Explain AP identity for SITE-A-House19-AP123",
            "List canonical APs with more than one observation",
        ],
    },
    {
        "intent": "unjoined_aps",
        "purpose": "List WLC AP records that are not joined.",
        "examples": [
            "List unjoined APs",
            "Which APs are not joined to the controller?",
            "Show disconnected WLC access points",
            "How many APs are awaiting join?",
            "Give me nonjoined Cisco APs",
            "Are any controller APs unregistered?",
        ],
    },
    {
        "intent": "backup_history",
        "purpose": "Read backup status and changed-config history.",
        "examples": [
            "When was ZONE34 last backed up?",
            "Show failed backups",
            "List recent config backups",
            "Did site-a-core config change?",
            "Show backup history for engineering office",
            "Which devices have no successful backup?",
            "What was the latest backup result?",
            "How many configs changed recently?",
        ],
    },
    {
        "intent": "diagnostic_history",
        "purpose": "Read saved latency, speed, filtering, and interface results.",
        "examples": [
            "Show the latest latency results",
            "What was the last speed test?",
            "List failed filtering checks",
            "Show diagnostic history for ZONE34",
            "What packet loss was recorded recently?",
            "Give me recent interface utilization",
            "Were there suspicious DNS or TLS checks?",
            "Show the last ten diagnostics",
        ],
    },
    {
        "intent": "job_status",
        "purpose": "Read queued, running, completed, failed, or cancelled job history.",
        "examples": [
            "What jobs are running?",
            "Show failed jobs",
            "List recent operations",
            "Did the AP scan finish?",
            "What is pending?",
            "Show the latest inventory job",
            "How many jobs failed?",
            "Give me the last workflow result",
        ],
    },
]

QUESTION_PATTERNS.append({
    "intent": "command_plan",
    "purpose": "Plan, preview, clarify, and safely execute registered Netrune commands.",
    "examples": [
        "Run a fast health check for ZONE34",
        "Refresh the AP and topology inventory",
        "Ping 198.51.100.92 five times",
        "Test filtering for example.com",
        "Run show version on SITEAZONE34SW01",
        "Connect to admin-hill over SSH",
        "Back up the online switches in ZONE10",
        "Locate VLAN 120 on ZONE34",
        "Monitor Gi1/0/7 on ZONE34 once",
        "Import the legacy flat inventory",
        "Check SQLite integrity",
        "Preview changing Gi1/0/7 on ZONE34 to access VLAN 120",
    ],
})



class NaturalAskEngine:
    def __init__(self, app: Any):
        self.app = app

    def patterns_payload(self) -> Dict[str, Any]:
        return {
            "ok": True,
            "engine": "deterministic-command-center",
            "patterns": QUESTION_PATTERNS,
            "count": sum(len(item["examples"]) for item in QUESTION_PATTERNS),
            "notes": [
                "Retrieval questions query current SQLite state and relationship memory.",
                "Operational requests map only to registered commands with validated arguments and safety metadata.",
                "Ask plans commands by default; explicit execution is a separate guarded action.",
                "Use profile aliases for local names that cannot be inferred reliably.",
            ],
        }

    def aliases(self) -> List[Dict[str, Any]]:
        return self.app.state.rows("SELECT phrase,target,created_at,updated_at FROM ask_aliases ORDER BY phrase")

    def set_alias(self, phrase: str, target: str) -> Dict[str, Any]:
        phrase = re.sub(r"\s+", " ", str(phrase or "").strip())
        target = re.sub(r"\s+", " ", str(target or "").strip())
        if not phrase or not target:
            return {"ok": False, "error": "Alias requires both a phrase and a target."}
        ts = int(time.time())
        existing = self.app.state.one("SELECT created_at FROM ask_aliases WHERE lower(phrase)=lower(?)", (phrase,))
        created = int((existing or {}).get("created_at") or ts)
        self.app.state.execute(
            "INSERT OR REPLACE INTO ask_aliases(phrase,target,created_at,updated_at) VALUES(?,?,?,?)",
            (phrase, target, created, ts),
        )
        return {"ok": True, "phrase": phrase, "target": target, "created_at": created, "updated_at": ts}

    def remove_alias(self, phrase: str) -> Dict[str, Any]:
        phrase = str(phrase or "").strip()
        before = self.app.state.one("SELECT phrase,target FROM ask_aliases WHERE lower(phrase)=lower(?)", (phrase,))
        if not before:
            return {"ok": False, "error": f"Alias not found: {phrase}"}
        self.app.state.execute("DELETE FROM ask_aliases WHERE lower(phrase)=lower(?)", (phrase,))
        return {"ok": True, "removed": before}

    def resolve_alias(self, text: str) -> str:
        """The alias a phrase names, tolerating spacing and punctuation.

        An input that merely *appears inside* a known phrase is not that phrase.
        Matching that direction means the word "admin" resolves to whatever
        device "camp admin office" names, and a short word an operator typed
        becomes a specific switch they never asked for.
        """
        query = self._compact(text)
        if not query:
            return ""
        best: Tuple[int, str] = (0, "")
        for row in self.aliases():
            phrase = str(row.get("phrase") or "")
            key = self._compact(phrase)
            if key and (key == query or key in query):
                score = len(key) + (100 if key == query else 0)
                if score > best[0]:
                    best = (score, str(row.get("target") or ""))
        return best[1]

    def apply_aliases(self, text: str, strict: bool = False) -> str:
        """Rewrite known phrases into their targets.

        `strict` is for naming a device rather than asking a question. A
        question may be phrased loosely and still mean one place; a target is an
        identity, and guessing which device someone meant is how a command lands
        on the wrong switch.
        """
        output = re.sub(r"\s+", " ", str(text or "").strip())
        if not output:
            return ""
        changed = False
        for row in sorted(self.aliases(), key=lambda item: len(str(item.get("phrase") or "")), reverse=True):
            phrase = str(row.get("phrase") or "").strip()
            target = str(row.get("target") or "").strip()
            if not phrase or not target:
                continue
            pattern = re.compile(r"(?<![a-z0-9])" + r"\s+".join(re.escape(part) for part in phrase.split()) + r"(?![a-z0-9])", re.I)
            output, count = pattern.subn(target, output)
            changed = changed or bool(count)
        if not changed and not strict:
            resolved = self.resolve_alias(output)
            if resolved:
                return resolved
        return output

    def _compact(self, value: Any) -> str:
        return re.sub(r"[^a-z0-9]", "", str(value or "").lower())

    def _tokens(self, value: Any) -> List[str]:
        return re.findall(r"[a-z0-9]+", str(value or "").lower())

    def _normalize_question(self, question: str) -> str:
        text = re.sub(r"\s+", " ", str(question or "").strip())
        phrase_replacements = {
            r"\baccess\s*points?\b": "APs",
            r"\bwireless\s+aps?\b": "APs",
            r"\bhoa\s+many\b": "how many",
            r"\bhow\s+much\s+aps?\b": "how many APs",
            r"\bont\s+(?:the\s+)?": "on ",
            r"\bwitch\s+switch\b": "which switch",
            r"\bpreviou?sly\b": "previously",
            r"\battatched\b": "attached",
            r"\bconected\b": "connected",
            r"\bwich\b": "which",
            r"\brecen(?:t|lty)\b": "recent",
            r"\bchornolog(?:y|ical)\b": "chronology",
            r"\brefesh\b": "refresh",
            r"\bdiagno(?:se|sis)s?\b": "diagnose",
            r"\bconect\b": "connect",
            r"\bbldg\s+(\d+)\b": r"building\1",
            r"\bhouse\s+(\d+)\b": r"house\1",
            r"\bsquare\s+(\d+)\b": r"sq\1",
        }
        for pattern, replacement in phrase_replacements.items():
            text = re.sub(pattern, replacement, text, flags=re.I)
        return text

    def _location_variants(self, value: str) -> List[str]:
        base = re.sub(r"\s+", " ", str(value or "").strip().lower())
        variants = {base, normalize_location_label(base).lower()}
        patterns = [
            (re.compile(r"\b(?:building|bldg|bld|b)\s*0*(\d{1,3})\b", re.I), lambda n: [f"building{int(n)}", f"bldg{int(n)}", f"b{int(n)}"]),
            (re.compile(r"\b(?:house|h)\s*0*(\d{1,3})\b", re.I), lambda n: [f"house{int(n)}", f"h{int(n)}"]),
            (re.compile(r"\b(?:square|sq)\s*0*(\d{1,3})\b", re.I), lambda n: [f"square{int(n)}", f"sq{int(n)}"]),
        ]
        for _ in range(3):
            for current in list(variants):
                for pattern, make in patterns:
                    match = pattern.search(current)
                    if not match:
                        continue
                    for replacement in make(match.group(1)):
                        variants.add(current[:match.start()] + replacement + current[match.end():])
        variants.update(self._compact(item) for item in list(variants))
        return [item for item in variants if item]

    def _all_devices(self) -> List[Dict[str, Any]]:
        return self.app.state.rows(
            "SELECT 'device' AS kind,ip,hostname AS name,platform,model,serial,mac,NULL AS switch_ip,NULL AS switch_name,NULL AS switch_port,source,last_seen,status FROM devices"
        )

    def _all_aps(self) -> List[Dict[str, Any]]:
        rows = self.app.state.rows(
            "SELECT 'ap' AS kind,ip,name,platform,NULL AS model,NULL AS serial,mac,switch_ip,switch_name,switch_port,'AP' AS source,last_seen,status FROM aps"
        )
        return reconcile_ap_rows(rows)

    def _score(self, row: Dict[str, Any], query: str) -> int:
        query = self.apply_aliases(query)
        q_compact = self._compact(query)
        variants = {self._compact(item) for item in self._location_variants(query)}
        values = [
            row.get("name"), row.get("hostname"), row.get("entity_id"), row.get("ip"), row.get("platform"), row.get("model"), row.get("serial"),
            row.get("mac"), row.get("switch_name"), row.get("switch_port"), row.get("canonical_id"),
            row.get("identity_signature"), row.get("alias_names"),
        ]
        values.extend(row.get("aliases") or [])
        values.extend(row.get("addresses") or [])
        values.extend(row.get("macs") or [])
        blob = " ".join(str(value or "") for value in values).lower()
        compact_blob = self._compact(blob)
        score = 0
        if q_compact and q_compact == compact_blob:
            score += 100
        if q_compact and q_compact in compact_blob:
            score += 45
        if any(item and item in compact_blob for item in variants):
            score += 35
        query_tokens = [token for token in self._tokens(query) if token not in {"the", "at", "in", "on", "of"}]
        for token in query_tokens:
            canonical = normalize_location_label(token).lower()
            if token in blob or self._compact(token) in compact_blob or (canonical and canonical in compact_blob):
                score += 8
            elif len(token) >= 5:
                candidates = [item for item in self._tokens(blob) if abs(len(item) - len(token)) <= 2]
                if any(SequenceMatcher(None, token, item).ratio() >= 0.82 for item in candidates):
                    score += 3
        return score

    def _ranked_matches(self, rows: Sequence[Dict[str, Any]], query: str, limit: int = 500, spread: int = 10) -> List[Dict[str, Any]]:
        query = self.apply_aliases(query)
        if not query or query.lower() in {"all", "*", "any"}:
            return [dict(row) for row in rows[:limit]]
        scored = [(self._score(row, query), dict(row)) for row in rows]
        scored = [(score, row) for score, row in scored if score > 0]
        scored.sort(key=lambda item: (item[0], int(item[1].get("last_seen") or item[1].get("created_at") or 0)), reverse=True)
        if not scored:
            return []
        best = scored[0][0]
        threshold = max(8, best - spread)
        return [row for score, row in scored if score >= threshold][:limit]

    def inventory_candidates(self, query: str, kind: str = "any", limit: int = 100) -> List[Dict[str, Any]]:
        devices = self._all_devices()
        aps = self._all_aps()
        evidence = ap_name_evidence(query)
        if evidence.get("signature") and kind in {"any", "ap"}:
            compact_query = self._compact(query)
            exact = []
            for row in aps:
                aliases = row.get("aliases") or [row.get("name")]
                alias_exact = any(self._compact(alias) == compact_query for alias in aliases if alias)
                signature_exact = str(row.get("identity_signature") or "") == str(evidence["signature"])
                if alias_exact or signature_exact:
                    exact.append(row)
            if exact or kind == "ap":
                return exact[:limit]
        rows = devices + aps
        if kind in {"device", "ap"}:
            rows = [row for row in rows if row.get("kind") == kind]
        return self._ranked_matches(rows, query, limit)

    def _extract_status(self, question: str) -> str:
        if re.search(r"\b(offline|down|unreachable)\b", question, re.I):
            return "OFFLINE"
        if re.search(r"\b(online|up|reachable)\b", question, re.I):
            return "ONLINE"
        return ""

    def _wants_list(self, question: str) -> bool:
        return bool(re.search(r"\b(list|show|which|what are|give me|names?)\b", question, re.I))

    def _wants_count(self, question: str) -> bool:
        return bool(re.search(r"\b(how many|count|number|total)\b", question, re.I))

    def _is_past(self, question: str) -> bool:
        return bool(re.search(r"\b(before|previous|previously|prior|used to|history|timeline|moved from|was|were|last seen)\b", question, re.I))

    def _entity_label(self, row: Dict[str, Any]) -> str:
        return str(row.get("name") or row.get("hostname") or row.get("ip") or "unnamed")

    def _filter_status(self, rows: Sequence[Dict[str, Any]], status: str) -> List[Dict[str, Any]]:
        return [dict(row) for row in rows if not status or str(row.get("status") or "UNKNOWN").upper() == status]

    def _counts(self, rows: Sequence[Dict[str, Any]]) -> Dict[str, int]:
        result = {"ONLINE": 0, "OFFLINE": 0, "UNKNOWN": 0}
        for row in rows:
            status = str(row.get("status") or "UNKNOWN").upper()
            result[status if status in result else "UNKNOWN"] += 1
        return result

    def _workflow(self, *steps: Tuple[str, str]) -> List[Dict[str, Any]]:
        return [{"step": index + 1, "source": source, "operation": operation} for index, (source, operation) in enumerate(steps)]

    def _response(self, question: str, intent: str, answer: str, rows: Optional[List[Dict[str, Any]]] = None, workflow: Optional[List[Dict[str, Any]]] = None, **extra: Any) -> Dict[str, Any]:
        rows = [self._timestamp_row(row) for row in (rows or [])]
        payload = {
            "ok": True,
            "engine": "deterministic-command-center",
            "question": question,
            "intent": intent,
            "answer": answer,
            "result": {"rows": rows, "count": len(rows)},
            "workflow": workflow or [],
            "provenance": {"scope": "current-memory-and-command-registry", "engine": "deterministic-workflow"},
        }
        payload.update(extra)
        return payload

    def _format_time(self, value: Any) -> str:
        try:
            timestamp = int(value or 0)
        except (TypeError, ValueError):
            return ""
        if timestamp <= 0:
            return ""
        with contextlib.suppress(OverflowError, OSError, ValueError):
            return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(timestamp))
        return ""

    def _timestamp_row(self, row: Dict[str, Any]) -> Dict[str, Any]:
        item = dict(row)
        for key, value in tuple(item.items()):
            if key in {"first_seen", "last_seen", "last_failed"} or key.endswith("_at"):
                rendered = self._format_time(value)
                if rendered:
                    item[f"{key}_iso"] = rendered
        if item.get("created_at_iso"):
            item["recorded_at_iso"] = item["created_at_iso"]
        return item

    def _not_found(self, question: str, intent: str, target: str, kind: str = "record") -> Dict[str, Any]:
        return self._response(
            question,
            intent,
            f"I could not resolve {target!r} to a current {kind}. Try a shorter site/name fragment or add a deterministic alias.",
            [],
            self._workflow(("inventory", f"search current {kind} records for {target}")),
            suggestions=["netrune ask patterns", f"netrune ask alias set {target!r} '<known name>'"],
        )

    def _ambiguous(self, question: str, intent: str, target: str, rows: List[Dict[str, Any]]) -> Dict[str, Any]:
        choices = [{"name": self._entity_label(row), "ip": row.get("ip"), "kind": row.get("kind")} for row in rows[:12]]
        return self._response(
            question,
            intent,
            f"{target!r} matches {len(rows)} records. Be more specific.",
            rows[:12],
            self._workflow(("inventory", f"resolve {target}"), ("resolver", "return explicit choices")),
            choices=choices,
            ambiguous=True,
        )

    def _extract_ap_switch_query(self, question: str) -> Optional[str]:
        patterns = [
            r"\b(?:aps?|APs|access points?)\b.*?\b(?:on|attached to|connected to|sit on|sitting on)\s+(?P<switch>.+?)(?:\s+\b(?:at|in|for)\b\s+(?P<location>.+?))?[?.!]*$",
            r"\b(?:aps?|APs|access points?)\b.*?\b(?:at|in)\s+(?P<location>.+?)\s+\b(?:on|attached to|connected to)\b\s+(?P<switch>.+?)[?.!]*$",
            r"\b(?:AP count|count of APs?|number of APs?)\b\s*(?:for|on|at)\s+(?P<switch>.+?)(?:\s+\b(?:at|in)\b\s+(?P<location>.+?))?[?.!]*$",
        ]
        for pattern in patterns:
            match = re.search(pattern, question, re.I)
            if not match:
                continue
            switch = re.sub(r"\b(?:the|switch|device)\b", " ", match.group("switch") or "", flags=re.I)
            switch = re.sub(r"\s+", " ", switch).strip(" .,;:")
            location = re.sub(r"\b(?:the|site|location)\b", " ", match.groupdict().get("location") or "", flags=re.I)
            location = re.sub(r"\s+", " ", location).strip(" .,;:")
            query = " ".join(part for part in (location, switch) if part)
            if query:
                return query
        return None

    def _extract_collection_target(self, question: str, noun_pattern: str) -> str:
        text = re.sub(noun_pattern, " ", question, flags=re.I)
        text = re.sub(r"\b(?:how many|count|number|total|list|show|which|what are|give me|online|offline|down|up|reachable|unreachable|health|status|are|is|do we have|we have|the|all|that|currently|right now|please|just|known|recorded)\b", " ", text, flags=re.I)
        text = re.sub(r"\b(?:at|in|for|from|around)\b", " ", text, flags=re.I)
        return re.sub(r"\s+", " ", text).strip(" ?.!,;:")

    def _collection_answer(self, question: str, intent: str, rows: List[Dict[str, Any]], label: str, target: str = "", limit: int = 100) -> Dict[str, Any]:
        status = self._extract_status(question)
        filtered = self._filter_status(rows, status)
        counts = self._counts(filtered)
        location = f" for {target}" if target else ""
        if self._wants_list(question):
            shown = "; ".join(
                f"{self._entity_label(row)} ({str(row.get('status') or 'UNKNOWN').lower()})"
                for row in filtered[:30]
            )
            answer = f"{len(filtered)} {label}{location}: {shown or 'none'}."
        else:
            health = ", ".join(f"{value} {key.lower()}" for key, value in counts.items() if value)
            answer = f"{len(filtered)} {label}{location}" + (f"; {health}" if health else "") + "."
        return self._response(
            question,
            intent,
            answer,
            filtered[:limit],
            self._workflow(("inventory", f"load reconciled current {label}"), ("filters", f"apply target={target or 'all'} status={status or 'all'}"), ("formatter", "count or list results")),
            total_count=len(filtered),
            status_counts=counts,
            target=target,
        )

    def _ask_ap_on_switch(self, question: str, switch_query: str, limit: int) -> Dict[str, Any]:
        switches = self.inventory_candidates(switch_query, "device", max(limit, 20))
        if not switches:
            return self._not_found(question, "ap_on_switch", switch_query, "switch")
        if len(switches) > 1 and self._score(switches[0], switch_query) == self._score(switches[1], switch_query):
            return self._ambiguous(question, "ap_on_switch", switch_query, switches)
        switch = switches[0]
        payload = self.app.memory_switch_payload(str(switch.get("ip") or switch.get("name")), type("O", (), {"limit": max(limit, 100)})())
        aps = reconcile_ap_rows(payload.get("attachments", {}).get("aps", []))
        status = self._extract_status(question)
        aps = self._filter_status(aps, status)
        counts = self._counts(aps)
        switch_name = self._entity_label(switch)
        if self._wants_list(question):
            items = []
            for row in aps[:30]:
                aliases = row.get("aliases") or []
                alias_note = f", aliases: {', '.join(aliases)}" if len(aliases) > 1 else ""
                items.append(f"{self._entity_label(row)} [{row.get('switch_port') or '?'}; {str(row.get('status') or 'UNKNOWN').lower()}{alias_note}]")
            answer = f"{len(aps)} APs on {switch_name}: " + ("; ".join(items) if items else "none") + "."
        else:
            health = ", ".join(f"{value} {key.lower()}" for key, value in counts.items() if value)
            answer = f"{len(aps)} APs are attached to {switch_name}" + (f"; {health}" if health else "") + "."
        return self._response(
            question,
            "ap_on_switch",
            answer,
            aps,
            self._workflow(("inventory", f"resolve switch description {switch_query}"), ("memory", f"load current AP attachments for {switch.get('ip')}"), ("identity", "collapse AP aliases by MAC or location plus AP number"), ("filters", f"apply status={status or 'all'}")),
            selected=switch,
            status_counts=counts,
        )

    def _parse_event_state(self, value: Any) -> Dict[str, Any]:
        if isinstance(value, dict):
            return value
        with contextlib.suppress(Exception):
            parsed = json.loads(str(value or ""))
            return parsed if isinstance(parsed, dict) else {}
        return {}

    def _ask_ap_location(self, question: str, ap_target: str, limit: int) -> Dict[str, Any]:
        matches = self.inventory_candidates(ap_target, "ap", max(limit, 50))
        if not matches:
            like = f"%{ap_target}%"
            historical = self.app.state.one(
                "SELECT * FROM inventory_history WHERE entity_type='ap' AND (identity_value LIKE ? OR name LIKE ? OR previous_value LIKE ? OR current_value LIKE ?) ORDER BY created_at DESC,id DESC LIMIT 1",
                (like, like, like, like),
            )
            if historical:
                matches = [{
                    "kind": "ap",
                    "name": historical.get("name") or ap_target,
                    "ip": historical.get("ip") or "",
                    "mac": historical.get("mac") or "",
                    "switch_ip": historical.get("switch_ip") or "",
                    "switch_name": historical.get("switch_name") or "",
                    "switch_port": historical.get("switch_port") or "",
                    "platform": historical.get("platform") or "",
                    "status": historical.get("status") or "UNKNOWN",
                    "aliases": [ap_target, historical.get("name")] if historical.get("name") and historical.get("name") != ap_target else [ap_target],
                }]
            else:
                return self._not_found(question, "ap_location", ap_target, "AP")
        if len(matches) > 1:
            signatures = {row.get("canonical_id") for row in matches}
            if len(signatures) > 1:
                return self._ambiguous(question, "ap_location", ap_target, matches)
        ap = matches[0]
        terms = list(dict.fromkeys([self._entity_label(ap), str(ap.get("ip") or ""), str(ap.get("mac") or ""), *(ap.get("aliases") or [])]))
        events: List[Dict[str, Any]] = []
        seen = set()
        for term in [item for item in terms if item and item.upper() != "N/A"]:
            like = f"%{term}%"
            for row in self.app.state.rows(
                "SELECT * FROM relationship_events WHERE rel_type='ap_attachment' AND (subject_id LIKE ? OR object_id LIKE ? OR previous_json LIKE ? OR current_json LIKE ?) ORDER BY created_at DESC,id DESC LIMIT ?",
                (like, like, like, like, limit),
            ):
                if row.get("id") not in seen:
                    seen.add(row.get("id"))
                    events.append(row)
        events.sort(key=lambda row: (int(row.get("created_at") or 0), int(row.get("id") or 0)), reverse=True)
        past = self._is_past(question)
        state: Dict[str, Any] = {}
        chosen: Optional[Dict[str, Any]] = None
        if past:
            chosen = next((row for row in events if str(row.get("event_type") or "").lower() in {"changed", "disappeared"}), None)
            if chosen:
                state = self._parse_event_state(chosen.get("previous_json")) or self._parse_event_state(chosen.get("current_json"))
        elif events:
            chosen = events[0]
            state = self._parse_event_state(chosen.get("current_json")) or self._parse_event_state(chosen.get("previous_json"))
        attrs = state.get("attrs") if isinstance(state.get("attrs"), dict) else {}
        switch = state.get("switch_name") or state.get("object_id") or ap.get("switch_name") or ap.get("switch_ip") or "unknown switch"
        port = state.get("switch_port") or ap.get("switch_port") or "unknown port"
        tense = "was previously recorded" if past else "is currently recorded"
        controller_only = str(port).strip().lower() in {"", "n/a", "wireless", "not-joined", "unknown port"} or bool(
            re.search(r"(?:wlc|controller|vsz)", str(switch), re.I)
        )
        if controller_only:
            answer = f"{self._entity_label(ap)} only has a controller observation ({switch}, {port}); no physical switch port is cached"
            mac = normalize_mac(ap.get("mac"))
            if mac:
                display_mac = ".".join(mac[index:index + 4] for index in range(0, 12, 4))
                answer += f". A live read-only search is available with `netrune lookup mac all {display_mac}`"
            answer += "."
        else:
            answer = f"{self._entity_label(ap)} {tense} on {switch}, port {port}."
        aliases = ap.get("aliases") or []
        if len(aliases) > 1:
            answer += " Known aliases: " + ", ".join(aliases) + "."
        return self._response(
            question,
            "ap_location",
            answer,
            [ap],
            self._workflow(("identity", f"resolve AP aliases for {ap_target}"), ("memory", "search AP attachment relationship events"), ("timeline", "select previous state" if past else "select current state")),
            selected=ap,
            events=events[:limit],
            attachment={"switch": switch, "port": port, "attrs": attrs},
        )

    def _ask_port(self, question: str, switch_query: str, port: str, limit: int) -> Dict[str, Any]:
        switches = self.inventory_candidates(switch_query, "device", max(limit, 20))
        if not switches:
            return self._not_found(question, "port_memory", switch_query, "switch")
        if len(switches) > 1:
            return self._ambiguous(question, "port_memory", switch_query, switches)
        switch = switches[0]
        payload = self.app.memory_port_payload(str(switch.get("ip") or switch.get("name")), port, limit)
        current = payload.get("current") or []
        events = payload.get("timeline") or payload.get("events") or []
        if current:
            names = []
            for row in current[:10]:
                attrs = self._parse_event_state(row.get("attrs_json"))
                names.append(str(attrs.get("ap_name") or attrs.get("remote_name") or row.get("object_id") or "unknown"))
            answer = f"{self._entity_label(switch)} {port} currently records: {', '.join(names)}."
        else:
            answer = f"No current occupant is recorded on {self._entity_label(switch)} {port}."
        if self._is_past(question) and events:
            answer += f" {len(events)} historical event(s) are available."
        return self._response(
            question,
            "port_memory",
            answer,
            current,
            self._workflow(("inventory", f"resolve switch {switch_query}"), ("memory", f"query current and historical occupancy for {port}")),
            selected=switch,
            events=events,
        )

    def _ask_ip_or_mac(self, question: str, value: str, kind: str, limit: int) -> Dict[str, Any]:
        normalized = normalize_mac(value) if kind == "mac" else value
        payload = self.app.relationship_timeline_payload(normalized, limit, subject_kind=kind)
        rows = payload.get("rows") or []
        current = self.app.state.rows(
            "SELECT * FROM relationships_current WHERE subject_kind=? AND subject_id LIKE ? ORDER BY CASE WHEN status='disappeared' THEN 1 ELSE 0 END,confidence DESC,last_seen DESC LIMIT ?",
            (kind, f"%{normalized}%", limit),
        )
        labels = [str(row.get("object_id") or row.get("switch_name") or "") for row in current if row.get("object_id") or row.get("switch_name")]
        answer = f"{kind.upper()} {value}"
        if labels:
            answer += " is currently associated with " + ", ".join(dict.fromkeys(labels[:10]))
        else:
            answer += " has no current relationship record"
        if rows:
            answer += f"; {len(rows)} historical event(s) found"
        answer += "."
        return self._response(
            question,
            f"{kind}_memory",
            answer,
            current,
            self._workflow(("memory", f"query current {kind} relationships"), ("timeline", f"query historical {kind} events")),
            events=rows,
        )

    def _ask_topology(self, question: str, target: str, limit: int) -> Dict[str, Any]:
        switches = self.inventory_candidates(target, "device", max(limit, 20))
        if not switches:
            return self._not_found(question, "topology", target, "switch")
        if len(switches) > 1:
            return self._ambiguous(question, "topology", target, switches)
        switch = switches[0]
        key = str(switch.get("ip") or switch.get("name"))
        like = f"%{key}%"
        rows = self.app.state.rows(
            "SELECT * FROM neighbors WHERE local_ip LIKE ? OR local_name LIKE ? OR remote_ip LIKE ? OR remote_name LIKE ? ORDER BY local_port,remote_name LIMIT ?",
            (like, like, like, like, limit),
        )
        links = "; ".join(f"{row.get('local_port') or '?'} -> {row.get('remote_name') or row.get('remote_ip') or 'unknown'} {row.get('remote_port') or ''}".strip() for row in rows[:20])
        answer = f"{self._entity_label(switch)} has {len(rows)} cached neighbor link(s)" + (f": {links}." if links else ".")
        return self._response(
            question,
            "topology",
            answer,
            rows,
            self._workflow(("inventory", f"resolve switch {target}"), ("topology", "read current LLDP/CDP neighbor cache")),
            selected=switch,
        )

    def _ask_details(self, question: str, target: str, limit: int) -> Dict[str, Any]:
        rows = self.inventory_candidates(target, "any", max(limit, 30))
        if not rows:
            return self._not_found(question, "entity_details", target)
        if len(rows) > 1:
            return self._ambiguous(question, "entity_details", target, rows)
        row = rows[0]
        lower = question.lower()
        if re.search(r"\bip(?:s| address(?:es)?)?\b", lower):
            addresses = row.get("addresses") or ([row.get("ip")] if row.get("ip") else [])
            answer = f"{self._entity_label(row)} has IP" + ("s " if len(addresses) != 1 else " ") + (", ".join(str(value) for value in addresses) if addresses else "unknown") + "."
        elif re.search(r"\bmac(?:s| address(?:es)?)?\b", lower):
            macs = row.get("macs") or ([row.get("mac")] if row.get("mac") else [])
            answer = f"{self._entity_label(row)} has MAC" + ("s " if len(macs) != 1 else " ") + (", ".join(str(value) for value in macs) if macs else "unknown") + "."
        elif re.search(r"\b(model|platform)\b", lower):
            answer = f"{self._entity_label(row)} is {row.get('model') or row.get('platform') or 'unknown platform'}."
        elif re.search(r"\b(last seen|seen last|when.*seen)\b", lower):
            last_seen = self._format_time(row.get("last_seen"))
            answer = f"{self._entity_label(row)} was last seen at {last_seen or 'an unknown time'}."
        elif re.search(r"\b(alias|aliases|alternate names?|called now|current name)\b", lower):
            aliases = row.get("aliases") or [self._entity_label(row)]
            answer = f"{self._entity_label(row)} is the canonical active name. Known aliases: {', '.join(str(value) for value in aliases)}."
        elif re.search(r"\b(health|status|online|offline|up|down)\b", lower):
            answer = f"{self._entity_label(row)} is {str(row.get('status') or 'UNKNOWN').lower()}."
        else:
            parts = [str(row.get("kind") or "record"), self._entity_label(row)]
            addresses = row.get("addresses") or ([row.get("ip")] if row.get("ip") else [])
            if addresses:
                parts.append("IP " + ", ".join(str(value) for value in addresses))
            if row.get("platform") or row.get("model"):
                parts.append(str(row.get("model") or row.get("platform")))
            parts.append(str(row.get("status") or "UNKNOWN").lower())
            answer = "; ".join(parts) + "."
            if len(row.get("aliases") or []) > 1:
                answer += " Known aliases: " + ", ".join(row.get("aliases") or []) + "."
        return self._response(
            question,
            "entity_details",
            answer,
            [row],
            self._workflow(("inventory", f"resolve current entity {target}"), ("identity", "reconcile aliases when entity is an AP")),
            selected=row,
        )

    def _target_from_question(self, question: str, extra_patterns: Sequence[str] = ()) -> str:
        text = str(question or "")
        protected: Dict[str, str] = {}

        def protect_identifier(match: re.Match[str]) -> str:
            key = f"QZX{len(protected)}ZXQ"
            protected[key] = match.group(0)
            return key

        # Hostnames, addresses, MACs, and interface-like tokens are opaque.
        # Their hyphen-delimited components may otherwise look like articles
        # or prepositions to the natural-language filler removal below.
        text = re.sub(
            r"(?<![A-Za-z0-9_.:/-])[A-Za-z0-9][A-Za-z0-9_.:/-]*[-_.:/][A-Za-z0-9_.:/-]*(?![A-Za-z0-9_.:/-])",
            protect_identifier,
            text,
        )
        patterns = [
            *extra_patterns,
            r"\b(?:please|can you|could you|would you|tell me|give me|show me|show|list|find|check|review)\b",
            r"\b(?:what|which|who|where|when|how many|how|are|is|was|were|did|do|does|have|has|had)\b",
            r"\b(?:the|a|an|all|any|some|that|this|these|those|current|currently|recent|recently|latest|last|right now|recorded|known)\b",
            r"\b(?:at|in|on|of|for|from|around|about|to|with|by)\b",
        ]
        for pattern in patterns:
            text = re.sub(pattern, " ", text, flags=re.I)
        for key, value in protected.items():
            text = text.replace(key, value)
        return re.sub(r"\s+", " ", text).strip(" ?.!,;:-")

    def _filter_blob(self, rows: Sequence[Dict[str, Any]], target: str) -> List[Dict[str, Any]]:
        target = self.apply_aliases(target)
        if not target or target.lower() in {"all", "*", "any"}:
            return [dict(row) for row in rows]
        variants = {self._compact(item) for item in self._location_variants(target)}
        tokens = [self._compact(token) for token in self._tokens(target) if token not in {"the", "switch", "device", "ap"}]
        output = []
        for row in rows:
            blob = self._compact(json.dumps(row, default=str))
            if any(value and value in blob for value in variants):
                output.append(dict(row))
                continue
            if tokens and all(token in blob for token in tokens if token):
                output.append(dict(row))
        return output

    def _ask_switch_summary(self, question: str, target: str, limit: int) -> Dict[str, Any]:
        switches = self.inventory_candidates(target, "device", max(limit, 20))
        if not switches:
            return self._not_found(question, "switch_summary", target, "switch")
        if len(switches) > 1:
            return self._ambiguous(question, "switch_summary", target, switches)
        switch = switches[0]
        payload = self.app.memory_switch_payload(str(switch.get("ip") or switch.get("name")), type("Options", (), {"limit": max(limit, 100)})())
        health = self.app.state.one(
            "SELECT * FROM health_state WHERE entity_type='device' AND (entity_id=? OR name=?) ORDER BY updated_at DESC LIMIT 1",
            (switch.get("ip"), switch.get("name")),
        ) or {}
        counts = payload.get("counts") or {}
        answer = (
            f"{self._entity_label(switch)} is {str(health.get('status') or switch.get('status') or 'UNKNOWN').lower()}; "
            f"{counts.get('aps', 0)} APs, {counts.get('neighbors', 0)} neighbors, "
            f"{counts.get('relationships', 0)} active relationships, and {counts.get('events', 0)} recent memory events."
        )
        return self._response(
            question,
            "switch_summary",
            answer,
            payload.get("attachments", {}).get("aps", []),
            self._workflow(("inventory", f"resolve switch {target}"), ("health", "read canonical health"), ("memory", "combine AP, neighbor, and relationship state")),
            selected=switch,
            summary=counts,
            neighbors=payload.get("attachments", {}).get("neighbors", []),
            events=payload.get("timeline", []),
        )

    def _ask_health(self, question: str, limit: int) -> Dict[str, Any]:
        rows = self.app.state.rows(
            "SELECT entity_type AS kind,entity_id,name,platform,status,first_seen,last_seen,last_failed,outage_started_at,flap_count,switch_ip,switch_port,updated_at FROM health_state ORDER BY CASE status WHEN 'OFFLINE' THEN 0 WHEN 'UNKNOWN' THEN 1 ELSE 2 END,flap_count DESC,last_seen"
        )
        lower = question.lower()
        if re.search(r"\b(?:aps?|access points?)\b", lower):
            rows = [row for row in rows if row.get("kind") == "ap"]
            target = self._extract_collection_target(question, r"\b(?:aps?|access points?)\b")
        elif re.search(r"\b(?:switches|network devices|routers?)\b", lower):
            rows = [row for row in rows if row.get("kind") == "device"]
            target = self._extract_collection_target(question, r"\b(?:switches|network devices|routers?)\b")
        else:
            target = self._target_from_question(
                question,
                (
                    r"\b(?:health|status|state|outages?|flapping|flaps?|stale|offline|online|down|up|unreachable|reachable|not seen|last seen|devices?|network)\b",
                ),
            )
        status = self._extract_status(question)
        predicate = bool(target and re.search(r"^\s*(?:is|are|was|were|did)\b", question, re.I))
        if status and not predicate:
            rows = [row for row in rows if str(row.get("status") or "").upper() == status]
        if re.search(r"\bflapp(?:ing|ers?)|\bflaps?\b", lower):
            rows = [row for row in rows if int(row.get("flap_count") or 0) > 0]
        if re.search(r"\b(stale|not seen|old inventory)\b", lower):
            cutoff = int(time.time()) - 86400
            rows = [row for row in rows if int(row.get("last_seen") or 0) < cutoff]
        if re.search(r"\b(outage|outages)\b", lower):
            rows = [row for row in rows if row.get("outage_started_at") or str(row.get("status") or "").upper() == "OFFLINE"]
        if target:
            rows = self._filter_blob(rows, target)
        counts = self._counts(rows)
        health = ", ".join(f"{value} {key.lower()}" for key, value in counts.items() if value)
        label = f" for {target}" if target else ""
        if predicate and len(rows) == 1 and status:
            actual = str(rows[0].get("status") or "UNKNOWN").upper()
            requested = status.lower()
            answer = f"{self._entity_label(rows[0])} is {actual.lower()}" + ("." if actual == status else f", not {requested}.")
        else:
            answer = f"{len(rows)} health record(s){label}" + (f"; {health}" if health else "") + "."
        return self._response(
            question,
            "health",
            answer,
            rows[:limit],
            self._workflow(("health", "read canonical current health"), ("filters", f"apply target={target or 'all'} status={status or 'all'}")),
            total_count=len(rows),
            status_counts=counts,
            target=target,
        )

    def _ask_attention(self, question: str, limit: int) -> Dict[str, Any]:
        payload = self.app.attention_payload(max(limit, 100))
        rows = payload.get("items") or []
        target = self._target_from_question(question, (r"\b(?:attention|warnings?|alerts?|issues?|problems?|important|changes?|failed|failures?|outstanding|needs?|review)\b",))
        if target:
            rows = self._filter_blob(rows, target)
        kinds: Dict[str, int] = {}
        for row in rows:
            key = str(row.get("kind") or "other")
            kinds[key] = kinds.get(key, 0) + 1
        detail = ", ".join(f"{count} {kind}" for kind, count in sorted(kinds.items()))
        answer = f"{len(rows)} attention item(s)" + (f" for {target}" if target else "") + (f": {detail}." if detail else ".")
        return self._response(
            question,
            "attention",
            answer,
            rows[:limit],
            self._workflow(("health", "read offline, stale, and flapping state"), ("memory", "read topology, AP move, and backup events"), ("filters", f"apply target={target or 'all'}")),
            total_count=len(rows),
            kind_counts=kinds,
            target=target,
        )

    def _ask_topology_changes(self, question: str, limit: int) -> Dict[str, Any]:
        rows = self.app.state.rows("SELECT * FROM topology_events ORDER BY created_at DESC,id DESC LIMIT ?", (max(limit * 4, 200),))
        target = self._target_from_question(question, (r"\b(?:topology|links?|neighbors?|downstream|upstream|events?|changes?|changed|new|added|removed|disappeared)\b",))
        lower = question.lower()
        if re.search(r"\b(removed|disappeared|missing)\b", lower):
            rows = [row for row in rows if "removed" in str(row.get("event_type") or "").lower()]
        elif re.search(r"\b(new|added|appeared)\b", lower):
            rows = [row for row in rows if "added" in str(row.get("event_type") or "").lower()]
        if target:
            rows = self._filter_blob(rows, target)
        answer = f"{len(rows)} topology change(s)" + (f" matched {target}" if target else "") + "."
        return self._response(
            question,
            "topology_changes",
            answer,
            rows[:limit],
            self._workflow(("topology", "read cached link change events"), ("filters", f"apply target={target or 'all'}")),
            total_count=len(rows),
            target=target,
        )

    def _ask_ap_moves(self, question: str, limit: int) -> Dict[str, Any]:
        rows = self.app.state.rows("SELECT * FROM ap_move_events ORDER BY created_at DESC,id DESC LIMIT ?", (max(limit * 4, 200),))
        target = self._target_from_question(question, (r"\b(?:aps?|access points?|wireless|moves?|moved|movement|timeline|attachments?|switches?|ports?|changed|changes)\b",))
        if target:
            rows = self._filter_blob(rows, target)
        answer = f"{len(rows)} AP movement event(s)" + (f" matched {target}" if target else "") + "."
        return self._response(
            question,
            "ap_moves",
            answer,
            rows[:limit],
            self._workflow(("memory", "read canonical AP attachment changes"), ("filters", f"apply target={target or 'all'}")),
            total_count=len(rows),
            target=target,
        )

    def _ask_ap_aliases(self, question: str, limit: int) -> Dict[str, Any]:
        rows = self._all_aps()
        explicit = list(dict.fromkeys(re.findall(r"\b[A-Za-z0-9][A-Za-z0-9_.-]*AP\d+[A-Za-z0-9_.-]*\b", question, re.I)))
        if len(explicit) >= 2:
            left_name, right_name = explicit[0], explicit[1]
            left_evidence = ap_name_evidence(left_name)
            right_evidence = ap_name_evidence(right_name)

            def exact_matches(name: str, evidence: Dict[str, Any]) -> List[Dict[str, Any]]:
                compact = self._compact(name)
                return [
                    row for row in rows
                    if any(self._compact(alias) == compact for alias in (row.get("aliases") or [row.get("name")]) if alias)
                    or (evidence.get("signature") and row.get("identity_signature") == evidence.get("signature"))
                ]

            left = exact_matches(left_name, left_evidence)
            right = exact_matches(right_name, right_evidence)
            same_current = bool(left and right and left[0].get("canonical_id") == right[0].get("canonical_id"))
            comparable = bool(left_evidence.get("signature") and right_evidence.get("signature"))
            same_signature = comparable and left_evidence.get("signature") == right_evidence.get("signature")
            determined = same_current or comparable
            same = same_current or same_signature
            if not determined:
                answer = f"I cannot establish whether {left_name} and {right_name} are the same AP from their names alone."
            elif same:
                answer = f"{left_name} and {right_name} are the same canonical AP."
            else:
                answer = f"{left_name} and {right_name} are different APs."
            result_rows: List[Dict[str, Any]] = []
            for row in [*(left[:1]), *(right[:1])]:
                if not any(existing.get("canonical_id") == row.get("canonical_id") for existing in result_rows):
                    result_rows.append(row)
            return self._response(
                question,
                "ap_aliases",
                answer,
                result_rows,
                self._workflow(("identity", "normalize organization prefixes and retain location qualifiers"), ("identity", "compare exact active aliases and location-plus-AP-number signatures")),
                comparison={"same": same, "determined": determined, "left": left_name, "right": right_name},
                evidence={"left": left_evidence, "right": right_evidence, "active_matches": result_rows},
            )
        target = explicit[0] if explicit else self._target_from_question(
            question,
            (r"\b(?:aps?|access points?|aliases?|alternate|names?|canonical|identity|identities|records?|merged|duplicates?|same|observations?|addresses?|ips?|explain|multiple)\b",),
        )
        if target:
            rows = self.inventory_candidates(target, "ap", limit)
        else:
            rows = [row for row in rows if int(row.get("merged_records") or 0) > 1 or len(row.get("aliases") or []) > 1 or len(row.get("addresses") or []) > 1]
        parts = []
        for row in rows[:20]:
            aliases = row.get("aliases") or []
            addresses = row.get("addresses") or []
            parts.append(f"{self._entity_label(row)}: {len(aliases)} name(s), {len(addresses)} address(es)")
        subject = f"{len(rows)} canonical AP identit{'y' if len(rows) == 1 else 'ies'}"
        qualifier = f" matched {target}" if target else f" {'has' if len(rows) == 1 else 'have'} multiple observations"
        answer = subject + qualifier + (": " + "; ".join(parts) + "." if parts else ".")
        return self._response(
            question,
            "ap_aliases",
            answer,
            rows[:limit],
            self._workflow(("inventory", "load raw current AP observations"), ("identity", "merge by valid MAC or normalized location plus AP number"), ("safety", "keep conflicting MACs and meaningful location qualifiers separate")),
            total_count=len(rows),
            target=target,
        )

    def _ask_unjoined_aps(self, question: str, limit: int) -> Dict[str, Any]:
        rows = self.app.state.rows(
            "SELECT 'ap' AS kind,* FROM aps WHERE lower(COALESCE(switch_port,'')) IN ('not-joined','not joined','unjoined','nonjoined') ORDER BY last_seen DESC,name"
        )
        rows = reconcile_ap_rows(rows)
        target = self._extract_collection_target(question, r"\b(?:aps?|access points?)\b")
        target = re.sub(r"\b(?:unjoined|not joined|nonjoined|disconnected|awaiting join|controller|wlc|unregistered)\b", " ", target, flags=re.I)
        target = re.sub(r"\s+", " ", target).strip()
        if target:
            rows = self._ranked_matches(rows, target, limit)
        answer = f"{len(rows)} unjoined AP(s)" + (f" matched {target}" if target else "") + "."
        return self._response(
            question,
            "unjoined_aps",
            answer,
            rows[:limit],
            self._workflow(("inventory", "read controller AP observations marked not joined"), ("identity", "collapse aliases without hiding distinct APs")),
            total_count=len(rows),
            target=target,
        )

    def _ask_identity_history(self, question: str, target: str, limit: int) -> Dict[str, Any]:
        target = target.strip()
        current = self.inventory_candidates(target, "any", 20) if target else []
        if len(current) > 1:
            return self._ambiguous(question, "identity_history", target, current)
        selected = current[0] if current else {}
        terms = [target]
        if selected:
            terms.extend([
                self._entity_label(selected),
                str(selected.get("ip") or ""),
                str(selected.get("mac") or ""),
                str(selected.get("canonical_id") or ""),
                *(selected.get("aliases") or []),
                *(selected.get("addresses") or []),
            ])
        history: List[Dict[str, Any]] = []
        events: List[Dict[str, Any]] = []
        seen_history = set()
        seen_events = set()
        for term in [item for item in dict.fromkeys(terms) if item]:
            like = f"%{term}%"
            for row in self.app.state.rows(
                "SELECT * FROM inventory_history WHERE identity_value LIKE ? OR ip LIKE ? OR mac LIKE ? OR name LIKE ? OR previous_value LIKE ? OR current_value LIKE ? ORDER BY created_at DESC,id DESC LIMIT ?",
                (like, like, like, like, like, like, limit),
            ):
                if row.get("id") not in seen_history:
                    seen_history.add(row.get("id"))
                    history.append(row)
            for row in self.app.state.rows(
                "SELECT * FROM relationship_events WHERE subject_id LIKE ? OR object_id LIKE ? OR previous_json LIKE ? OR current_json LIKE ? ORDER BY created_at DESC,id DESC LIMIT ?",
                (like, like, like, like, limit),
            ):
                if row.get("id") not in seen_events:
                    seen_events.add(row.get("id"))
                    events.append(row)
        history.sort(key=lambda row: (int(row.get("created_at") or 0), int(row.get("id") or 0)), reverse=True)
        events.sort(key=lambda row: (int(row.get("created_at") or 0), int(row.get("id") or 0)), reverse=True)
        if not selected and not history and not events:
            return self._not_found(question, "identity_history", target)
        names = list(dict.fromkeys(str(row.get("name") or "") for row in history if row.get("name")))
        ips = list(dict.fromkeys(str(row.get("ip") or "") for row in history if row.get("ip")))
        macs = list(dict.fromkeys(str(row.get("mac") or "") for row in history if row.get("mac")))
        if selected:
            names = list(dict.fromkeys([*(selected.get("aliases") or []), self._entity_label(selected), *names]))
            ips = list(dict.fromkeys([*(selected.get("addresses") or []), str(selected.get("ip") or ""), *ips]))
        names = [value for value in names if value]
        ips = [value for value in ips if value]
        macs = [value for value in macs if value]
        label = self._entity_label(selected) if selected else target
        answer = f"{label}: {len(history)} identity event(s) and {len(events)} relationship event(s)."
        if names:
            answer += " Known names: " + ", ".join(names[:12]) + "."
        if ips:
            answer += " Known IPs: " + ", ".join(ips[:12]) + "."
        return self._response(
            question,
            "identity_history",
            answer,
            history[:limit],
            self._workflow(("inventory", f"resolve current identity for {target}"), ("history", "read name, IP, MAC, model, and status events"), ("memory", "read relationship changes")),
            selected=selected,
            events=events[:limit],
            names=names,
            ips=ips,
            macs=macs,
        )

    def _ask_backup_history(self, question: str, limit: int) -> Dict[str, Any]:
        rows = self.app.state.rows("SELECT * FROM backup_history ORDER BY created_at DESC,id DESC LIMIT ?", (max(limit * 4, 200),))
        lower = question.lower()
        if re.search(r"\b(failed|failure|error|unsuccessful)\b", lower):
            rows = [row for row in rows if str(row.get("status") or "").lower() not in {"saved", "unchanged", "success", "completed"}]
        elif re.search(r"\b(changed|change)\b", lower):
            rows = [row for row in rows if int(row.get("changed") or 0) == 1]
        target = self._target_from_question(question, (r"\b(?:backups?|configs?|configurations?|history|results?|failed|failure|successful|saved|changed|change|latest|recent|when)\b",))
        if target:
            rows = self._filter_blob(rows, target)
        latest = rows[0] if rows else {}
        answer = f"{len(rows)} backup record(s)" + (f" matched {target}" if target else "")
        if latest:
            answer += f"; latest is {latest.get('status') or 'unknown'} for {latest.get('hostname') or latest.get('device_ip') or 'unknown device'}"
        answer += "."
        return self._response(
            question,
            "backup_history",
            answer,
            rows[:limit],
            self._workflow(("backup", "read saved backup metadata only"), ("filters", f"apply target={target or 'all'}")),
            total_count=len(rows),
            target=target,
        )

    def _ask_diagnostic_history(self, question: str, limit: int) -> Dict[str, Any]:
        rows: List[Dict[str, Any]] = []
        table_specs = [
            ("latency", "probe_results"),
            ("speed", "speed_tests"),
            ("filtering", "filtering_checks"),
            ("interface", "interface_samples"),
        ]
        for kind, table in table_specs:
            for row in self.app.state.rows(f"SELECT * FROM {table} ORDER BY created_at DESC,id DESC LIMIT ?", (max(limit, 50),)):
                item = dict(row)
                item["kind"] = kind
                rows.append(item)
        lower = question.lower()
        if re.search(r"\b(latency|ping|packet loss|jitter)\b", lower):
            rows = [row for row in rows if row.get("kind") == "latency"]
        elif re.search(r"\b(speed|download|upload|bandwidth)\b", lower):
            rows = [row for row in rows if row.get("kind") == "speed"]
        elif re.search(r"\b(filtering|dns|tls|ssl|mitm)\b", lower):
            rows = [row for row in rows if row.get("kind") == "filtering"]
        elif re.search(r"\b(interface|utilization|traffic)\b", lower):
            rows = [row for row in rows if row.get("kind") == "interface"]
        target = self._target_from_question(question, (r"\b(?:diagnostics?|history|results?|latency|ping|packet loss|jitter|speed|tests?|download|upload|bandwidth|filtering|checks?|dns|tls|ssl|mitm|interface|utilization|traffic|failed|suspicious|last|ten)\b",))
        if target:
            rows = self._filter_blob(rows, target)
        rows.sort(key=lambda row: int(row.get("created_at") or 0), reverse=True)
        answer = f"{len(rows)} saved diagnostic result(s)" + (f" matched {target}" if target else "") + "."
        return self._response(
            question,
            "diagnostic_history",
            answer,
            rows[:limit],
            self._workflow(("diagnostics", "combine saved latency, speed, filtering, and interface samples"), ("filters", f"apply target={target or 'all'}")),
            total_count=len(rows),
            target=target,
        )

    def _ask_jobs(self, question: str, limit: int) -> Dict[str, Any]:
        rows = self.app.state.rows("SELECT * FROM jobs ORDER BY created_at DESC LIMIT ?", (max(limit * 4, 200),))
        lower = question.lower()
        status = ""
        for pattern, value in [
            (r"\b(running|active)\b", "running"),
            (r"\b(queued|pending|waiting)\b", "queued"),
            (r"\b(failed|failure|error)\b", "failed"),
            (r"\b(completed|finished|successful|done)\b", "completed"),
            (r"\b(cancelled|canceled)\b", "cancelled"),
        ]:
            if re.search(pattern, lower):
                status = value
                break
        if status:
            rows = [row for row in rows if str(row.get("status") or "").lower() == status]
        target = self._target_from_question(question, (r"\b(?:jobs?|operations?|workflows?|scans?|pending|queued|waiting|running|active|failed|failure|completed|finished|successful|done|cancelled|canceled|latest|recent|result|status)\b",))
        if target:
            rows = self._filter_blob(rows, target)
        answer = f"{len(rows)} job(s)" + (f" with status {status}" if status else "") + (f" matched {target}" if target else "") + "."
        return self._response(
            question,
            "job_status",
            answer,
            rows[:limit],
            self._workflow(("jobs", "read recorded job lifecycle"), ("filters", f"apply status={status or 'all'} target={target or 'all'}")),
            total_count=len(rows),
            target=target,
            status=status,
        )

    def _command_matches(self, question: str) -> List[Tuple[str, int]]:
        lower = question.lower()
        rules: List[Tuple[str, str, int]] = [
            ("ask-alias-remove", r"\b(?:remove|delete|unset)\b.*\b(?:ask\s+)?alias\b", 101),
            ("ask-alias-set", r"\b(?:set|create|add|save)\b.*\b(?:ask\s+)?alias\b", 101),
            ("vlan-set", r"\b(?:set|change|assign|move|configure|put)\b.*\bvlan\b|\b(?:access|trunk)\s+vlan\b", 100),
            ("device-config", r"\b(?:configure|push|apply|change)\b.*\b(?:configuration|config)\b", 98),
            ("device-show", r"\b(?:show|sh|display|get)\s+[^?]+\b(?:on|from|at)\b", 97),
            ("device-trust-enroll", r"\b(?:enroll|add|trust)\b.*\bssh\b.*\b(?:host[ -]?key|fingerprint|trust)\b|\bssh\s+trust\s+enroll\b", 104),
            ("device-trust-forget", r"\b(?:forget|remove|delete)\b.*\bssh\b.*\b(?:host[ -]?key|trust)\b|\bssh\s+trust\s+forget\b", 104),
            ("device-trust-scan", r"\b(?:scan|inspect|retrieve)\b.*\bssh\b.*\b(?:host[ -]?keys?|fingerprints?)\b|\bssh\s+trust\s+scan\b", 103),
            ("device-trust-status", r"\bssh\s+(?:host[ -]?key\s+)?trust\s+status\b|\bssh\s+trust\s+status\b", 103),
            ("device-ssh", r"\b(?:ssh(?:\s+to)?|connect(?:\s+to)?|log\s*in\s+to|open\s+(?:an?\s+)?ssh\s+session)\b", 96),
            ("workflow-refresh-inventory", r"\brefresh\b.*\b(?:inventory|aps?.*topology|topology.*aps?)\b", 95),
            ("workflow-morning-check", r"\b(?:run|start|perform|do)\b.*\bmorning\s+check\b", 95),
            ("workflow-ap-audit", r"\b(?:run|start|perform|do)\b.*\bap\s+audit\b", 95),
            ("workflow-site-health", r"\b(?:run|start|perform|do)\b.*\bsite\s+health\b", 95),
            ("workflow-backup-online", r"\b(?:run|start|perform|do)\b.*\bbackup[- ]online\b", 95),
            ("inventory-import-flat", r"\bimport\b.*\b(?:flat|legacy|cache|inventory)\b", 94),
            ("inventory-export-flat", r"\bexport\b.*\b(?:flat|legacy|cache|inventory)\b", 94),
            ("inventory-scan", r"\b(?:scan|discover|rescan)\b.*\b(?:inventory|switches?|routers?|devices?)\b|\binventory\s+scan\b", 93),
            ("inventory-activity", r"\b(?:ping|poll|check)\b.*\b(?:inventory\s+)?activity\b", 92),
            ("health-check", r"\b(?:run|start|perform|trigger|poll|refresh)\b.*\bhealth(?:\s+check)?\b|\b(?:fast\s+)?health\s+check\b|\bcheck\s+(?:the\s+)?health\b", 93),
            ("ap-scan", r"\b(?:scan|discover|rescan|refresh)\b.*\b(?:aps?|access points?)\b", 93),
            ("topology-scan", r"\b(?:scan|discover|rescan|refresh)\b.*\b(?:topology|lldp|cdp|neighbors?)\b", 93),
            ("memory-refresh", r"\b(?:refresh|rebuild|recompute|sync)\b.*\b(?:memory|relationships?)\b", 93),
            ("backup-run", r"\b(?:back\s+up|take\s+(?:a\s+)?backup|run\s+(?:a\s+)?backup|start\s+(?:a\s+)?backup|backup\s+now)\b", 93),
            ("backup-verify", r"\b(?:verify|validate|check)\b.*\bbackups?\b", 92),
            ("diagnose-core-ping", r"\b(?:point[- ]of[- ]truth|truth)\s+ping\b|\bping\b.*\bfrom\s+(?:the\s+)?core\b|\bcore[- ]origin(?:ated)?\s+(?:ping|latency)\b", 99),
            ("diagnose-doctor", r"\b(?:diagnostic|diagnostics|netops)\s+(?:doctor|readiness|prerequisites?)\b|\bdoctor\b.*\bdiagnos", 99),
            ("diagnose-cable-test", r"\b(?:start|run|perform)\b.*\b(?:tdr|cable diagnostic|cable test)\b", 100),
            ("diagnose-cable", r"\b(?:show|read|check|diagnose)\b.*\b(?:tdr|cable health|cable diagnostic|cabling)\b", 99),
            ("diagnose-port-health", r"\b(?:check|diagnose|sample|inspect)\b.*\b(?:port health|link negotiation|crc|counter deltas?)\b|\bport[- ]health\b", 99),
            ("diagnose-throughput", r"\biperf3?\b|\bthroughput\b.*\b(?:core|server|between|from|to)\b|\b(?:core|endpoint)\b.*\bthroughput\b", 98),
            ("diagnose-latency", r"\b(?:ping|probe)\b|\b(?:test|measure|diagnose)\b.*\b(?:latency|reachability)\b|\blatency\s+(?:test|probe)\b", 92),
            ("diagnose-speed", r"\b(?:run|start|perform|do)\b.*\bspeed\s*test\b|\btest\b.*\b(?:bandwidth|internet speed|throughput)\b", 94),
            ("diagnose-filtering", r"\b(?:run|start|test|check|diagnose)\b.*\b(?:filtering|dns|tls|mitm)\b", 94),
            ("diagnose-interface", r"\b(?:monitor|sample|watch|diagnose)\b.*(?:\b(?:interface|port)\b|\b(?:gi|gig|te|fa|eth)\s*\d+(?:/\d+){1,4}\b)", 94),
            ("lookup-mac-profile", r"\b(?:profile|deep inspect|fingerprint)\b.*\bmac\b|\bmac\b.*\b(?:profile|deep inspect|fingerprint)\b", 98),
            ("lookup-mac-history", r"\b(?:history|timeline|movement|moves?)\b.*\bmac\b|\bmac\b.*\b(?:history|timeline|movement|moves?)\b", 97),
            ("lookup-mac-vendor", r"\b(?:vendor|manufacturer|oui)\b.*\bmac\b|\bmac\b.*\b(?:vendor|manufacturer|oui)\b", 97),
            ("lookup-mac-inspect", r"\b(?:inspect|correlate|evidence)\b.*\bmac\b|\bmac\b.*\b(?:inspect|correlate|evidence)\b", 96),
            ("lookup-mac-locate", r"\b(?:look\s*up|locate|trace|find|search)\b.*\bmac\b", 95),
            ("lookup-mac", r"\bquery\b.*\bmac\b", 90),
            ("lookup-core", r"\b(?:look\s*up|query|trace)\b.*\bcore\b", 90),
            ("vlan-locate", r"\b(?:locate|find|look\s*up)\b.*\bvlan\b", 90),
            ("vlan-propagation", r"\b(?:trace|check|show)\b.*\bvlan\b.*\bpropagat|\bvlan\s+propagation\b", 91),
            ("db-integrity", r"\b(?:check|verify|run)\b.*\b(?:sqlite|database|db)\b.*\bintegrity\b|\bintegrity\s+check\b", 90),
            ("db-repair", r"\brepair\b.*\b(?:sqlite|database|db)\b", 90),
            ("db-vacuum", r"\b(?:vacuum|compact)\b.*\b(?:sqlite|database|db)\b", 90),
            ("db-migrate", r"\b(?:migrate|initialize|init)\b.*\b(?:sqlite|database|db)\b", 90),
            ("serve-run", r"\b(?:start|run|launch)\b.*\b(?:server|webui|api)\b", 89),
        ]
        scores: Dict[str, int] = {}
        for action, pattern, score in rules:
            if re.search(pattern, lower, re.I):
                scores[action] = max(score, scores.get(action, 0))

        meta_request = bool(re.search(r"\b(?:command|action|tool|preview|prepare|plan|execute|run)\b", lower))
        if meta_request:
            query_tokens = {token for token in self._tokens(lower) if token not in {"the", "a", "an", "please", "command", "action", "tool", "preview", "prepare", "plan", "execute", "run", "netops", "for", "on", "at"}}
            for spec in self.app.command_registry():
                if spec.id == "ask-query":
                    continue
                haystack = " ".join([spec.id.replace("-", " "), spec.label, spec.description, spec.domain, *spec.examples]).lower()
                hay_tokens = set(self._tokens(haystack))
                overlap = len(query_tokens & hay_tokens)
                score = overlap * 10
                if spec.id.replace("-", " ") in lower or spec.label.lower() in lower:
                    score += 150
                if score >= 20:
                    scores[spec.id] = max(score, scores.get(spec.id, 0))
        return sorted(scores.items(), key=lambda item: (-item[1], item[0]))

    def _command_target(self, question: str, action: str) -> str:
        text = self.apply_aliases(question)
        quoted = re.findall(r"['\"]([^'\"]{1,120})['\"]", text)
        if quoted and action not in {"device-show", "device-config"}:
            return quoted[-1].strip()

        specific_patterns = {
            "device-ssh": r"\b(?:ssh(?:\s+to)?|connect(?:\s+to)?|log\s*in\s+to|open\s+(?:an?\s+)?ssh\s+session\s+(?:to)?)\s+(.+)$",
            "backup-run": r"\b(?:back\s+up|take\s+(?:a\s+)?backup\s+(?:of|for)?|run\s+(?:a\s+)?backup\s+(?:of|for)?|start\s+(?:a\s+)?backup\s+(?:of|for)?)\s+(.+)$",
        }
        pattern = specific_patterns.get(action)
        if pattern:
            match = re.search(pattern, text, re.I)
            if match:
                return re.sub(r"\b(?:now|please|online-only|changed-only|over\s+ssh|using\s+ssh)\b", " ", match.group(1), flags=re.I).strip(" ?.!,;:")

        preposition = re.search(r"\b(?:for|against|on|at|from|to)\s+(?:the\s+)?(.+)$", text, re.I)
        if preposition:
            candidate = preposition.group(1)
            candidate = re.sub(r"\b(?:once|twice|\d+\s+(?:times|runs|packets)|with\s+\d+\s+(?:times|runs|packets))\b.*$", " ", candidate, flags=re.I)
            candidate = re.sub(r"\b(?:switch|device|router|site|target)\b\s*$", " ", candidate, flags=re.I)
            if candidate.strip(" ?.!,;:"):
                return candidate.strip(" ?.!,;:")

        text = re.sub(r"(?i)(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}|[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}|[0-9a-f]{12}", " ", text)
        text = re.sub(r"\b(?:gi|gig|gigabit(?:ethernet)?|te|ten|fa|fastethernet|eth|ethernet)\s*\d+(?:/\d+){1,4}\b", " ", text, flags=re.I)
        text = re.sub(r"\bvlan\s+\d{1,4}\b", " ", text, flags=re.I)
        text = re.sub(r"\b\d+\s+(?:times|runs|packets)\b", " ", text, flags=re.I)
        text = re.sub(r"\b(?:please|can you|could you|would you|run|execute|start|launch|trigger|perform|do|scan|discover|rescan|refresh|rebuild|recompute|sync|check|poll|probe|ping|test|measure|diagnose|monitor|sample|watch|look up|lookup|locate|trace|find|back up|backup|take|verify|validate|import|export|migrate|initialize|init|repair|vacuum|compact|connect|ssh|login|log in|open|prepare|plan|preview|now|fast|online|changed|only)\b", " ", text, flags=re.I)
        text = re.sub(r"\b(?:inventory|health|aps?|access points?|topology|lldp|cdp|neighbors?|memory|relationships?|speed|latency|reachability|filtering|dns|tls|mitm|interface|port|core|database|sqlite|db|workflow|audit|morning|server|webui|api|switch|device|router|site|target|the|a|an|for|on|at|from|to|of|all)\b", " ", text, flags=re.I)
        return re.sub(r"\s+", " ", text).strip(" ?.!,;:")

    def _extract_command_args(self, action: str, question: str, session: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        args: Dict[str, Any] = {}
        mac = re.search(r"(?i)(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}|[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}|[0-9a-f]{12}", question)
        ip = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", question)
        interface = re.search(r"\b((?:gi|gig|gigabit(?:ethernet)?|te|ten|fa|fastethernet|eth|ethernet)\s*\d+(?:/\d+){1,4})\b", question, re.I)
        vlan = re.search(r"\bvlan\s*(\d{1,4})\b", question, re.I)
        depth = re.search(r"(?:--depth\s+|\bdepth\s*(?:of|=|:)?\s*|\bup\s+to\s+)(\d+)\b", question, re.I)
        max_nodes = re.search(r"(?:--max-nodes\s+|\bmax(?:imum)?\s+nodes?\s*(?:of|=|:)?\s*)(\d+)\b", question, re.I)
        amount = re.search(r"\b(\d+)\s*(?:times|runs|packets)\b|\b(?:count|runs?|packets?)\s*(?:of|=|:)?\s*(\d+)\b", question, re.I)
        word_amount = re.search(r"\b(one|two|three|four|five|six|seven|eight|nine|ten)\s+(?:times|runs|packets)\b", question, re.I)
        amount_value = (amount.group(1) or amount.group(2)) if amount else ({"one":"1","two":"2","three":"3","four":"4","five":"5","six":"6","seven":"7","eight":"8","nine":"9","ten":"10"}.get(word_amount.group(1).lower()) if word_amount else "")

        if action == "device-show":
            match = re.search(r"\b(?P<command>(?:show|sh|display|get)\s+.+?)\s+(?:on|from|at)\s+(?P<target>.+?)\s*[?.!]*$", question, re.I)
            if match:
                args["command"] = re.sub(r"^\s*(?:run|execute)\s+", "", match.group("command"), flags=re.I).strip()
                args["target"] = self.apply_aliases(match.group("target").strip(" ?.!,;:"))
        elif action == "device-config":
            quoted = re.findall(r"['\"]([^'\"]{1,240})['\"]", question)
            if quoted:
                args["commands"] = quoted if len(quoted) > 1 else quoted[0]
        elif action.startswith("device-trust-"):
            fingerprint = re.search(r"\bSHA256:[A-Za-z0-9+/]{8,}={0,2}\b", question)
            if fingerprint:
                args["fingerprint"] = fingerprint.group(0)
        elif action in {"vlan-set", "vlan-locate", "vlan-propagation"}:
            if not vlan:
                vlan = re.search(r"\b(?:propagation|propagate|locate)\b[^\d]{0,80}(\d{1,4})\b", question, re.I)
            if vlan:
                args["vlan"] = vlan.group(1)
            if action in {"vlan-locate", "vlan-propagation"}:
                if depth:
                    args["depth"] = depth.group(1)
                if max_nodes:
                    args["max_nodes"] = max_nodes.group(1)
                if re.search(r"\b(?:refresh|live|query)\s+(?:the\s+)?(?:lldp|cdp|neighbors?)\b|--refresh-neighbors\b", question, re.I):
                    args["refresh_neighbors"] = True
            if action == "vlan-set":
                args["vlan_mode"] = "trunk" if re.search(r"\btrunk\b", question, re.I) else "access"
                if interface:
                    args["interface"] = interface.group(1).replace(" ", "")
            target_match = re.search(r"\b(?:on|at|from)\s+(.+?)(?:\s+(?:for\s+vlan|to\s+depth|with\s+depth|to|as|with)\b|[?.!]|$)", question, re.I)
            if target_match:
                args["target"] = self.apply_aliases(target_match.group(1).strip())
            elif action in {"vlan-locate", "vlan-propagation"}:
                cli_style = re.search(r"\b(?:locate|propagation|propagate)\s+(?!vlan\b)([A-Za-z0-9_.:/-]{2,80})\s+(?:vlan\s*)?\d{1,4}\b", question, re.I)
                if cli_style:
                    args["target"] = self.apply_aliases(cli_style.group(1).strip())
        elif action in {"diagnose-interface", "diagnose-port-health", "diagnose-cable", "diagnose-cable-test"}:
            target_match = re.search(r"\b(?:on|at|from)\s+(.+?)(?:\s+(?:once|with|using)|[?.!]|$)", question, re.I)
            if target_match:
                device = target_match.group(1).strip()
                if interface:
                    device = re.sub(
                        rf"\s+(?:(?:port|interface)\s+)?{re.escape(interface.group(1))}\s*$",
                        "",
                        device,
                        flags=re.I,
                    ).strip()
                if device:
                    args["device"] = self.apply_aliases(device)
            cli_match = re.search(r"\b(?:port[- ]health|cable|tdr)\s+([A-Za-z0-9_.:/-]{2,80})\s+(?:on\s+)?(?:port\s+|interface\s+)?((?:gi|gig|gigabit(?:ethernet)?|te|ten|fa|fastethernet|eth|ethernet)?\s*\d+(?:/\d+){0,4})\b", question, re.I)
            if cli_match:
                args["device"] = self.apply_aliases(cli_match.group(1).strip())
                args["interface"] = cli_match.group(2).replace(" ", "")
            if interface:
                args["interface"] = interface.group(1).replace(" ", "")
            if action == "diagnose-interface" and re.search(r"\bonce\b", question, re.I):
                args["once"] = True
            chart = re.search(r"\b(classic|histogram)\b", question, re.I)
            if action == "diagnose-interface" and chart:
                args["chart"] = chart.group(1).lower()
            sample = re.search(r"\b(?:sample|observe)(?:\s+for)?\s+(\d+)\s*(?:seconds?|s)\b", question, re.I)
            expected = re.search(r"\bexpected(?:\s+speed)?\s*(?:of|=|:)?\s*(\d+)\s*(?:mbps|meg)", question, re.I)
            wait = re.search(r"\bwait\s+(\d+)\s*(?:seconds?|s)?\b", question, re.I)
            if action == "diagnose-port-health":
                if sample: args["sample_seconds"] = sample.group(1)
                if expected: args["expected_speed"] = expected.group(1)
            if action == "diagnose-cable-test" and wait:
                args["wait"] = wait.group(1)
        elif action == "diagnose-throughput":
            server = re.search(
                r"\b(?:iperf3?(?:\s+throughput)?|throughput(?:\s+test)?)\s+"
                r"(?:to|against|on|with)\s+(?:the\s+)?(?:server\s+)?([A-Za-z0-9_.:-]{2,120})\b",
                question,
                re.I,
            )
            if not server:
                server = re.search(r"\b(?:iperf3?\s+server|server)\s+([A-Za-z0-9_.:-]{2,120})\b", question, re.I)
            if not server:
                server = re.search(r"\biperf3?\s+(?!throughput\b|server\b)([A-Za-z0-9_.:-]{2,120})\b", question, re.I)
            if server:
                args["target"] = self.apply_aliases(server.group(1).strip())
            elif ip:
                args["target"] = ip.group(0)
            port_match = re.search(r"\bport\s*(?:=|:)?\s*(\d{1,5})\b", question, re.I)
            seconds_match = re.search(r"\b(?:for|duration)\s*(\d+)\s*(?:seconds?|s)\b", question, re.I)
            parallel_match = re.search(r"\b(\d+)\s*(?:parallel\s+)?streams?\b|\bparallel\s*(?:=|:)?\s*(\d+)\b", question, re.I)
            direction_match = re.search(r"\b(upload|download|both(?: directions?)?)\b", question, re.I)
            if port_match: args["port"] = port_match.group(1)
            if seconds_match: args["seconds"] = seconds_match.group(1)
            if parallel_match: args["parallel"] = parallel_match.group(1) or parallel_match.group(2)
            if direction_match: args["direction"] = "both" if direction_match.group(1).lower().startswith("both") else direction_match.group(1).lower()
        elif action in {"lookup-mac", "lookup-mac-inspect", "lookup-mac-locate", "lookup-mac-profile", "lookup-mac-history", "lookup-mac-vendor"}:
            if mac:
                args["mac"] = mac.group(0)
            if action == "lookup-mac" and re.search(r"\b(?:all|every)\s+(?:switch|device)", question, re.I):
                args["target"] = "all"
            if action in {"lookup-mac-locate", "lookup-mac-profile"}:
                scope_match = re.search(r"\b(?:on|at|from|within)\s+(?:the\s+)?(?:switch|site)?\s*([A-Za-z0-9_.:/-]{2,80})\b", question, re.I)
                if scope_match and scope_match.group(1).lower() not in {"all", "every"}:
                    args["scope"] = self.apply_aliases(scope_match.group(1).strip())
        elif action in {"ask-alias-set", "ask-alias-remove"}:
            quoted = re.findall(r"['\"]([^'\"]{1,160})['\"]", question)
            if quoted:
                args["phrase"] = quoted[0]
                if action == "ask-alias-set" and len(quoted) > 1:
                    args["alias_target"] = quoted[1]
            if not args.get("phrase"):
                if action == "ask-alias-set":
                    alias_match = re.search(r"\balias\s+(.+?)\s+(?:to|as|=)\s+(.+?)[?.!]*$", question, re.I)
                    if alias_match:
                        args["phrase"] = alias_match.group(1).strip()
                        args["alias_target"] = alias_match.group(2).strip()
                else:
                    alias_match = re.search(r"\balias\s+(.+?)[?.!]*$", question, re.I)
                    if alias_match:
                        args["phrase"] = alias_match.group(1).strip()
        elif action == "commands-show":
            for spec in self.app.command_registry():
                if spec.id in question.lower():
                    args["action"] = spec.id
                    break

        if action in {"diagnose-latency", "diagnose-core-ping"} and amount_value:
            args["count"] = amount_value
        if action == "diagnose-speed":
            if re.search(r"\b(?:quick|fast|faster|rapid)\b", question, re.I):
                args["profile"] = "quick"
            elif re.search(r"\b(?:thorough|full|deep|high[- ]confidence|most accurate)\b", question, re.I):
                args["profile"] = "thorough"
            elif re.search(r"\bbalanced\b", question, re.I):
                args["profile"] = "balanced"
            if amount_value:
                args["runs"] = amount_value
        if action == "diagnose-doctor" and re.search(r"\bonline\b|\bverify\s+(?:tls|internet|server)", question, re.I):
            args["online"] = True
        if action == "lookup-core" and mac:
            args["target"] = mac.group(0)
        if action == "diagnose-core-ping":
            destination = re.search(r"\b(?:point[- ]of[- ]truth\s+ping|core[- ]origin(?:ated)?\s+ping|ping)\s+(?:the\s+)?(?:device\s+)?([A-Za-z0-9_.:/-]{2,80})", question, re.I)
            if destination and destination.group(1).lower() not in {"from", "using", "core"}:
                args["target"] = self.apply_aliases(destination.group(1).strip())
            elif ip:
                args["target"] = ip.group(0)
            core_match = re.search(r"\bfrom\s+(?:the\s+)?core(?:\s+switch)?(?:\s+at|\s+on|\s+named)?\s+([A-Za-z0-9_.:/-]{2,80})\b", question, re.I)
            if core_match:
                args["core"] = self.apply_aliases(core_match.group(1).strip())

        target_actions = {
            "inventory-scan", "inventory-list", "inventory-details", "inventory-activity",
            "health-check", "health-status", "health-offline", "health-timeline", "ap-list", "ap-unjoined", "ap-on-switch", "ap-timeline", "ap-controller",
            "topology-show", "topology-timeline", "memory-switch", "memory-device", "memory-ip", "memory-mac",
            "memory-timeline", "memory-explain", "backup-run", "backup-history", "backup-diff", "diagnose-latency", "diagnose-filtering",
            "diagnose-core-ping", "diagnose-throughput", "lookup-core", "device-ssh", "device-inventory", "device-trust-status", "device-trust-scan", "device-trust-enroll", "device-trust-forget", "workflow-backup-online", "workflow-site-health",
        }
        if action in target_actions and not args.get("target"):
            if action in {"diagnose-latency", "lookup-core"} and ip:
                args["target"] = ip.group(0)
            elif action == "memory-mac" and mac:
                args["target"] = mac.group(0)
            else:
                target = self._command_target(question, action)
                if target:
                    args["target"] = target
        if action in {"diagnose-interface", "diagnose-port-health", "diagnose-cable", "diagnose-cable-test"} and not args.get("device"):
            target = self._command_target(question, action)
            if target:
                args["device"] = target
        if action in {"vlan-set", "vlan-locate", "vlan-propagation"} and not args.get("target"):
            target = self._command_target(question, action)
            if target:
                args["target"] = target
        if action == "device-config" and not args.get("target"):
            target = self._command_target(question, action)
            if target:
                args["target"] = target
        device_actions = {"diagnose-interface", "diagnose-port-health", "diagnose-cable", "diagnose-cable-test"}
        if session and not any(args.get(key) for key in ("target", "device")) and session.get("last_target") and action in target_actions | device_actions | {"device-config", "vlan-set", "vlan-locate", "vlan-propagation"}:
            args["device" if action in device_actions else "target"] = session["last_target"]
        return {key: value for key, value in args.items() if value not in (None, "", [])}

    def _plan_command(self, question: str, session: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        matches = self._command_matches(question)
        if not matches:
            return None
        action = matches[0][0]
        spec = self.app.command_spec(action)
        if not spec:
            return None
        args = self._extract_command_args(action, question, session)
        preview = self.app.preview_for_action(action, args)
        missing = preview.get("missing_args") or []
        if missing:
            status = "needs_clarification"
            answer = f"I matched this to {spec.label}, but I still need: {', '.join(missing)}."
        elif preview.get("validation_error"):
            status = "blocked"
            answer = f"The {spec.label} request was blocked by validation: {preview['validation_error']}."
        elif not spec.run_supported or spec.risk_level in {"config", "danger"}:
            status = "preview_only"
            answer = f"Prepared a preview-only {spec.label} plan. {preview.get('reason') or ''}".strip()
        else:
            status = "ready"
            answer = f"Prepared {spec.label}. Review the exact command and safety class before execution."
        confirmation = spec.effective_safety_class() != "read-only"
        if status == "ready":
            execution_hint = f"netrune ask --execute{' --confirm' if confirmation else ''} {shlex.quote(question)}"
        else:
            execution_hint = preview.get("command") if spec.output_type == "terminal" else ""
        alternatives = []
        for alternative, score in matches[1:4]:
            if score < 30:
                continue
            other = self.app.command_spec(alternative)
            if other:
                alternatives.append({"action": other.id, "label": other.label, "score": score})
        plan = {
            "action": spec.id,
            "label": spec.label,
            "description": spec.description,
            "args": args,
            "command": preview.get("command"),
            "status": status,
            "missing_args": missing,
            "read_only": spec.read_only,
            "writes_local": spec.writes_local,
            "risk_level": spec.risk_level,
            "safety_class": spec.effective_safety_class(),
            "state_effects": spec.effective_state_effects(),
            "output_type": spec.output_type,
            "run_supported": spec.run_supported and not bool(preview.get("validation_error")),
            "requires_confirmation": confirmation,
            "reason": preview.get("reason") or "",
            "execution_hint": execution_hint,
            "alternatives": alternatives,
        }
        return self._response(
            question,
            "command_plan",
            answer,
            [],
            self._workflow(("language", "classify operational request"), ("command_registry", f"select registered action {spec.id}"), ("argument_parser", "extract and validate structured arguments"), ("safety_policy", f"classify {spec.effective_safety_class()} and generate preview")),
            mode="command",
            command_plan=plan,
            suggestions=[],
        )

    def _command_followup(self, question: str, session: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if not isinstance(session, dict) or not isinstance(session.get("last_command_plan"), dict):
            return None
        if not re.search(r"\b(?:run|execute|do|preview|show|that|it|plan|command|change|use|set)\b", question, re.I):
            return None
        plan = json.loads(json.dumps(session["last_command_plan"]))
        change = re.search(r"\b(?:change|use|set)\s+(?:the\s+)?(?:target|device|site)\s+(?:to|as)\s+(.+)$", question, re.I)
        if change:
            key = "device" if "device" in (plan.get("args") or {}) and "target" not in (plan.get("args") or {}) else "target"
            plan.setdefault("args", {})[key] = self.apply_aliases(change.group(1).strip(" ?.!,;:"))
            preview = self.app.preview_for_action(str(plan.get("action") or ""), plan["args"])
            plan.update({"command": preview.get("command"), "missing_args": preview.get("missing_args") or []})
            plan["status"] = "needs_clarification" if plan["missing_args"] else ("preview_only" if not plan.get("run_supported") else "ready")
            answer = f"Updated the {plan.get('label')} plan for {plan['args'][key]}."
        elif re.search(r"\b(?:run|execute|do)\s+(?:that|it|the plan|the command)?\b", question, re.I):
            answer = "The plan is ready for explicit execution." if plan.get("status") == "ready" else "The previous plan cannot execute until its missing inputs or safety restriction are resolved."
        else:
            answer = "Here is the previous command plan and exact preview."
        return self._response(
            question,
            "command_followup",
            answer,
            [],
            self._workflow(("session", "reuse previous registered command plan"), ("safety_policy", "preserve explicit execution boundary")),
            mode="command",
            command_plan=plan,
            suggestions=[],
        )

    def _session_followup(self, question: str, session: Optional[Dict[str, Any]], limit: int) -> Optional[Dict[str, Any]]:
        if not isinstance(session, dict):
            return None
        command_followup = self._command_followup(question, session)
        if command_followup:
            return command_followup
        previous = session.get("last_result") if isinstance(session.get("last_result"), dict) else {}
        rows = [dict(row) for row in previous.get("rows") or [] if isinstance(row, dict)]
        if not rows or not re.search(r"\b(them|those|these|their|the list|that list|ones|same)\b", question, re.I):
            return None
        status = self._extract_status(question)
        rows = self._filter_status(rows, status)
        if re.search(r"\b(model|platform)\b", question, re.I):
            answer = "; ".join(f"{self._entity_label(row)}: {row.get('model') or row.get('platform') or 'unknown'}" for row in rows[:limit]) + "."
        elif re.search(r"\bip(?:s| addresses?)?\b", question, re.I):
            answer = "; ".join(f"{self._entity_label(row)}: {row.get('ip') or 'unknown'}" for row in rows[:limit]) + "."
        elif re.search(r"\b(where|connected|attached|switch|port)\b", question, re.I):
            answer = "; ".join(f"{self._entity_label(row)}: {row.get('switch_name') or row.get('switch_ip') or 'unknown switch'}, {row.get('switch_port') or 'unknown port'}" for row in rows[:limit]) + "."
        elif self._wants_count(question) or re.search(r"\b(health|status|online|offline|up|down)\b", question, re.I):
            counts = self._counts(rows)
            health = ", ".join(f"{value} {key.lower()}" for key, value in counts.items() if value)
            answer = f"{len(rows)} records from the previous result" + (f"; {health}" if health else "") + "."
        else:
            answer = f"{len(rows)} records: " + ", ".join(self._entity_label(row) for row in rows[:limit]) + "."
        return self._response(
            question,
            "session_followup",
            answer,
            rows,
            self._workflow(("session", "reuse previous deterministic result set"), ("filters", f"apply status={status or 'all'}")),
        )

    def ask(self, question: str, opts: Any, session: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        raw = str(question or "").strip()
        if not raw:
            return {"ok": False, "error": "Ask a question or run: netrune ask patterns"}
        question = self._normalize_question(raw)
        lower = question.lower()
        limit = max(1, min(int(getattr(opts, "limit", 100) or 100), 500))

        followup = self._session_followup(question, session, limit)
        if followup:
            return followup

        command_plan = self._plan_command(question, session)
        if command_plan:
            return command_plan

        mac_match = re.search(r"(?i)(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}|[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}|[0-9a-f]{12}", question)
        ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", question)
        port_match = re.search(r"\b((?:gi|gig|gigabit(?:ethernet)?|te|ten|fa|fastethernet|eth|ethernet)\s*\d+(?:/\d+){1,4})\b", question, re.I)
        plain_port_match = re.search(r"\bport\s*(\d{1,3})\b", question, re.I)
        explicit_ap = re.search(r"\b[A-Za-z0-9][A-Za-z0-9_.-]*AP\d+[A-Za-z0-9_.-]*\b", question, re.I)

        if re.search(r"\b(?:same AP|AP aliases?|alternate AP names?|canonical AP|merged AP|duplicate AP|AP identity|multiple IPs?)\b", question, re.I):
            return self._ask_ap_aliases(question, limit)

        if re.search(r"\b(?:unjoined|not joined|nonjoined|awaiting join|unregistered)\b", lower) and re.search(r"\b(?:aps?|access points?|wireless|wlc|controller)\b", lower):
            return self._ask_unjoined_aps(question, limit)

        if re.search(r"\b(?:needs? attention|warnings?|alerts?|outstanding issues?|network problems?|what failed|important changes?)\b", lower):
            return self._ask_attention(question, limit)

        if re.search(r"\b(?:topology|links?|neighbors?|upstream|downstream)\b", lower) and re.search(r"\b(?:changes?|changed|events?|new|added|removed|disappeared)\b", lower):
            return self._ask_topology_changes(question, limit)

        if re.search(r"\b(?:aps?|access points?|wireless)\b", lower) and re.search(r"\b(?:moves?|moved|movement|changed (?:switch|port)|attachment changes?)\b", lower):
            return self._ask_ap_moves(question, limit)

        if re.search(r"\b(?:backups?|backed up|config backup|configuration backup)\b", lower):
            return self._ask_backup_history(question, limit)

        if re.search(r"\b(?:diagnostics?|latency results?|speed tests?|packet loss|jitter|filtering checks?|interface utilization|dns checks?|tls checks?)\b", lower):
            return self._ask_diagnostic_history(question, limit)

        if re.search(r"\b(?:jobs?|operations?|workflows?)\b", lower) and re.search(r"\b(?:running|pending|queued|failed|completed|finished|cancelled|canceled|recent|latest|status|result|list|show|what)\b", lower):
            return self._ask_jobs(question, limit)

        switch_query = self._extract_ap_switch_query(question)
        if switch_query:
            return self._ask_ap_on_switch(question, switch_query, limit)

        port_value = port_match.group(1).replace(" ", "") if port_match else (plain_port_match.group(1) if plain_port_match else "")
        port_token = port_match or plain_port_match
        if port_token and re.search(r"\b(on|of|from|at)\b", question, re.I):
            tail = question[port_token.end():]
            switch = re.sub(r"^\s*(?:on|of|from|at)\s+", "", tail, flags=re.I).strip(" ?.!,;:")
            switch = re.sub(r"\b(?:switch|device|router)\b", " ", switch, flags=re.I)
            switch = re.sub(r"\s+", " ", switch).strip()
            if switch:
                return self._ask_port(question, switch, port_value, limit)

        if explicit_ap and (self._is_past(question) or re.search(r"\b(where|connected|attached|which switch|which port|location|plugged)\b", question, re.I)):
            if re.search(r"\b(?:called|named|rename|identity|older names?|previous names?|versions?|changed details?|IPs? used)\b", lower):
                return self._ask_identity_history(question, explicit_ap.group(0), limit)
            return self._ask_ap_location(question, explicit_ap.group(0), limit)

        if mac_match and re.search(r"\b(where|history|timeline|which|what|who|find|locate|seen|belongs|moved|names?|ips?|ports?)\b", question, re.I):
            return self._ask_ip_or_mac(question, mac_match.group(0), "mac", limit)

        if ip_match and re.search(r"\b(who|which|what|history|timeline|used|owns?|belong|previous|changed|names?|macs?)\b", question, re.I):
            return self._ask_ip_or_mac(question, ip_match.group(0), "ip", limit)

        if re.search(r"\b(?:rename|renamed|called before|named before|identity history|older names?|previous names?|previous versions?|record history|what ips? has|serial.*changed|model.*changed)\b", lower):
            target = explicit_ap.group(0) if explicit_ap else self._target_from_question(
                question,
                (r"\b(?:rename|renamed|called|named|before|identity|history|older|previous|names?|versions?|records?|what|ips?|has|used|serial|model|changed|change)\b",),
            )
            if target:
                return self._ask_identity_history(question, target, limit)

        if re.search(r"\b(?:summarize|summary|overview|what do we know|switch context|memory summary)\b", lower):
            target = self._target_from_question(question, (r"\b(?:summarize|summary|overview|what do we know|switch context|memory|switch|device|context)\b",))
            if target:
                return self._ask_switch_summary(question, target, limit)

        if re.search(r"\b(neighbors?|downstream|upstream|topology|lldp|cdp|what is connected|what's connected|connected devices?|devices? connected|links? around)\b", question, re.I):
            target = self._target_from_question(question, (r"\b(?:neighbors?|downstream|upstream|devices?|topology|lldp|cdp|connected|connects?|links?|switch)\b",))
            if target:
                return self._ask_topology(question, target, limit)

        health_specific = re.search(r"\b(?:health|flapping|flaps?|stale|outages?|not seen|old inventory)\b", lower)
        generic_state = re.search(r"\b(?:offline|online|unreachable|reachable|down|up)\b", lower) and not re.search(r"\b(?:aps?|access points?|switches|routers|network devices)\b", lower)
        if health_specific or generic_state:
            return self._ask_health(question, limit)

        if re.search(r"\b(?:aps?|access points?)\b", question, re.I):
            target = self._extract_collection_target(question, r"\b(?:aps?|access points?)\b")
            rows = self._all_aps()
            if target:
                rows = self._ranked_matches(rows, target, 500, spread=14)
            return self._collection_answer(question, "ap_inventory", rows, "APs", target, limit)

        if re.search(r"\b(?:switches|routers|network devices)\b", question, re.I):
            target = self._extract_collection_target(question, r"\b(?:switches|routers|network devices)\b")
            rows = self._all_devices()
            if target:
                rows = self._ranked_matches(rows, target, 500, spread=14)
            return self._collection_answer(question, "switch_inventory", rows, "switches", target, limit)

        field_match = re.search(r"\b(?:ip|mac|model|platform|status|health|details?|tell me about|last seen|aliases?|called now)\b", question, re.I)
        if field_match:
            target = self._target_from_question(
                question,
                (r"\b(?:ip|mac|address|addresses|model|platform|status|health|details?|online|offline|up|down|switch|device|AP|last seen|aliases?|called|now|current name)\b",),
            )
            if target:
                return self._ask_details(question, target, limit)

        target = self._target_from_question(question)
        if target:
            return self._ask_details(question, target, limit)
        return {
            "ok": False,
            "error": "That wording does not match a predefined Natural Ask workflow.",
            "suggestions": [item["examples"][0] for item in QUESTION_PATTERNS[:8]],
        }

    def update_session(self, question: str, payload: Dict[str, Any], session: Dict[str, Any]) -> None:
        result = payload.get("result") if isinstance(payload.get("result"), dict) else {}
        rows = [dict(row) for row in result.get("rows") or [] if isinstance(row, dict)]
        if rows:
            session["last_result"] = {"rows": rows[:250], "count": result.get("count", len(rows)), "question": question}
            if len(rows) == 1:
                session["last_target"] = self._entity_label(rows[0])
        selected = payload.get("selected") if isinstance(payload.get("selected"), dict) else {}
        if selected:
            session["last_target"] = self._entity_label(selected)
        plan = payload.get("command_plan") if isinstance(payload.get("command_plan"), dict) else None
        if plan:
            session["last_command_plan"] = json.loads(json.dumps(plan))
            args = plan.get("args") if isinstance(plan.get("args"), dict) else {}
            if args.get("target") or args.get("device"):
                session["last_target"] = args.get("target") or args.get("device")
        history = session.setdefault("history", [])
        history.append({"question": question, "intent": payload.get("intent"), "answer": payload.get("answer") or payload.get("error")})
        del history[:-20]
