"""Headless application service consumed by the CLI and Textual console."""

from __future__ import annotations

import csv
import getpass
import json
import os
from pathlib import Path
import re
import tempfile
import time
import uuid
from typing import Any, Iterable, Mapping, Sequence

from netops_platform.core import GlobalOptions, fmt_time

from .contracts import (
    ActionPreviewV1,
    ColumnSpec,
    DatasetV1,
    Finding,
    JobEventV1,
    OperatorContext,
    Provenance,
    QuerySpec,
    ResultEnvelopeV1,
    columns_for_rows,
)


VIEW_TITLES = {
    "overview": "Operations Overview",
    "inventory": "Inventory",
    "topology": "Topology and VLAN",
    "diagnostics": "Diagnostics",
    "operations": "Action Hub",
    "history": "History and Audit",
    "settings": "Settings and Readiness",
}

PREFERRED_COLUMNS: dict[str, Sequence[str]] = {
    "inventory": ("status", "kind", "name", "ip", "platform", "model", "switch_name", "switch_port", "last_seen"),
    "attention": ("level", "kind", "title", "text"),
    "jobs": ("status", "action", "created_at", "started_at", "finished_at", "duration_ms", "exit_code", "actor"),
    "topology": ("local_name", "local_ip", "local_port", "remote_name", "remote_port", "remote_ip", "last_seen"),
    "diagnostic_runs": ("status", "kind", "target", "source", "summary", "created_at"),
    "audit": ("created_at", "actor", "event_type", "action", "target", "result", "reason", "ticket"),
    "scan_runs": ("status", "domain", "mode", "complete", "source", "started_at", "finished_at", "detail"),
    "commands": ("label", "domain", "safety_class", "run_supported", "output_view", "description", "id"),
    "speed_tests": ("status", "profile", "download_mbps", "upload_mbps", "latency_ms", "jitter_ms", "created_at"),
    "probes": ("status", "target", "source", "loss_pct", "avg_ms", "min_ms", "max_ms", "created_at"),
    "interface_samples": ("status", "device", "interface", "in_bps", "out_bps", "created_at"),
    "topology_changes": ("event_type", "local_ip", "local_port", "remote_name", "remote_port", "created_at"),
    "relationship_history": ("created_at", "event_type", "subject_type", "subject_id", "object_type", "object_id", "detail"),
    "inventory_history": ("created_at", "event_type", "entity_type", "entity_id", "name", "detail"),
    "health_history": ("created_at", "event_type", "entity_type", "entity_id", "status", "detail"),
}


def _status(payload: Mapping[str, Any]) -> str:
    if payload.get("blocked") or payload.get("ok") is False:
        return "failed"
    if payload.get("status") in {"PARTIAL", "ATTENTION", "partial"}:
        return "partial"
    return "success"


def _finding(value: Mapping[str, Any]) -> Finding:
    return Finding(
        severity=str(value.get("severity") or value.get("level") or "info").lower(),
        code=str(value.get("code") or value.get("kind") or "FINDING"),
        message=str(value.get("message") or value.get("detail") or value.get("text") or value.get("title") or ""),
        target=str(value.get("target") or value.get("device") or value.get("switch_name") or ""),
        remediation=str(value.get("remediation") or value.get("next_step") or ""),
        evidence=dict(value),
    )


class NetOpsService:
    """Single application boundary for queries, previews, jobs, and exports."""

    def __init__(self, core: Any):
        self.core = core
        self.session_id = uuid.uuid4().hex[:12]

    def operator_context(self, reason: str = "", ticket: str = "") -> OperatorContext:
        return OperatorContext(
            actor=getpass.getuser() or str(os.getuid()),
            uid=os.getuid(),
            session_id=self.session_id,
            reason=reason.strip(),
            ticket=ticket.strip(),
        )

    def _dataset(
        self,
        dataset_id: str,
        title: str,
        rows: Iterable[Mapping[str, Any]],
        *,
        row_key: str = "",
        actions: Sequence[str] = (),
    ) -> DatasetV1:
        materialized = [dict(row) for row in rows]
        preferred = PREFERRED_COLUMNS.get(dataset_id, ())
        columns = columns_for_rows(materialized, preferred)
        if not columns and preferred:
            columns = columns_for_rows([{key: None for key in preferred}], preferred)
        return DatasetV1(
            id=dataset_id,
            title=title,
            rows=materialized,
            columns=columns,
            row_key=row_key,
            row_actions=list(actions),
        )

    @staticmethod
    def _latest_time(rows: Iterable[Mapping[str, Any]]) -> int | None:
        fields = ("observed_at", "created_at", "last_seen", "updated_at", "finished_at", "started_at")
        latest = 0
        for row in rows:
            for field in fields:
                try:
                    latest = max(latest, int(row.get(field) or 0))
                except (TypeError, ValueError):
                    continue
        return latest or None

    @staticmethod
    def _freshness(observed_at: int | None) -> str:
        if not observed_at:
            return "unknown"
        age = max(0, int(time.time()) - observed_at)
        if age <= 300:
            return "fresh"
        if age <= 3600:
            return "recent"
        if age <= 86400:
            return "aging"
        return "stale"

    def _envelope(
        self,
        action_id: str,
        title: str,
        *,
        summary: str = "",
        metrics: Mapping[str, Any] | None = None,
        datasets: Sequence[DatasetV1] = (),
        findings: Iterable[Mapping[str, Any]] = (),
        raw: Mapping[str, Any] | None = None,
        source: str = "sqlite",
        complete: bool | None = None,
    ) -> ResultEnvelopeV1:
        latest = self._latest_time(row for dataset in datasets for row in dataset.rows)
        materialized_findings = [_finding(item) for item in findings]
        status = "partial" if any(item.severity in {"warning", "error", "critical", "danger"} for item in materialized_findings) else "success"
        return ResultEnvelopeV1(
            action_id=action_id,
            status=status,
            title=title,
            summary=summary,
            metrics=dict(metrics or {}),
            datasets=list(datasets),
            findings=materialized_findings,
            provenance=Provenance(
                source=source,
                observed_at=latest,
                observed_at_iso=fmt_time(latest),
                complete=complete,
                freshness=self._freshness(latest),
            ),
            raw=dict(raw or {}),
        )

    def query(self, view_id: str, spec: QuerySpec | None = None) -> ResultEnvelopeV1:
        spec = spec or QuerySpec()
        view_id = view_id if view_id in VIEW_TITLES else "overview"
        handler = getattr(self, f"_query_{view_id}")
        return handler(spec)

    def _query_overview(self, spec: QuerySpec) -> ResultEnvelopeV1:
        counts = self.core.state.counts()
        attention = self.core.attention_payload(min(spec.limit, 300))
        jobs = self.core.jobs_list()[: min(spec.limit, 100)]
        health = self.core.health_summary_payload("", GlobalOptions(limit=min(spec.limit, 300)))
        diagnostics = self.core.diagnostics_payload(min(spec.limit, 100))
        latest_scan = self.core.state.rows(
            "SELECT domain,mode,status,complete,source,started_at,finished_at,detail FROM scan_runs ORDER BY started_at DESC LIMIT 20"
        )
        datasets = [
            self._dataset("attention", "Attention Queue", attention.get("items") or [], actions=("inspect", "refresh")),
            self._dataset("jobs", "Recent Jobs", jobs, row_key="id", actions=("open-job", "cancel-job", "rerun")),
            self._dataset("scan_runs", "Source Freshness", latest_scan, actions=("refresh",)),
        ]
        metrics = {
            "devices": counts.get("devices", 0),
            "access_points": counts.get("aps", 0),
            "offline": health.get("counts", {}).get("OFFLINE", 0),
            "attention": len(attention.get("items") or []),
            "running_jobs": counts.get("running_jobs", 0),
            "job_issues": counts.get("partial_jobs", 0) + counts.get("failed_jobs", 0),
            "diagnostic_runs": diagnostics.get("summary", {}).get("counts", {}).get("diagnostic_runs", 0),
        }
        return self._envelope(
            "view-overview",
            VIEW_TITLES["overview"],
            summary="Current canonical state, attention signals, job activity, and source freshness.",
            metrics=metrics,
            datasets=datasets,
            findings=attention.get("items") or [],
            raw={"counts": counts, "health": health, "diagnostics": diagnostics.get("summary", {})},
            complete=None,
        )

    def _query_inventory(self, spec: QuerySpec) -> ResultEnvelopeV1:
        rows = self.core.inventory_rows(spec.query, GlobalOptions(limit=max(1, min(spec.limit + spec.offset, 5000))))
        rows = self._apply_query(rows, spec)
        dataset = self._dataset(
            "inventory",
            "Canonical Devices and Access Points",
            rows,
            row_key="ip",
            actions=("inspect", "health-check", "core-ping", "memory", "ssh", "backup"),
        )
        metrics = {
            "shown": len(rows),
            "online": sum(str(row.get("status") or "").upper() == "ONLINE" for row in rows),
            "offline": sum(str(row.get("status") or "").upper() == "OFFLINE" for row in rows),
            "devices": sum(row.get("kind") == "device" for row in rows),
            "access_points": sum(row.get("kind") == "ap" for row in rows),
        }
        return self._envelope("view-inventory", VIEW_TITLES["inventory"], summary="Searchable canonical inventory.", metrics=metrics, datasets=[dataset])

    def _query_topology(self, spec: QuerySpec) -> ResultEnvelopeV1:
        payload = self.core.topology_graph_payload(max(spec.limit, 500))
        edges = self._apply_query(payload.get("raw_edges") or [], spec)
        changes = self.core.state.rows(
            "SELECT * FROM topology_events ORDER BY created_at DESC,id DESC LIMIT ?",
            (min(spec.limit, 300),),
        )
        datasets = [
            self._dataset("topology", "Neighbor Links", edges, actions=("inspect-switch", "vlan-trace", "health-check")),
            self._dataset("topology_changes", "Recent Topology Changes", changes),
        ]
        return self._envelope(
            "view-topology",
            VIEW_TITLES["topology"],
            summary="Core-rooted topology evidence and recent link changes.",
            metrics={"nodes": len(payload.get("nodes") or []), "links": len(payload.get("edges") or []), "changes": len(changes)},
            datasets=datasets,
            raw={"nodes": payload.get("nodes") or [], "edges": payload.get("edges") or [], "root": payload.get("root") or ""},
        )

    def _query_diagnostics(self, spec: QuerySpec) -> ResultEnvelopeV1:
        payload = self.core.diagnostics_payload(min(spec.limit, 300))
        datasets = [
            self._dataset("diagnostic_runs", "Diagnostic Runs", payload.get("diagnostic_runs") or [], row_key="id", actions=("inspect", "rerun")),
            self._dataset("speed_tests", "Internet Speed", payload.get("speed_tests") or [], row_key="id"),
            self._dataset("probes", "Latency", payload.get("probes") or [], row_key="id"),
            self._dataset("interface_samples", "Interface Samples", payload.get("interface_samples") or [], row_key="id"),
        ]
        counts = payload.get("summary", {}).get("counts", {})
        return self._envelope(
            "view-diagnostics",
            VIEW_TITLES["diagnostics"],
            summary="Historical measurements and guided network diagnostic entry points.",
            metrics=counts,
            datasets=datasets,
            raw=payload.get("summary", {}),
        )

    def _query_operations(self, spec: QuerySpec) -> ResultEnvelopeV1:
        jobs = self._apply_query(self.core.jobs_list(), spec)
        registry = self.registry()
        command_rows = [
            {
                "id": item["id"],
                "label": item["label"],
                "domain": item["domain"],
                "safety_class": item["safety_class"],
                "run_supported": item["run_supported"],
                "output_view": item["output_view"],
                "description": item["description"],
            }
            for item in registry
        ]
        commands = self._dataset("commands", "Action Catalog", command_rows, row_key="id", actions=("open-action", "preview"))
        commands.columns = [
            ColumnSpec("label", "Action", priority=0),
            ColumnSpec("domain", "Function", priority=1),
            ColumnSpec("safety_class", "Safety", priority=2),
            ColumnSpec("description", "Purpose", priority=3),
        ]
        return self._envelope(
            "view-operations",
            VIEW_TITLES["operations"],
            summary="Search and run registered commands, diagnostics, and workflows.",
            metrics={"registered_actions": len(registry), "jobs": len(jobs), "running": sum(row.get("status") in {"queued", "running", "cancelling"} for row in jobs)},
            datasets=[
                commands,
                self._dataset("jobs", "Jobs", jobs, row_key="id", actions=("open-job", "cancel-job", "rerun")),
            ],
        )

    def _query_history(self, spec: QuerySpec) -> ResultEnvelopeV1:
        relationships = self.core.relationship_timeline_payload(spec.query, min(spec.limit, 500)).get("rows") or []
        inventory = self.core.inventory_history_payload(spec.query, min(spec.limit, 500)).get("rows") or []
        health = self.core.state.rows(
            "SELECT * FROM health_events WHERE (?='' OR entity_id LIKE ? OR detail LIKE ?) ORDER BY created_at DESC,id DESC LIMIT ?",
            (spec.query, f"%{spec.query}%", f"%{spec.query}%", min(spec.limit, 500)),
        )
        audit = self.core.state.rows(
            "SELECT * FROM audit_events WHERE (?='' OR action LIKE ? OR target LIKE ? OR actor LIKE ?) ORDER BY created_at DESC,id DESC LIMIT ?",
            (spec.query, f"%{spec.query}%", f"%{spec.query}%", f"%{spec.query}%", min(spec.limit, 500)),
        )
        return self._envelope(
            "view-history",
            VIEW_TITLES["history"],
            summary="Newest-first operational chronology with exact UTC recording times.",
            metrics={"relationships": len(relationships), "inventory": len(inventory), "health": len(health), "audit": len(audit)},
            datasets=[
                self._dataset("relationship_history", "Relationship Timeline", relationships, row_key="id"),
                self._dataset("inventory_history", "Inventory Timeline", inventory, row_key="id"),
                self._dataset("health_history", "Health Timeline", health, row_key="id"),
                self._dataset("audit", "Audit Trail", audit, row_key="id"),
            ],
        )

    def _query_settings(self, spec: QuerySpec) -> ResultEnvelopeV1:
        status = self.core.webui_status_payload()
        db = self.core.state.db_status_payload()
        config = self.core.config.public_safe()
        settings = [
            {"setting": key, "value": value}
            for key, value in sorted(config.items())
        ]
        paths = [{"path": key, "value": value} for key, value in sorted(status.get("paths", {}).items())]
        return self._envelope(
            "view-settings",
            VIEW_TITLES["settings"],
            summary="Local paths, non-secret configuration, database integrity, and dependency readiness.",
            metrics={"schema": db.get("schema_version"), "expected_schema": db.get("expected_schema_version"), "missing": len(status.get("missing") or [])},
            datasets=[self._dataset("settings", "Public Configuration", settings), self._dataset("paths", "Runtime Paths", paths)],
            findings=[{"severity": "warning", "code": "MISSING", "message": item} for item in status.get("missing") or []],
            raw={"database": db, "credential_status": status.get("credential_status", {}), "ssh_host_key_mode": status.get("ssh_host_key_mode", "accept-new")},
        )

    @staticmethod
    def _apply_query(rows: Sequence[Mapping[str, Any]], spec: QuerySpec) -> list[dict[str, Any]]:
        materialized = [dict(row) for row in rows]
        query = spec.query.strip().lower()
        if query:
            materialized = [row for row in materialized if query in json.dumps(row, default=str).lower()]
        for key, wanted in spec.filters.items():
            if wanted not in (None, "", []):
                materialized = [row for row in materialized if str(row.get(key, "")).lower() == str(wanted).lower()]
        if spec.sort_by:
            materialized.sort(key=lambda row: (row.get(spec.sort_by) is None, str(row.get(spec.sort_by) or "").lower()), reverse=spec.descending)
        start = max(0, spec.offset)
        return materialized[start : start + max(1, min(spec.limit, 5000))]

    def registry(self) -> list[dict[str, Any]]:
        return [self._command_metadata(self.core.command_dict(spec)) for spec in self.core.command_registry()]

    def command(self, action_id: str) -> dict[str, Any] | None:
        spec = self.core.command_spec(action_id)
        return self._command_metadata(self.core.command_dict(spec)) if spec else None

    def _command_metadata(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        item = dict(payload)
        domain = str(item.get("domain") or "general")
        output_type = str(item.get("output_type") or "log")
        item["output_view"] = {
            "table": "table",
            "json": "evidence",
            "terminal": "terminal",
            "text": "text",
        }.get(output_type, "live-result")
        item["capability"] = self._capability_for(str(item.get("id") or ""))
        item["context_kinds"] = self._context_kinds_for(str(item.get("id") or ""))
        item["category"] = {
            "inventory": "Assets",
            "ap": "Assets",
            "topology": "Network",
            "vlan": "Network",
            "diagnose": "Diagnostics",
            "lookup": "Diagnostics",
            "health": "Operations",
            "backup": "Operations",
            "workflow": "Workflows",
            "memory": "History",
            "jobs": "Operations",
            "db": "System",
            "vault": "System",
            "commands": "System",
            "ask": "Search",
            "device": "Devices",
            "serve": "System",
            "tui": "System",
        }.get(domain, "General")
        fields = []
        for field in item.get("arg_schema") or []:
            enriched = dict(field)
            name = str(enriched.get("name") or "")
            enriched.setdefault("help", self._field_help(name))
            enriched.setdefault("group", "Target" if name in {"target", "device", "interface", "port", "mac", "core", "scope"} else "Options")
            enriched.setdefault("default", self._field_default(name))
            if name in {"target", "device", "core", "scope"}:
                enriched.setdefault("options_source", "inventory")
            fields.append(enriched)
        item["arg_schema"] = fields
        item["confirmation_policy"] = self._confirmation_policy(item)
        return item

    @staticmethod
    def _field_help(name: str) -> str:
        return {
            "target": "Hostname, IP address, site token, or supported shorthand.",
            "device": "Exact or uniquely resolvable switch/router identity.",
            "interface": "Physical or logical interface name as shown by the device.",
            "mac": "Physical unicast MAC in colon, hyphen, dotted, or plain form.",
            "vlan": "Access VLAN ID, or a comma/range list such as 10,20,100-120 for trunk mode.",
            "vlan_mode": "Access assigns one untagged VLAN; trunk carries the validated allowed list.",
            "native_vlan": "Optional untagged native VLAN for trunk mode only.",
            "replace": "Replace the trunk allowed list instead of adding the requested VLANs.",
            "depth": "Maximum switch-link layers to traverse, from 1 through 10.",
            "runs": "Independent benchmark servers/runs used for comparison.",
            "question": "Natural-language retrieval or registered operation request.",
            "fingerprint": "SHA-256 host-key fingerprint verified through an independent source; separate multiple values with commas.",
        }.get(name, name.replace("_", " ").capitalize())

    @staticmethod
    def _field_default(name: str) -> Any:
        return {
            "profile": "balanced",
            "runs": 2,
            "count": 5,
            "depth": 1,
            "max_nodes": 64,
            "direction": "both",
            "port": 5201,
            "seconds": 10,
            "parallel": 1,
            "sample_seconds": 5,
            "chart": "classic",
            "wait": 8,
            "once": True,
            "online": False,
            "refresh_neighbors": False,
        }.get(name, "")

    @staticmethod
    def _capability_for(action_id: str) -> str:
        for prefix, capability in (
            ("vlan-", "vlan"),
            ("topology-", "neighbors"),
            ("diagnose-cable", "copper-tdr"),
            ("diagnose-port", "interface-counters"),
            ("device-", "ssh"),
            ("backup-", "configuration-backup"),
            ("lookup-mac", "forwarding-table"),
        ):
            if action_id.startswith(prefix):
                return capability
        return "core"

    @staticmethod
    def _context_kinds_for(action_id: str) -> list[str]:
        if action_id.startswith("ap-"):
            return ["ap", "switch"]
        if action_id.startswith(("device-", "backup-", "vlan-")):
            return ["device", "switch", "port"]
        if action_id.startswith("lookup-mac"):
            return ["mac", "device", "switch"]
        if action_id.startswith("diagnose-"):
            return ["device", "switch", "port", "host"]
        return []

    @staticmethod
    def _confirmation_policy(item: Mapping[str, Any]) -> str:
        if item.get("risk_level") in {"config", "danger"}:
            return "preview-ticket-reason-typed-confirmation"
        if item.get("safety_class") != "read-only":
            return "preview-confirmation"
        return "none"

    def preview(self, action_id: str, args: Mapping[str, Any]) -> ActionPreviewV1:
        payload = self.core.preview_for_action(action_id, dict(args))
        targets = [
            str(args.get(name)).strip()
            for name in ("target", "device", "core", "scope", "interface", "mac")
            if args.get(name) not in (None, "", [])
        ]
        confirmation_phrase = ""
        if str(payload.get("safety_class") or "") == "config-write" and not payload.get("blocked"):
            target = str(args.get("target") or args.get("device") or "TARGET").strip()
            interface = str(args.get("interface") or args.get("port") or "").strip()
            confirmation_phrase = " ".join(part for part in ("APPLY", target, interface) if part)
        return ActionPreviewV1(
            action_id=action_id,
            args=dict(args),
            command=str(payload.get("command") or ""),
            safety_class=str(payload.get("safety_class") or "read-only"),
            state_effects=list((self.command(action_id) or {}).get("state_effects") or []),
            resolved_targets=targets,
            missing_args=list(payload.get("missing_args") or []),
            blocked=bool(payload.get("blocked")),
            reason=str(payload.get("reason") or ""),
            requires_confirmation=bool(payload.get("requires_confirmation")),
            preview_hash=self.core.preview_hash_for_action(action_id, dict(args), payload),
            confirmation_phrase=confirmation_phrase,
            validation_error=str(payload.get("validation_error") or ""),
        )

    def submit(
        self,
        action_id: str,
        args: Mapping[str, Any],
        *,
        reason: str = "",
        ticket: str = "",
        preview_hash: str = "",
        typed_confirmation: str = "",
    ) -> dict[str, Any]:
        preview = self.preview(action_id, args)
        if preview.blocked:
            raise PermissionError(preview.reason or "Action is preview-only.")
        if preview.requires_confirmation and preview_hash != preview.preview_hash:
            raise PermissionError("The submitted operation does not match the reviewed preview.")
        context = self.operator_context(reason, ticket)
        if preview.requires_confirmation and not context.reason:
            raise PermissionError("Active operations require an operator reason.")
        if preview.confirmation_phrase and typed_confirmation.strip() != preview.confirmation_phrase:
            raise PermissionError(f"Type {preview.confirmation_phrase!r} exactly to authorize this configuration change.")
        if preview.confirmation_phrase and not context.ticket:
            raise PermissionError("Configuration changes require a change or incident ticket.")
        return self.core.create_job(
            action_id,
            dict(args),
            context={**context.to_dict(), "preview_hash": preview.preview_hash, "typed_confirmation": typed_confirmation.strip(), "structured": True},
        )

    def cancel(self, job_id: str) -> tuple[bool, str]:
        return self.core.cancel_job(job_id)

    def job_detail(self, job_id: str, after_id: int = 0) -> dict[str, Any]:
        job = self.core.state.one("SELECT * FROM jobs WHERE id=?", (job_id,))
        logs = self.core.state.rows(
            "SELECT * FROM job_logs WHERE job_id=? AND id>? ORDER BY id",
            (job_id, max(0, after_id)),
        )
        events = [self._job_event(job_id, row).to_dict() for row in logs]
        return {"job": job, "events": events}

    def job_result(self, job_id: str) -> ResultEnvelopeV1 | None:
        detail = self.job_detail(job_id)
        job = detail.get("job") or {}
        if not job:
            return None
        payload: dict[str, Any] = {}
        try:
            parsed = json.loads(str(job.get("result_json") or "{}"))
            payload = parsed if isinstance(parsed, dict) else {"result": parsed}
        except (TypeError, ValueError):
            payload = {}
        datasets = [self._dataset("job", "Job Metadata", [job], row_key="id")]
        used_ids = {"job"}
        for key, value in payload.items():
            if not isinstance(value, list) or not value or not all(isinstance(row, Mapping) for row in value):
                continue
            dataset_id = re.sub(r"[^a-z0-9_]+", "_", str(key).lower()).strip("_") or "result"
            if dataset_id in used_ids:
                dataset_id = f"result_{dataset_id}"
            used_ids.add(dataset_id)
            datasets.append(self._dataset(dataset_id, str(key).replace("_", " ").title(), value))
        events = detail.get("events") or []
        if events:
            datasets.append(self._dataset("job_events", "Job Events", events, row_key="id"))
        findings: list[Mapping[str, Any]] = []
        if isinstance(payload.get("findings"), list):
            findings.extend(item for item in payload["findings"] if isinstance(item, Mapping))
        if str(job.get("status") or "") in {"failed", "partial", "cancelled", "stale"}:
            findings.append({"severity":"error" if job.get("status") == "failed" else "warning", "code":"JOB_STATUS", "message":f"Job finished with status {job.get('status')} and exit code {job.get('exit_code')}."})
        envelope = self._envelope(
            str(job.get("action") or "job-result"),
            f"Job {job_id}: {job.get('action') or 'result'}",
            summary=str(job.get("summary") or payload.get("summary") or payload.get("status") or "Recorded operation result."),
            metrics={"status":job.get("status"), "exit_code":job.get("exit_code"), "duration_ms":job.get("duration_ms"), "events":len(events)},
            datasets=datasets,
            findings=findings,
            raw=payload,
            source="job-result",
            complete=str(job.get("status") or "") in {"completed", "partial", "failed", "cancelled"},
        )
        envelope.status = "success" if job.get("status") == "completed" else "partial" if job.get("status") == "partial" else "failed" if job.get("status") in {"failed", "cancelled", "stale"} else "running"
        envelope.started_at = job.get("started_at")
        envelope.finished_at = job.get("finished_at")
        return envelope

    def _job_event(self, job_id: str, row: Mapping[str, Any]) -> JobEventV1:
        payload: dict[str, Any] = {}
        try:
            payload = json.loads(str(row.get("payload_json") or "{}"))
        except (TypeError, ValueError):
            pass
        return JobEventV1(
            id=int(row.get("id") or 0),
            job_id=job_id,
            created_at=int(row.get("created_at") or 0),
            created_at_iso=fmt_time(row.get("created_at")),
            event_type=str(row.get("event_type") or "log"),
            stream=str(row.get("stream") or "system"),
            phase=str(row.get("phase") or ""),
            message=str(row.get("line") or ""),
            progress_current=row.get("progress_current"),
            progress_total=row.get("progress_total"),
            payload=payload,
        )

    def export_dataset(self, dataset: DatasetV1, format_name: str = "csv", directory: Path | None = None) -> Path:
        format_name = format_name.lower()
        if format_name not in {"csv", "json"}:
            raise ValueError("Export format must be csv or json.")
        state_root = Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local" / "state")))
        root = directory or Path(os.environ.get("NETOPS_EXPORT_DIR", str(state_root / "netops" / "exports")))
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        safe_id = re.sub(r"[^A-Za-z0-9_.-]+", "-", dataset.id).strip(".-") or "result"
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + uuid.uuid4().hex[:6]
        destination = root / f"{safe_id}-{stamp}.{format_name}"
        descriptor, staged_name = tempfile.mkstemp(prefix=f".{safe_id}.", suffix=".tmp", dir=str(root))
        staged = Path(staged_name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
                if format_name == "json":
                    json.dump(dataset.to_dict(), handle, indent=2, sort_keys=True, default=str)
                    handle.write("\n")
                else:
                    keys = [column.key for column in dataset.columns if not column.hidden]
                    writer = csv.DictWriter(handle, fieldnames=keys, extrasaction="ignore")
                    writer.writeheader()
                    writer.writerows(dataset.rows)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(staged, destination)
            destination.chmod(0o600)
            return destination
        finally:
            if staged.exists():
                staged.unlink()
