"""Versioned contracts shared by the CLI, jobs, ingest, and path-inspection adapters."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence


SCHEMA_VERSION = "1"


def _canonical_hash(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _rfc3339(epoch: int | None) -> str:
    if not epoch:
        return ""
    return datetime.fromtimestamp(int(epoch), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class ObservationV1:
    entity_kind: str
    stable_source_id: str
    channel: str
    observed_at: int
    received_at: int
    completeness: str
    facts: Mapping[str, Any]
    status: str = "observed"
    confidence: int = 100
    provenance: Mapping[str, Any] = field(default_factory=dict)
    raw_evidence_hash: str = ""
    idempotency_key: str = ""
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if not self.entity_kind.strip() or not self.stable_source_id.strip() or not self.channel.strip():
            raise ValueError("observation entity_kind, stable_source_id, and channel are required")
        if self.observed_at <= 0 or self.received_at <= 0:
            raise ValueError("observation timestamps must be positive epoch seconds")
        if self.completeness not in {"complete", "partial", "status-only"}:
            raise ValueError("observation completeness must be complete, partial, or status-only")
        if not 0 <= int(self.confidence) <= 100:
            raise ValueError("observation confidence must be between 0 and 100")
        if not self.raw_evidence_hash:
            object.__setattr__(self, "raw_evidence_hash", _canonical_hash(dict(self.facts)))
        if not self.idempotency_key:
            identity = {
                "channel": self.channel,
                "entity_kind": self.entity_kind,
                "stable_source_id": self.stable_source_id,
                "observed_at": self.observed_at,
                "raw_evidence_hash": self.raw_evidence_hash,
            }
            object.__setattr__(self, "idempotency_key", _canonical_hash(identity))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class IngestChannelV1:
    name: str
    kind: str
    enabled: bool = True
    entity_kind: str = "device"
    source_id_field: str = "id"
    observed_at_field: str = "observed_at"
    configuration: Mapping[str, Any] = field(default_factory=dict)
    secret_references: Mapping[str, str] = field(default_factory=dict)
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if not self.name.strip() or not self.kind.strip() or not self.entity_kind.strip():
            raise ValueError("ingest channel name, kind, and entity_kind are required")
        for name, reference in self.secret_references.items():
            if not str(name).strip() or not str(reference).startswith(("vault:", "env:", "file:")):
                raise ValueError("ingest secret references must use vault:, env:, or file:")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class IngestRunV1:
    run_id: str
    channel: str
    status: str
    started_at: int
    finished_at: int | None = None
    received: int = 0
    accepted: int = 0
    duplicates: int = 0
    rejected: int = 0
    message: str = ""
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.status not in {"running", "completed", "partial", "failed"}:
            raise ValueError("ingest run status is invalid")
        if self.started_at <= 0 or (self.finished_at is not None and self.finished_at < self.started_at):
            raise ValueError("ingest run timestamps are invalid")
        counts = (self.received, self.accepted, self.duplicates, self.rejected)
        if any(int(value) < 0 for value in counts):
            raise ValueError("ingest run counts cannot be negative")
        if self.accepted + self.duplicates + self.rejected > self.received:
            raise ValueError("ingest outcome counts cannot exceed received records")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class PluginDescriptorV1:
    name: str
    distribution: str
    version: str
    group: str
    entry_point: str
    api_version: str
    enabled: bool = False
    source: str = "installed-distribution"
    capabilities: Sequence[str] = field(default_factory=tuple)
    load_status: str = "discovered"
    error: str = ""
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if not all(value.strip() for value in (self.name, self.distribution, self.group, self.entry_point, self.api_version)):
            raise ValueError("plugin identity, group, entry point, and API version are required")

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["capabilities"] = list(self.capabilities)
        return payload


@dataclass(frozen=True)
class CapabilityEvidenceV1:
    device_id: str
    capability: str
    state: str
    observed_at: int
    source: str
    confidence: int
    facts: Mapping[str, Any] = field(default_factory=dict)
    raw_evidence_hash: str = ""
    driver_family: str = "unknown"
    parser_version: str = ""
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if not self.device_id.strip() or not self.capability.strip() or not self.source.strip():
            raise ValueError("capability evidence device, capability, and source are required")
        if self.state not in {"supported", "unsupported", "unknown", "error"}:
            raise ValueError("capability evidence state is invalid")
        if self.observed_at <= 0 or not 0 <= int(self.confidence) <= 100:
            raise ValueError("capability evidence timestamp or confidence is invalid")
        if not self.raw_evidence_hash:
            object.__setattr__(self, "raw_evidence_hash", _canonical_hash(dict(self.facts)))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class PathRequestV1:
    endpoint: str
    vlan: int
    source: str = ""
    destination: str = ""
    depth: int = 8
    max_nodes: int = 64
    mode: str = "hybrid"
    explain: bool = False
    requested_at: int = 0
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if not self.endpoint.strip():
            raise ValueError("path endpoint is required")
        if not 1 <= int(self.vlan) <= 4094:
            raise ValueError("path VLAN must be between 1 and 4094")
        if not 0 <= int(self.depth) <= 16:
            raise ValueError("path depth must be between 0 and 16")
        if not 1 <= int(self.max_nodes) <= 256:
            raise ValueError("path max_nodes must be between 1 and 256")
        if self.mode not in {"cached", "live", "hybrid"}:
            raise ValueError("path mode must be cached, live, or hybrid")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class PathHopV1:
    sequence: int
    device_id: str
    device_name: str = ""
    management_ip: str = ""
    ingress_interface: str = ""
    egress_interface: str = ""
    layer: str = "L2"
    vlan_state: str = "unknown"
    forwarding_state: str = "unknown"
    confidence: int = 0
    evidence_observed_at: int | None = None
    evidence_age_seconds: int | None = None
    evidence: Mapping[str, Any] = field(default_factory=dict)
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.sequence < 0 or not self.device_id.strip():
            raise ValueError("path hop sequence and device_id are invalid")
        if self.layer not in {"L2", "L3", "L2/L3", "unknown"}:
            raise ValueError("path hop layer is invalid")
        if not 0 <= int(self.confidence) <= 100:
            raise ValueError("path hop confidence is invalid")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class PathFindingV1:
    severity: str
    code: str
    message: str
    device_id: str = ""
    interface: str = ""
    confidence: int = 0
    evidence_observed_at: int | None = None
    evidence: Mapping[str, Any] = field(default_factory=dict)
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.severity not in {"info", "warning", "error", "critical"}:
            raise ValueError("path finding severity is invalid")
        if not self.code.strip() or not self.message.strip() or not 0 <= int(self.confidence) <= 100:
            raise ValueError("path finding code, message, or confidence is invalid")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class PathResultV1:
    run_id: str
    request: PathRequestV1
    status: str
    confidence: int
    started_at: int
    finished_at: int
    hops: Sequence[PathHopV1] = field(default_factory=tuple)
    findings: Sequence[PathFindingV1] = field(default_factory=tuple)
    summary: str = ""
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.status not in {"COMPLETE", "BLOCKED", "PARTIAL", "UNKNOWN"}:
            raise ValueError("path result status is invalid")
        if not self.run_id.strip() or not 0 <= int(self.confidence) <= 100:
            raise ValueError("path result run_id or confidence is invalid")
        if self.started_at <= 0 or self.finished_at < self.started_at:
            raise ValueError("path result timestamps are invalid")

    def to_dict(self) -> dict[str, Any]:
        request = self.request.to_dict()
        request["requested_at_iso"] = _rfc3339(self.request.requested_at)
        hops = []
        for hop in self.hops:
            payload = hop.to_dict()
            payload["evidence_observed_at_iso"] = _rfc3339(hop.evidence_observed_at)
            hops.append(payload)
        findings = []
        for finding in self.findings:
            payload = finding.to_dict()
            payload["evidence_observed_at_iso"] = _rfc3339(finding.evidence_observed_at)
            findings.append(payload)
        return {
            **asdict(self),
            "request": request,
            "hops": hops,
            "findings": findings,
            "started_at_iso": _rfc3339(self.started_at),
            "finished_at_iso": _rfc3339(self.finished_at),
        }
