"""Declarative, provenance-preserving ingest channels."""

from __future__ import annotations

import csv
import hashlib
import ipaddress
import io
import json
import os
import re
import ssl
import stat
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Mapping, TextIO

from netops_platform.contracts import IngestChannelV1, IngestRunV1, ObservationV1


CHANNEL_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
SUPPORTED_CHANNELS = {
    "csv",
    "json",
    "jsonl",
    "http-json",
    "netbox",
    "snmpv3",
    "stdin-ndjson",
    "catalyst-center",
    "aruba-central",
    "smartzone",
    "plugin",
}
EXPERIMENTAL_CHANNELS = {"catalyst-center", "aruba-central", "smartzone"}
SENSITIVE_FIELD_RE = re.compile(r"pass|secret|token|community|private[_-]?key|auth", re.I)
SECRET_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_./-]{0,127}$")
HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")
MAX_SECRET_BYTES = 65_536


def _origin(url: str) -> tuple[str, str, int | None]:
    parsed = urllib.parse.urlparse(url)
    scheme = parsed.scheme.lower()
    port = parsed.port
    if port is None:
        port = 443 if scheme == "https" else 80 if scheme == "http" else None
    return scheme, (parsed.hostname or "").lower(), port


class SameOriginRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, origin: tuple[str, str, int | None]):
        super().__init__()
        self.origin = origin

    def redirect_request(self, request: Any, file_pointer: Any, code: int, message: str, headers: Any, new_url: str) -> Any:
        parsed = urllib.parse.urlparse(new_url)
        if parsed.username or parsed.password or _origin(new_url) != self.origin:
            raise urllib.error.HTTPError(new_url, code, "HTTP redirect cannot leave the configured origin", headers, file_pointer)
        return super().redirect_request(request, file_pointer, code, message, headers, new_url)


def _hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()


def _timestamp(value: Any, default: int) -> int:
    if value in (None, ""):
        return default
    if isinstance(value, (int, float)):
        return int(value)
    text = str(value).strip()
    if text.isdigit():
        return int(text)
    parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return int(parsed.timestamp())


def _path_value(payload: Any, path: str, default: Any = None) -> Any:
    if not path:
        return payload
    current = payload
    for part in path.split("."):
        if isinstance(current, Mapping):
            if part not in current:
                return default
            current = current[part]
        elif isinstance(current, list) and part.isdigit():
            index = int(part)
            if index >= len(current):
                return default
            current = current[index]
        else:
            return default
    return current


def _redact(payload: Any) -> Any:
    if isinstance(payload, Mapping):
        return {
            str(key): "[redacted]" if SENSITIVE_FIELD_RE.search(str(key)) else _redact(value)
            for key, value in payload.items()
        }
    if isinstance(payload, list):
        return [_redact(value) for value in payload]
    return payload


@dataclass(frozen=True)
class ChannelManifest:
    path: Path
    channel: IngestChannelV1
    reader: Mapping[str, Any]
    fields: Mapping[str, str]
    provenance: Mapping[str, Any]


class SecretResolver:
    """Resolve references without allowing literal secrets in manifests."""

    def __init__(self, vault_getter: Callable[[str], str] | None = None):
        self.vault_getter = vault_getter

    @staticmethod
    def _read_private_file(path: Path) -> str:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise ValueError(f"secret file could not be opened securely: {path}: {exc.strerror}") from exc
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise ValueError(f"secret reference is not a regular file: {path}")
            if info.st_uid != os.getuid():
                raise ValueError(f"secret file must be owned by the current user: {path}")
            if stat.S_IMODE(info.st_mode) & 0o077:
                raise ValueError(f"secret file permissions must be 0600 or stricter: {path}")
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                content = stream.read(MAX_SECRET_BYTES + 1)
            if len(content) > MAX_SECRET_BYTES:
                raise ValueError(f"secret file exceeds {MAX_SECRET_BYTES} bytes: {path}")
            try:
                return content.decode("utf-8").rstrip("\r\n")
            except UnicodeDecodeError as exc:
                raise ValueError(f"secret file must be UTF-8 text: {path}") from exc
        finally:
            os.close(descriptor)

    def resolve(self, reference: str) -> str:
        if not isinstance(reference, str) or ":" not in reference:
            raise ValueError("secrets must use vault:, env:, or file: references")
        scheme, value = reference.split(":", 1)
        value = value.strip()
        if not value:
            raise ValueError("secret reference target is empty")
        if scheme == "env":
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", value):
                raise ValueError("secret environment variable name is invalid")
            if value not in os.environ:
                raise ValueError(f"secret environment variable is not set: {value}")
            resolved = os.environ[value]
            if not resolved:
                raise ValueError(f"secret environment variable is empty: {value}")
            return resolved
        if scheme == "file":
            resolved = self._read_private_file(Path(value).expanduser())
            if not resolved:
                raise ValueError(f"secret file is empty: {value}")
            return resolved
        if scheme == "vault":
            if not SECRET_NAME_RE.fullmatch(value) or ".." in value.split("/"):
                raise ValueError("named secret reference is invalid")
            if self.vault_getter is None:
                raise ValueError("named-vault access is unavailable in this runtime")
            resolved = self.vault_getter(value)
            if not resolved:
                raise ValueError(f"named secret is empty: {value}")
            return resolved
        raise ValueError(f"unsupported secret reference scheme: {scheme}")


def load_manifest(path: Path) -> ChannelManifest:
    path = Path(path)
    with path.open("rb") as stream:
        payload = tomllib.load(stream)
    if int(payload.get("schema_version") or 0) != 1:
        raise ValueError("ingest channel schema_version must be 1")
    section = payload.get("channel")
    if not isinstance(section, Mapping):
        raise ValueError("ingest manifest requires a [channel] table")
    name = str(section.get("name") or path.stem).strip().lower()
    if not CHANNEL_NAME_RE.fullmatch(name):
        raise ValueError("channel name must use lowercase letters, digits, '_' or '-'")
    kind = str(section.get("kind") or "").strip().lower()
    if kind not in SUPPORTED_CHANNELS:
        raise ValueError(f"unsupported ingest channel kind: {kind}")
    secret_refs = payload.get("secrets", {})
    if not isinstance(secret_refs, Mapping):
        raise ValueError("[secrets] must be a table of named references")
    for key, reference in secret_refs.items():
        if not isinstance(reference, str) or not reference.startswith(("vault:", "env:", "file:")):
            raise ValueError(f"secret {key} must use a vault:, env:, or file: reference")
    reader = payload.get("reader", {})
    fields = payload.get("fields", {})
    if not isinstance(reader, Mapping) or not isinstance(fields, Mapping):
        raise ValueError("[reader] and [fields] must be TOML tables")
    provider = str(reader.get("provider") or "").strip()
    if provider and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", provider):
        raise ValueError("reader.provider is invalid")
    if kind == "plugin" and not provider:
        raise ValueError("plugin ingest channels require reader.provider")
    headers = reader.get("headers", {})
    if not isinstance(headers, Mapping):
        raise ValueError("reader.headers must be a TOML table")
    sensitive_headers = {"authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key"}
    if any(str(key).strip().lower() in sensitive_headers or SENSITIVE_FIELD_RE.search(str(key)) for key in headers):
        raise ValueError("credential-bearing headers must use [secrets] references")
    if any(not HEADER_NAME_RE.fullmatch(str(key).strip()) for key in headers):
        raise ValueError("reader header name is invalid")
    if any("\r" in str(value) or "\n" in str(value) for value in headers.values()):
        raise ValueError("reader header values cannot contain control lines")
    configured_url = str(reader.get("url") or "").strip()
    if configured_url:
        parsed_url = urllib.parse.urlparse(configured_url)
        if parsed_url.username or parsed_url.password:
            raise ValueError("ingest URLs cannot contain user information")
        sensitive_query = {"token", "secret", "password", "passwd", "api_key", "apikey", "key"}
        if any(key.lower() in sensitive_query for key, _ in urllib.parse.parse_qsl(parsed_url.query, keep_blank_values=True)):
            raise ValueError("ingest URL credentials must use [secrets] references")
    configuration = {
        "reader": dict(reader),
        "fields": dict(fields),
        "provenance": dict(payload.get("provenance", {})),
    }
    if any(SENSITIVE_FIELD_RE.search(str(target)) for target in fields):
        raise ValueError("ingest fields cannot materialize secret-bearing fact names")
    channel = IngestChannelV1(
        name=name,
        kind=kind,
        enabled=bool(section.get("enabled", True)),
        entity_kind=str(section.get("entity_kind") or "device"),
        source_id_field=str(section.get("source_id_field") or "id"),
        observed_at_field=str(section.get("observed_at_field") or "observed_at"),
        configuration=configuration,
        secret_references={str(key): str(value) for key, value in secret_refs.items()},
    )
    return ChannelManifest(path, channel, dict(reader), {str(k): str(v) for k, v in fields.items()}, dict(payload.get("provenance", {})))


class IngestManager:
    def __init__(
        self,
        state: Any,
        channels_dir: Path,
        resolver: SecretResolver | None = None,
        providers: Mapping[str, Any] | None = None,
        provider_sources: Mapping[str, str] | None = None,
    ):
        self.state = state
        self.channels_dir = Path(channels_dir)
        self.resolver = resolver or SecretResolver()
        self.providers = dict(providers or {})
        self.provider_sources = dict(provider_sources or {})

    def validation(self) -> list[dict[str, Any]]:
        if not self.channels_dir.is_dir():
            return []
        rows: list[dict[str, Any]] = []
        for path in sorted(self.channels_dir.glob("*.toml")):
            try:
                manifest = load_manifest(path)
                rows.append({"name": manifest.channel.name, "kind": manifest.channel.kind, "status": "valid", "path": str(path), "error": "", "manifest": manifest})
            except Exception as exc:
                rows.append({"name": path.stem, "kind": "", "status": "invalid", "path": str(path), "error": str(exc), "manifest": None})
        counts: dict[str, int] = {}
        for row in rows:
            if row["manifest"] is not None:
                counts[row["name"]] = counts.get(row["name"], 0) + 1
        for row in rows:
            if row["manifest"] is not None and counts[row["name"]] > 1:
                row["status"] = "invalid"
                row["error"] = "duplicate ingest channel name"
        return rows

    def manifests(self) -> list[ChannelManifest]:
        return [row["manifest"] for row in self.validation() if row["status"] == "valid"]

    def manifest(self, name: str) -> ChannelManifest:
        rows = self.validation()
        matches = [row["manifest"] for row in rows if row["status"] == "valid" and row["name"] == name]
        if not matches:
            invalid = [row for row in rows if row["name"] == name and row["status"] == "invalid"]
            if invalid:
                raise ValueError(f"ingest channel is invalid: {name}: {invalid[0]['error']}")
            raise ValueError(f"ingest channel not found: {name}")
        if len(matches) > 1:
            raise ValueError(f"duplicate ingest channel name: {name}")
        return matches[0]

    def sync_channels(self) -> list[dict[str, Any]]:
        stamp = int(time.time())
        rows: list[dict[str, Any]] = []
        with self.state.connect() as connection:
            for manifest in self.manifests():
                channel = manifest.channel
                config_json = json.dumps(channel.to_dict(), sort_keys=True)
                connection.execute(
                    "INSERT INTO ingest_channels(name,kind,enabled,manifest_path,config_json,created_at,updated_at) "
                    "VALUES(?,?,?,?,?,?,?) ON CONFLICT(name) DO UPDATE SET kind=excluded.kind,enabled=excluded.enabled,"
                    "manifest_path=excluded.manifest_path,config_json=excluded.config_json,updated_at=excluded.updated_at",
                    (channel.name, channel.kind, int(channel.enabled), str(manifest.path), config_json, stamp, stamp),
                )
                rows.append({**channel.to_dict(), "status": "valid", "error": "", "manifest_path": str(manifest.path), "updated_at": stamp})
        for row in self.validation():
            if row["status"] == "invalid":
                rows.append({"enabled": False, "name": row["name"], "kind": row["kind"], "entity_kind": "", "manifest_path": row["path"], "updated_at": stamp, "status": "invalid", "error": row["error"]})
        known = {row["name"] for row in rows}
        for row in self.state.rows(
            "SELECT name,kind,enabled,manifest_path,config_json,updated_at FROM ingest_channels WHERE manifest_path='<built-in>' ORDER BY name"
        ):
            if row["name"] in known:
                continue
            try:
                configuration = json.loads(row.get("config_json") or "{}")
            except json.JSONDecodeError:
                configuration = {}
            rows.append({
                "enabled": bool(row.get("enabled")),
                "name": row["name"],
                "kind": row["kind"],
                "entity_kind": configuration.get("entity_kind", ""),
                "manifest_path": row["manifest_path"],
                "updated_at": row["updated_at"],
                "status": "built-in",
                "error": "",
            })
        return rows

    @staticmethod
    def _file_path(manifest: ChannelManifest) -> Path:
        value = str(manifest.reader.get("path") or "").strip()
        if not value:
            raise ValueError(f"{manifest.channel.kind} channel requires reader.path")
        path = Path(value).expanduser()
        if not path.is_absolute():
            path = manifest.path.parent / path
        if not path.is_file():
            raise ValueError(f"ingest source is not a regular file: {path}")
        limit = max(1, min(int(manifest.reader.get("max_bytes") or 100_000_000), 1_000_000_000))
        if path.stat().st_size > limit:
            raise ValueError(f"ingest source exceeds reader.max_bytes ({limit})")
        return path

    @staticmethod
    def _json_records(payload: Any, records_path: str) -> list[Mapping[str, Any]]:
        records = _path_value(payload, records_path, payload)
        if isinstance(records, Mapping):
            records = [records]
        if not isinstance(records, list):
            raise ValueError("JSON record path must resolve to an object or array")
        if not all(isinstance(record, Mapping) for record in records):
            raise ValueError("every ingest record must be a JSON object")
        return list(records)

    def _read_file_records(self, manifest: ChannelManifest) -> Iterator[Mapping[str, Any]]:
        path = self._file_path(manifest)
        kind = manifest.channel.kind
        if kind == "csv":
            with path.open("r", encoding=str(manifest.reader.get("encoding") or "utf-8"), newline="") as stream:
                yield from csv.DictReader(stream)
            return
        if kind == "json":
            payload = json.loads(path.read_text(encoding="utf-8"))
            yield from self._json_records(payload, str(manifest.reader.get("records_path") or ""))
            return
        with path.open("r", encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, 1):
                if not line.strip():
                    continue
                record = json.loads(line)
                if not isinstance(record, Mapping):
                    raise ValueError(f"JSONL line {line_number} is not an object")
                yield record

    def _ssl_context(self, manifest: ChannelManifest) -> ssl.SSLContext:
        if manifest.reader.get("tls_verify", True) is False:
            raise ValueError("TLS certificate verification cannot be disabled for ingest channels")
        ca_file = str(manifest.reader.get("ca_file") or "").strip()
        return ssl.create_default_context(cafile=ca_file or None)

    def _headers(self, manifest: ChannelManifest) -> dict[str, str]:
        headers = {str(k): str(v) for k, v in dict(manifest.reader.get("headers") or {}).items()}
        for name, reference in manifest.channel.secret_references.items():
            value = self.resolver.resolve(reference)
            if name == "token":
                scheme = "Token" if manifest.channel.kind == "netbox" else "Bearer"
                headers["Authorization"] = f"{scheme} {value}"
            elif name.startswith("header_"):
                header = name.removeprefix("header_").replace("_", "-")
                if not HEADER_NAME_RE.fullmatch(header) or header.lower() in {"host", "content-length", "transfer-encoding"}:
                    raise ValueError(f"secret header name is not allowed: {header}")
                headers[header] = value
        headers.setdefault("Accept", "application/json")
        headers.setdefault("User-Agent", "netops-platform-ingest/1")
        return headers

    def _http_json(self, url: str, manifest: ChannelManifest) -> Any:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != "https" and not (
            parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        ):
            raise ValueError("HTTP ingest requires HTTPS except for loopback fixture services")
        origin = _origin(url)
        request = urllib.request.Request(url, headers=self._headers(manifest))
        timeout = max(1, min(int(manifest.reader.get("timeout_seconds") or 20), 120))
        attempts = max(1, min(int(manifest.reader.get("rate_limit_attempts") or 2), 4))
        max_bytes = max(1, min(int(manifest.reader.get("max_bytes") or 25_000_000), 100_000_000))
        context = self._ssl_context(manifest)
        opener = urllib.request.build_opener(
            SameOriginRedirectHandler(origin),
            urllib.request.HTTPSHandler(context=context),
        )
        for attempt in range(attempts):
            try:
                with opener.open(request, timeout=timeout) as response:
                    if _origin(response.geturl()) != origin:
                        raise ValueError("HTTP response left the configured origin")
                    declared = response.headers.get("Content-Length")
                    if declared and int(declared) > max_bytes:
                        raise ValueError(f"HTTP ingest response exceeds reader.max_bytes ({max_bytes})")
                    content = response.read(max_bytes + 1)
                    if len(content) > max_bytes:
                        raise ValueError(f"HTTP ingest response exceeds reader.max_bytes ({max_bytes})")
                    return json.loads(content.decode("utf-8"))
            except urllib.error.HTTPError as exc:
                if exc.code != 429 or attempt + 1 >= attempts:
                    raise
                try:
                    retry = min(5, max(0, int(exc.headers.get("Retry-After") or 1)))
                except (TypeError, ValueError):
                    retry = 1
                time.sleep(retry)
        raise RuntimeError("HTTP ingest retry loop ended unexpectedly")

    def _read_http_records(self, manifest: ChannelManifest) -> Iterator[Mapping[str, Any]]:
        url = str(manifest.reader.get("url") or "").strip()
        if not url:
            raise ValueError(f"{manifest.channel.kind} channel requires reader.url")
        if manifest.channel.kind == "netbox" and not urllib.parse.urlparse(url).path.rstrip("/").endswith("api/dcim/devices"):
            url = url.rstrip("/") + "/api/dcim/devices/"
        initial = urllib.parse.urlparse(url)
        origin = _origin(url)
        max_pages = max(1, min(int(manifest.reader.get("max_pages") or 100), 1000))
        records_path = str(manifest.reader.get("records_path") or ("results" if manifest.channel.kind == "netbox" else ""))
        next_path = str(manifest.reader.get("next_path") or ("next" if manifest.channel.kind == "netbox" else ""))
        seen: set[str] = set()
        for _ in range(max_pages):
            if url in seen:
                raise ValueError("HTTP pagination loop detected")
            seen.add(url)
            payload = self._http_json(url, manifest)
            yield from self._json_records(payload, records_path)
            next_url = _path_value(payload, next_path, "") if next_path else ""
            if not next_url:
                return
            url = urllib.parse.urljoin(url, str(next_url))
            candidate = urllib.parse.urlparse(url)
            if candidate.username or candidate.password or _origin(url) != origin:
                raise ValueError("HTTP pagination cannot leave the configured origin")
        raise ValueError("HTTP ingest exceeded reader.max_pages")

    def _records(self, manifest: ChannelManifest, stdin: TextIO | None) -> Iterator[Mapping[str, Any]]:
        kind = manifest.channel.kind
        if kind in {"csv", "json", "jsonl"}:
            yield from self._read_file_records(manifest)
            return
        provider_name = str(manifest.reader.get("provider") or "").strip()
        if kind == "plugin" or provider_name:
            yield from self._provider_records(manifest, provider_name)
            return
        if kind == "stdin-ndjson":
            stream = stdin or io.StringIO("")
            for line_number, line in enumerate(stream, 1):
                if not line.strip():
                    continue
                record = json.loads(line)
                if not isinstance(record, Mapping):
                    raise ValueError(f"stdin NDJSON line {line_number} is not an object")
                yield record
            return
        if kind == "snmpv3":
            # Live SNMPv3 uses a trusted provider implementation so credentials
            # never appear in process arguments. Fixtures exercise the contract.
            if manifest.reader.get("fixture_path"):
                fixture = ChannelManifest(
                    manifest.path,
                    IngestChannelV1(**{**manifest.channel.to_dict(), "kind": "json", "schema_version": "1"}),
                    {**manifest.reader, "path": manifest.reader["fixture_path"]},
                    manifest.fields,
                    manifest.provenance,
                )
                yield from self._read_file_records(fixture)
                return
            raise RuntimeError("live SNMPv3 ingest requires an enabled netops.ingest provider")
        if kind in EXPERIMENTAL_CHANNELS:
            if not bool(manifest.reader.get("experimental", False)):
                raise ValueError(f"{kind} requires reader.experimental = true")
            if manifest.reader.get("fixture_path"):
                fixture = ChannelManifest(
                    manifest.path,
                    IngestChannelV1(**{**manifest.channel.to_dict(), "kind": "json", "schema_version": "1"}),
                    {**manifest.reader, "path": manifest.reader["fixture_path"]},
                    manifest.fields,
                    manifest.provenance,
                )
                yield from self._read_file_records(fixture)
                return
            if os.environ.get("NETOPS_ENABLE_EXPERIMENTAL_APIS") != "1":
                raise RuntimeError(f"live {kind} ingest is fixture-gated until explicitly enabled")
        yield from self._read_http_records(manifest)

    def _provider_records(self, manifest: ChannelManifest, provider_name: str) -> Iterator[Mapping[str, Any]]:
        provider = self.providers.get(provider_name)
        if provider is None:
            raise RuntimeError(f"enabled ingest provider is unavailable: {provider_name}")
        method = getattr(provider, "read_records", None)
        if not callable(method):
            raise RuntimeError(f"ingest provider does not implement read_records(): {provider_name}")
        secrets = {
            name: self.resolver.resolve(reference)
            for name, reference in manifest.channel.secret_references.items()
        }
        try:
            records = method(manifest.channel, dict(manifest.reader), secrets)
            for index, record in enumerate(records or (), 1):
                if not isinstance(record, Mapping):
                    raise ValueError(f"ingest provider record {index} is not an object")
                yield record
        except Exception as exc:
            detail = str(exc)
            for value in secrets.values():
                if value:
                    detail = detail.replace(value, "[redacted]")
            raise RuntimeError(f"ingest provider {provider_name} failed: {detail}") from exc

    def _observation(self, manifest: ChannelManifest, record: Mapping[str, Any], received_at: int) -> ObservationV1:
        channel = manifest.channel
        facts = {
            target: _path_value(record, source)
            for target, source in manifest.fields.items()
            if _path_value(record, source, None) is not None
        } if manifest.fields else {
            str(key): value for key, value in record.items()
            if key not in {channel.source_id_field, channel.observed_at_field}
            and not SENSITIVE_FIELD_RE.search(str(key))
        }
        stable_id = _path_value(record, channel.source_id_field, "")
        if stable_id in (None, ""):
            stable_id = facts.get("ip") or facts.get("mac") or facts.get("name") or facts.get("hostname")
        if stable_id in (None, ""):
            raise ValueError(f"record is missing stable source id field: {channel.source_id_field}")
        observed_at = _timestamp(_path_value(record, channel.observed_at_field, None), received_at)
        completeness = str(manifest.reader.get("completeness") or "partial")
        confidence = max(0, min(100, int(manifest.reader.get("confidence") or 100)))
        provider_name = str(manifest.reader.get("provider") or "").strip()
        return ObservationV1(
            entity_kind=channel.entity_kind,
            stable_source_id=str(stable_id),
            channel=channel.name,
            observed_at=observed_at,
            received_at=received_at,
            completeness=completeness,
            facts=facts,
            status=str(facts.get("status") or "observed"),
            confidence=confidence,
            provenance={
                **manifest.provenance,
                "manifest": str(manifest.path),
                "channel_kind": channel.kind,
                "provider": provider_name,
                "provider_source": self.provider_sources.get(provider_name, "") if provider_name else "",
            },
            raw_evidence_hash=_hash(record),
        )

    @staticmethod
    def _materialize_device(connection: Any, observation: ObservationV1) -> None:
        if observation.entity_kind not in {"device", "switch", "router", "firewall"}:
            return
        facts = dict(observation.facts)
        candidate = str(facts.get("ip") or observation.stable_source_id or "").strip()
        try:
            ip = str(ipaddress.ip_interface(candidate).ip)
        except ValueError:
            ip = ""
        if not ip:
            return
        old = connection.execute("SELECT * FROM devices WHERE ip=?", (ip,)).fetchone()
        current = dict(old) if old else {
            "ip": ip, "hostname": "", "platform": "", "model": "", "serial": "", "mac": "", "source": "", "last_seen": 0, "status": "UNKNOWN"
        }
        if old and observation.observed_at < int(current.get("last_seen") or 0):
            return
        for field in ("hostname", "platform", "model", "serial", "mac"):
            value = facts.get(field)
            if value not in (None, "", "unknown", "N/A"):
                current[field] = str(value)
        if facts.get("status") not in (None, ""):
            current["status"] = str(facts["status"]).upper()
        current["last_seen"] = observation.observed_at
        sources = [item for item in str(current.get("source") or "").split("+") if item]
        source = f"ingest:{observation.channel}"
        if source not in sources:
            sources.append(source)
        current["source"] = "+".join(sources)
        connection.execute(
            "INSERT OR REPLACE INTO devices(ip,hostname,platform,model,serial,mac,source,last_seen,status) VALUES(?,?,?,?,?,?,?,?,?)",
            tuple(current[field] for field in ("ip", "hostname", "platform", "model", "serial", "mac", "source", "last_seen", "status")),
        )

    def _store(self, connection: Any, observation: ObservationV1, run_id: str) -> bool:
        cursor = connection.execute(
            "INSERT OR IGNORE INTO observations(idempotency_key,entity_kind,stable_source_id,channel,observed_at,received_at,completeness,status,confidence,provenance_json,facts_json,raw_evidence_hash,run_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                observation.idempotency_key, observation.entity_kind, observation.stable_source_id,
                observation.channel, observation.observed_at, observation.received_at,
                observation.completeness, observation.status, observation.confidence,
                json.dumps(observation.provenance, sort_keys=True), json.dumps(observation.facts, sort_keys=True),
                observation.raw_evidence_hash, run_id,
            ),
        )
        if cursor.rowcount == 0:
            return False
        observation_id = int(cursor.lastrowid)
        source = str(observation.provenance.get("source") or observation.channel)
        for name, value in observation.facts.items():
            connection.execute(
                "INSERT INTO observation_fields(observation_id,field_name,value_json,source,confidence,observed_at) VALUES(?,?,?,?,?,?)",
                (observation_id, str(name), json.dumps(value, sort_keys=True), source, observation.confidence, observation.observed_at),
            )
        self._materialize_device(connection, observation)
        return True

    def run(self, name: str, *, stdin: TextIO | None = None) -> IngestRunV1:
        manifest = self.manifest(name)
        if not manifest.channel.enabled:
            raise ValueError(f"ingest channel is disabled: {name}")
        started = int(time.time())
        run_id = "ing-" + uuid.uuid4().hex
        counters = {"received": 0, "accepted": 0, "duplicates": 0, "rejected": 0}
        status = "completed"
        message = ""
        with self.state.connect() as connection:
            connection.execute(
                "INSERT INTO ingest_runs(run_id,channel,status,started_at,request_json) VALUES(?,?,?,?,?)",
                (run_id, name, "running", started, json.dumps(manifest.channel.to_dict(), sort_keys=True)),
            )
        max_records = max(1, min(int(manifest.reader.get("max_records") or 1_000_000), 1_000_000))
        pending: list[tuple[int, Mapping[str, Any]]] = []

        def store_pending() -> None:
            if not pending:
                return
            with self.state.connect() as connection:
                for record_index, pending_record in pending:
                    counters["received"] += 1
                    try:
                        observation = self._observation(manifest, pending_record, int(time.time()))
                        if self._store(connection, observation, run_id):
                            counters["accepted"] += 1
                        else:
                            counters["duplicates"] += 1
                    except Exception as exc:
                        counters["rejected"] += 1
                        connection.execute(
                            "INSERT INTO observation_rejects(run_id,channel,received_at,record_index,error_code,message,raw_evidence_hash,redacted_record_json) VALUES(?,?,?,?,?,?,?,?)",
                            (run_id, name, int(time.time()), record_index, type(exc).__name__, str(exc), _hash(pending_record), json.dumps(_redact(pending_record), sort_keys=True)),
                        )
            pending.clear()

        try:
            for index, record in enumerate(self._records(manifest, stdin), 1):
                if index > max_records:
                    raise ValueError(f"ingest exceeded reader.max_records ({max_records})")
                pending.append((index, record))
                if len(pending) >= 250:
                    store_pending()
            store_pending()
            if counters["rejected"]:
                status = "partial" if counters["accepted"] or counters["duplicates"] else "failed"
        except Exception as exc:
            store_pending()
            status = "partial" if counters["accepted"] or counters["duplicates"] else "failed"
            message = str(exc)
        finished = int(time.time())
        result = IngestRunV1(run_id, name, status, started, finished, message=message, **counters)
        with self.state.connect() as connection:
            connection.execute(
                "UPDATE ingest_runs SET status=?,finished_at=?,received=?,accepted=?,duplicates=?,rejected=?,message=?,result_json=? WHERE run_id=?",
                (status, finished, counters["received"], counters["accepted"], counters["duplicates"], counters["rejected"], message, json.dumps(result.to_dict(), sort_keys=True), run_id),
            )
        return result

    def record_snapshot(
        self,
        channel: str,
        entity_kind: str,
        records: Iterable[Mapping[str, Any]],
        *,
        identity_fields: tuple[str, ...],
        source: str,
        observed_at_field: str = "last_seen",
        completeness: str = "partial",
        confidence: int = 80,
        composite_identity: bool = False,
    ) -> IngestRunV1:
        """Record built-in adapter rows through the same append-only contract."""
        if not CHANNEL_NAME_RE.fullmatch(channel):
            raise ValueError("built-in observation channel name is invalid")
        started = int(time.time())
        run_id = "ing-" + uuid.uuid4().hex
        counters = {"received": 0, "accepted": 0, "duplicates": 0, "rejected": 0}
        descriptor = {
            "name": channel,
            "kind": "built-in",
            "entity_kind": entity_kind,
            "source": source,
            "completeness": completeness,
        }
        with self.state.connect() as connection:
            connection.execute(
                "INSERT INTO ingest_channels(name,kind,enabled,manifest_path,config_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?) "
                "ON CONFLICT(name) DO UPDATE SET kind=excluded.kind,enabled=excluded.enabled,manifest_path=excluded.manifest_path,config_json=excluded.config_json,updated_at=excluded.updated_at",
                (channel, "built-in", 1, "<built-in>", json.dumps(descriptor, sort_keys=True), started, started),
            )
            connection.execute(
                "INSERT INTO ingest_runs(run_id,channel,status,started_at,request_json) VALUES(?,?,?,?,?)",
                (run_id, channel, "running", started, json.dumps(descriptor, sort_keys=True)),
            )
        with self.state.connect() as connection:
            for index, raw in enumerate(records, 1):
                record = dict(raw)
                counters["received"] += 1
                try:
                    identity_values = [str(record.get(field) or "").strip() for field in identity_fields]
                    identity = "|".join(identity_values) if composite_identity else next((value for value in identity_values if value), "")
                    if not identity.strip("|"):
                        raise ValueError("built-in observation has no stable identity")
                    observed_at = _timestamp(record.get(observed_at_field), started)
                    facts = {
                        str(key): value for key, value in record.items()
                        if not SENSITIVE_FIELD_RE.search(str(key))
                    }
                    observation = ObservationV1(
                        entity_kind=entity_kind,
                        stable_source_id=identity,
                        channel=channel,
                        observed_at=observed_at,
                        received_at=started,
                        completeness=completeness,
                        facts=facts,
                        status=str(facts.get("status") or "observed"),
                        confidence=max(0, min(100, int(confidence))),
                        provenance={"source": source, "adapter": "built-in-compatibility", "channel_kind": "built-in"},
                        raw_evidence_hash=_hash(record),
                    )
                    if self._store(connection, observation, run_id):
                        counters["accepted"] += 1
                    else:
                        counters["duplicates"] += 1
                except Exception as exc:
                    counters["rejected"] += 1
                    connection.execute(
                        "INSERT INTO observation_rejects(run_id,channel,received_at,record_index,error_code,message,raw_evidence_hash,redacted_record_json) VALUES(?,?,?,?,?,?,?,?)",
                        (run_id, channel, started, index, type(exc).__name__, str(exc), _hash(record), json.dumps(_redact(record), sort_keys=True)),
                    )
        status = "completed" if not counters["rejected"] else ("partial" if counters["accepted"] or counters["duplicates"] else "failed")
        finished = int(time.time())
        result = IngestRunV1(run_id, channel, status, started, finished, **counters)
        with self.state.connect() as connection:
            connection.execute(
                "UPDATE ingest_runs SET status=?,finished_at=?,received=?,accepted=?,duplicates=?,rejected=?,message=?,result_json=? WHERE run_id=?",
                (status, finished, counters["received"], counters["accepted"], counters["duplicates"], counters["rejected"], "", json.dumps(result.to_dict(), sort_keys=True), run_id),
            )
        return result

    def history(self, limit: int = 100) -> list[dict[str, Any]]:
        return self.state.rows(
            "SELECT run_id,channel,status,started_at,finished_at,received,accepted,duplicates,rejected,message FROM ingest_runs ORDER BY started_at DESC,run_id DESC LIMIT ?",
            (max(1, min(limit, 1000)),),
        )

    def rejects(self, run_id: str = "", limit: int = 100) -> list[dict[str, Any]]:
        if run_id:
            return self.state.rows(
                "SELECT id,run_id,channel,received_at,record_index,error_code,message,raw_evidence_hash FROM observation_rejects WHERE run_id=? ORDER BY id DESC LIMIT ?",
                (run_id, max(1, min(limit, 1000))),
            )
        return self.state.rows(
            "SELECT id,run_id,channel,received_at,record_index,error_code,message,raw_evidence_hash FROM observation_rejects ORDER BY id DESC LIMIT ?",
            (max(1, min(limit, 1000)),),
        )
