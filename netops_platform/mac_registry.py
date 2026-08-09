#!/usr/bin/env python3
"""Authoritative IEEE MAC assignment lookup with a private local cache."""

from __future__ import annotations

import argparse
import contextlib
import csv
import hashlib
import io
import json
import os
import re
import tempfile
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


IEEE_REGISTRATION_AUTHORITY_URL = "https://standards.ieee.org/products-programs/regauth/"


@dataclass(frozen=True)
class RegistrySource:
    registry: str
    prefix_bits: int
    filename: str
    url: str


SOURCES: tuple[RegistrySource, ...] = (
    RegistrySource("MA-L", 24, "oui.csv", "https://standards-oui.ieee.org/oui/oui.csv"),
    RegistrySource("MA-M", 28, "mam.csv", "https://standards-oui.ieee.org/oui28/mam.csv"),
    RegistrySource("MA-S", 36, "oui36.csv", "https://standards-oui.ieee.org/oui36/oui36.csv"),
)


def iso_utc(epoch: int) -> str:
    return datetime.fromtimestamp(int(epoch), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalize_lookup_mac(value: Any) -> str:
    clean = re.sub(r"[^0-9a-f]", "", str(value or "").lower())
    if len(clean) != 12 or clean in {"000000000000", "ffffffffffff"}:
        return ""
    if int(clean[:2], 16) & 1:
        return ""
    return clean


def _atomic_write(path: Path, payload: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with contextlib.suppress(OSError):
        path.parent.chmod(0o700)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        with contextlib.suppress(OSError):
            os.close(fd)
        with contextlib.suppress(OSError):
            os.unlink(temporary)
        raise


def _validate_csv(payload: bytes, source: RegistrySource) -> int:
    try:
        text = payload.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{source.registry} response is not UTF-8 CSV") from exc
    reader = csv.DictReader(io.StringIO(text))
    fields = {str(item or "").strip().lower() for item in reader.fieldnames or []}
    if not {"assignment", "organization name"}.issubset(fields):
        raise ValueError(f"{source.registry} response lacks IEEE assignment columns")
    count = sum(1 for row in reader if re.fullmatch(r"[0-9A-Fa-f]{6,9}", str(row.get("Assignment") or "").strip()))
    if count < 1:
        raise ValueError(f"{source.registry} response contains no assignments")
    return count


class IeeeMacRegistry:
    """Download and query IEEE MA-L, MA-M, and MA-S public assignments."""

    def __init__(
        self,
        cache_dir: Path,
        *,
        opener: Callable[..., Any] = urlopen,
        clock: Callable[[], float] = time.time,
        user_agent: str = "NetOps-MAC-Registry/1.0",
    ) -> None:
        self.cache_dir = Path(cache_dir)
        self.opener = opener
        self.clock = clock
        self.user_agent = user_agent
        self.manifest_path = self.cache_dir / "manifest.json"

    def _manifest(self) -> Dict[str, Any]:
        if not self.manifest_path.is_file():
            return {"version": 1, "provider": "IEEE Registration Authority", "registries": {}}
        try:
            value = json.loads(self.manifest_path.read_text(encoding="utf-8"))
            return value if isinstance(value, dict) else {}
        except (OSError, ValueError):
            return {"version": 1, "provider": "IEEE Registration Authority", "registries": {}}

    def _save_manifest(self, value: Dict[str, Any]) -> None:
        _atomic_write(
            self.manifest_path,
            (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        )

    def _fresh(self, source: RegistrySource, max_age_seconds: int) -> bool:
        path = self.cache_dir / source.filename
        if not path.is_file():
            return False
        manifest = self._manifest().get("registries") or {}
        recorded = manifest.get(source.registry) if isinstance(manifest, dict) else {}
        try:
            fetched_at = int((recorded or {}).get("fetched_at") or path.stat().st_mtime)
        except (OSError, TypeError, ValueError):
            return False
        return int(self.clock()) - fetched_at <= max(0, int(max_age_seconds))

    def refresh(
        self,
        *,
        force: bool = False,
        max_age_seconds: int = 7 * 86400,
        timeout: int = 15,
    ) -> Dict[str, Any]:
        self.cache_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        with contextlib.suppress(OSError):
            self.cache_dir.chmod(0o700)
        manifest = self._manifest()
        manifest.update({
            "version": 1,
            "provider": "IEEE Registration Authority",
            "provider_url": IEEE_REGISTRATION_AUTHORITY_URL,
        })
        registries = manifest.setdefault("registries", {})
        rows: List[Dict[str, Any]] = []
        errors: List[str] = []
        for source in SOURCES:
            path = self.cache_dir / source.filename
            if not force and self._fresh(source, max_age_seconds):
                entry = dict(registries.get(source.registry) or {})
                rows.append({"registry": source.registry, "status": "cached", **entry})
                continue
            request = Request(
                source.url,
                headers={"User-Agent": self.user_agent, "Accept": "text/csv,*/*;q=0.5"},
            )
            try:
                with self.opener(request, timeout=max(1, min(int(timeout), 120))) as response:
                    payload = response.read(32 * 1024 * 1024 + 1)
                if len(payload) > 32 * 1024 * 1024:
                    raise ValueError(f"{source.registry} response exceeds 32 MiB safety limit")
                count = _validate_csv(payload, source)
                _atomic_write(path, payload)
                fetched_at = int(self.clock())
                entry = {
                    "registry": source.registry,
                    "prefix_bits": source.prefix_bits,
                    "url": source.url,
                    "path": str(path),
                    "rows": count,
                    "bytes": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "fetched_at": fetched_at,
                    "fetched_at_iso": iso_utc(fetched_at),
                }
                registries[source.registry] = entry
                rows.append({"status": "downloaded", **entry})
            except (HTTPError, URLError, OSError, TimeoutError, ValueError) as exc:
                message = f"{source.registry}: {exc}"
                errors.append(message)
                rows.append({
                    "registry": source.registry,
                    "status": "stale-cache" if path.is_file() else "failed",
                    "url": source.url,
                    "error": str(exc),
                })
        manifest["updated_at"] = int(self.clock())
        manifest["updated_at_iso"] = iso_utc(manifest["updated_at"])
        self._save_manifest(manifest)
        available = sum((self.cache_dir / source.filename).is_file() for source in SOURCES)
        return {
            "ok": available == len(SOURCES),
            "complete": not errors and available == len(SOURCES),
            "provider": "IEEE Registration Authority",
            "provider_url": IEEE_REGISTRATION_AUTHORITY_URL,
            "rows": rows,
            "errors": errors,
            "available_registries": available,
            "required_registries": len(SOURCES),
            "recorded_at": manifest["updated_at"],
            "recorded_at_iso": manifest["updated_at_iso"],
        }

    def _records(self) -> Iterable[Dict[str, Any]]:
        for source in SOURCES:
            path = self.cache_dir / source.filename
            if not path.is_file():
                continue
            try:
                with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
                    for row in csv.DictReader(handle):
                        assignment = re.sub(r"[^0-9A-Fa-f]", "", str(row.get("Assignment") or "")).upper()
                        if len(assignment) * 4 != source.prefix_bits:
                            continue
                        yield {
                            "registry": source.registry,
                            "prefix_bits": source.prefix_bits,
                            "assignment": assignment,
                            "organization": str(row.get("Organization Name") or "").strip(),
                            "organization_address": str(row.get("Organization Address") or "").strip(),
                            "source_url": source.url,
                            "cache_path": str(path),
                        }
            except OSError:
                continue

    def lookup(
        self,
        mac_value: Any,
        *,
        online: bool = True,
        force_refresh: bool = False,
        max_age_seconds: int = 7 * 86400,
        timeout: int = 15,
    ) -> Dict[str, Any]:
        mac = normalize_lookup_mac(mac_value)
        if not mac:
            raise ValueError("MAC must be a valid physical unicast EUI-48 address")
        colon_mac = ":".join(mac[index:index + 2] for index in range(0, 12, 2))
        if int(mac[:2], 16) & 2:
            return {
                "ok": True,
                "found": False,
                "mac": colon_mac,
                "address_type": "locally-administered",
                "organization": "",
                "note": "A locally administered or randomized MAC has no authoritative IEEE manufacturer assignment.",
                "provider": "IEEE Registration Authority",
                "provider_url": IEEE_REGISTRATION_AUTHORITY_URL,
            }

        refresh_payload: Optional[Dict[str, Any]] = None
        stale_or_missing = any(not self._fresh(source, max_age_seconds) for source in SOURCES)
        if online and (force_refresh or stale_or_missing):
            refresh_payload = self.refresh(
                force=force_refresh,
                max_age_seconds=max_age_seconds,
                timeout=timeout,
            )
        matches = [row for row in self._records() if mac.upper().startswith(row["assignment"])]
        match = max(matches, key=lambda row: int(row["prefix_bits"])) if matches else None
        manifest = self._manifest()
        base: Dict[str, Any] = {
            "ok": bool(match) or any((self.cache_dir / source.filename).is_file() for source in SOURCES),
            "found": bool(match),
            "mac": colon_mac,
            "address_type": "universally-administered",
            "provider": "IEEE Registration Authority",
            "provider_url": IEEE_REGISTRATION_AUTHORITY_URL,
            "registry_updated_at": manifest.get("updated_at"),
            "registry_updated_at_iso": manifest.get("updated_at_iso") or "unknown",
            "refresh": refresh_payload,
            "note": "IEEE assignments identify the registered organization and address block, not an exact device model.",
        }
        if not match:
            base.update({"organization": "Unknown", "assignment": mac[:6].upper(), "registry": "", "prefix_bits": None, "block_size": None})
            return base
        base.update(match)
        base["block_size"] = 2 ** (48 - int(match["prefix_bits"]))
        return base


def lookup_ieee_mac(
    cache_dir: Path,
    mac_value: Any,
    *,
    refresh: bool = False,
    offline: bool = False,
    max_age_seconds: int = 7 * 86400,
    timeout: int = 15,
) -> Dict[str, Any]:
    return IeeeMacRegistry(Path(cache_dir)).lookup(
        mac_value,
        online=not offline,
        force_refresh=refresh,
        max_age_seconds=max_age_seconds,
        timeout=timeout,
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Query IEEE public MAC assignments")
    parser.add_argument("mac")
    parser.add_argument("--cache-dir", type=Path, required=True)
    parser.add_argument("--refresh", action="store_true")
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--timeout", type=int, default=15)
    args = parser.parse_args(argv)
    try:
        payload = lookup_ieee_mac(
            args.cache_dir,
            args.mac,
            refresh=args.refresh,
            offline=args.offline,
            timeout=args.timeout,
        )
    except ValueError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        return 6
    print(json.dumps(payload, sort_keys=True))
    return 0 if payload.get("found") else 3


if __name__ == "__main__":
    raise SystemExit(main())
