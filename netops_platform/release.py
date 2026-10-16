"""Reproducible release metadata, checksums, SBOM, and provenance."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import platform
import re
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _rfc3339(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _validated_artifacts(artifacts: Iterable[Path]) -> list[Path]:
    files = [Path(path) for path in artifacts]
    if not files:
        raise ValueError("at least one release artifact is required")
    names: set[str] = set()
    for path in files:
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"release artifact must be a regular file: {path}")
        if path.name in names:
            raise ValueError(f"release artifact names must be unique: {path.name}")
        names.add(path.name)
    return sorted(files, key=lambda item: item.name)


def _requirement_component(requirement: str) -> dict[str, Any]:
    name = re.split(r"[\s\[<>=!~;]", requirement.strip(), maxsplit=1)[0]
    try:
        installed = importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        installed = "not-installed"
    return {
        "type": "library",
        "name": name,
        "version": installed,
        "properties": [{"name": "netrune:declared-requirement", "value": requirement}],
    }


def _source_material() -> list[dict[str, Any]]:
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"], text=True, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, check=False,
    )
    if revision.returncode:
        return []
    commit = revision.stdout.strip()
    dirty = subprocess.run(
        ["git", "diff", "--quiet", "--ignore-submodules", "HEAD"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
    ).returncode != 0
    return [{
        "uri": "git+source",
        "digest": {"gitCommit": commit},
        "annotations": {"dirtyWorkingTree": dirty},
    }]


def release_metadata(version: str, artifacts: Iterable[Path]) -> dict[str, Any]:
    files = _validated_artifacts(artifacts)
    subjects = [{"name": path.name, "digest": {"sha256": sha256(path)}, "size": path.stat().st_size} for path in files]
    requirements = []
    try:
        distribution = importlib.metadata.distribution("netrune")
        requirements = list(distribution.requires or [])
    except importlib.metadata.PackageNotFoundError:
        requirements = ["rich>=14,<16"]
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH") or time.time())
    timestamp = _rfc3339(epoch)
    subject_fingerprint = "|".join(item["digest"]["sha256"] for item in subjects)
    serial = uuid.UUID(hashlib.sha256(f"{version}|{subject_fingerprint}".encode("utf-8")).hexdigest()[:32])
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {"timestamp": timestamp, "component": {"type": "application", "name": "netrune", "version": version}},
        "components": [_requirement_component(requirement) for requirement in requirements],
    }
    provenance = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": item["name"], "digest": item["digest"]} for item in subjects],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://github.com/pypa/build",
                "externalParameters": {"distribution": "netrune", "version": version},
                "internalParameters": {"python": platform.python_version(), "platform": platform.platform()},
                "resolvedDependencies": _source_material(),
            },
            "runDetails": {
                "builder": {"id": "netrune/local-release"},
                "metadata": {
                    "invocationId": os.environ.get("GITHUB_RUN_ID", "local"),
                    "startedOn": timestamp,
                    "finishedOn": timestamp,
                },
            },
        },
    }
    return {"subjects": subjects, "sbom": sbom, "provenance": provenance}


def write_release_metadata(version: str, artifacts: Iterable[Path], output_dir: Path) -> dict[str, Path]:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    metadata = release_metadata(version, artifacts)
    checksum_path = output_dir / "SHA256SUMS"
    checksum_path.write_text("".join(f"{item['digest']['sha256']}  {item['name']}\n" for item in metadata["subjects"]), encoding="utf-8")
    sbom_path = output_dir / f"netrune-{version}.sbom.cdx.json"
    sbom_path.write_text(json.dumps(metadata["sbom"], indent=2, sort_keys=True) + "\n", encoding="utf-8")
    provenance_path = output_dir / f"netrune-{version}.provenance.json"
    provenance_path.write_text(json.dumps(metadata["provenance"], indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {"checksums": checksum_path, "sbom": sbom_path, "provenance": provenance_path}


def sign_files(paths: Iterable[Path]) -> list[Path]:
    signatures: list[Path] = []
    for path in paths:
        signature = Path(str(path) + ".asc")
        process = subprocess.run(
            ["gpg", "--batch", "--yes", "--armor", "--detach-sign", "--output", str(signature), str(path)],
            check=False,
        )
        if process.returncode:
            raise RuntimeError(f"GPG signing failed for {path.name}")
        signatures.append(signature)
    return signatures
