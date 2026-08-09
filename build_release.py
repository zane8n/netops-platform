#!/usr/bin/env python3
"""Build release metadata around already-built wheel and sdist artifacts."""

from __future__ import annotations

import argparse
from pathlib import Path

from netops_platform.privacy import scan_archive, scan_tree
from netops_platform.release import sign_files, write_release_metadata


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("dist_path", nargs="?", type=Path, default=Path("dist"), help="Directory containing wheel and sdist artifacts")
    parser.add_argument("--dist", dest="dist_override", type=Path, help="Compatibility spelling for the artifact directory")
    parser.add_argument("--output", type=Path, default=Path(".release"), help="Directory for checksums, SBOM, provenance, and signatures")
    parser.add_argument("--version", default=Path("VERSION").read_text(encoding="ascii").strip())
    parser.add_argument("--denylist", type=Path, help="Private newline-separated identifiers; defaults to .privacy-denylist")
    parser.add_argument("--sign", action="store_true")
    args = parser.parse_args()
    dist_path = args.dist_override or args.dist_path
    denylist = args.denylist or Path(".privacy-denylist")
    denied = []
    if denylist.is_file():
        denied = [line.strip() for line in denylist.read_text(encoding="utf-8").splitlines() if line.strip() and not line.lstrip().startswith("#")]
    artifacts = sorted([*dist_path.glob("*.whl"), *dist_path.glob("*.tar.gz")])
    if not artifacts:
        parser.error("no wheel or sdist artifacts found; run python -m build first")
    findings = [finding for artifact in artifacts for finding in scan_archive(artifact, denied)]
    if findings:
        for finding in findings:
            print(f"{finding.code}: {finding.path}:{finding.line}: {finding.detail}")
        return 1
    metadata = write_release_metadata(args.version, artifacts, args.output)
    metadata_findings = scan_tree(args.output, denied)
    if metadata_findings:
        for finding in metadata_findings:
            print(f"{finding.code}: {finding.path}:{finding.line}: {finding.detail}")
        return 1
    signatures = sign_files([*artifacts, *metadata.values()]) if args.sign else []
    for name, path in metadata.items():
        print(f"{name}: {path}")
    for path in signatures:
        print(f"signature: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
