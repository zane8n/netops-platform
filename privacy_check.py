#!/usr/bin/env python3
"""Scan a source tree, archive, or clean Git history for publication blockers."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from netops_platform.privacy import scan_archive, scan_git_history, scan_tree


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="*", type=Path)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--denylist", type=Path, help="Private newline-separated identifiers; defaults to ROOT/.privacy-denylist when present")
    parser.add_argument("--git-history", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    denylist = args.denylist or (args.root / ".privacy-denylist")
    denied = []
    if denylist.is_file():
        denied = [line.strip() for line in denylist.read_text(encoding="utf-8").splitlines() if line.strip() and not line.lstrip().startswith("#")]
    findings = scan_tree(args.root, denied)
    for path in args.paths:
        findings.extend(scan_archive(path, denied))
    if args.git_history:
        findings.extend(scan_git_history(args.root, denied))
    payload = {"ok": not findings, "findings": [item.to_dict() for item in findings], "count": len(findings)}
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    elif findings:
        for item in findings:
            print(f"{item.code}: {item.path}:{item.line}: {item.detail}")
        print(f"Privacy scan failed with {len(findings)} finding(s).")
    else:
        print("Privacy scan passed.")
    return 0 if not findings else 1


if __name__ == "__main__":
    raise SystemExit(main())
