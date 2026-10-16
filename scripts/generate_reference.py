#!/usr/bin/env python3
"""Generate or verify registry-derived public reference artifacts."""

from __future__ import annotations

import argparse
import os
import tempfile
from pathlib import Path

from netops_platform.core import App, HELP_TOPICS, VERSION
from netops_platform.docsgen import write_or_check


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="netops-docgen-") as directory:
        root = Path(directory)
        os.environ["NETRUNE_CONFIG_DIR"] = str(root / "config")
        os.environ["NETRUNE_CACHE_DIR"] = str(root / "cache")
        os.environ["NETRUNE_STATE_DIR"] = str(root / "state")
        os.environ["NETRUNE_DATA_DIR"] = str(root / "data")
        app = App(args.root)
        changed = write_or_check(args.root, app.command_registry(), HELP_TOPICS, VERSION, check=args.check)
    if args.check and changed:
        print("Generated reference drift: " + ", ".join(changed))
        return 1
    print(("Checked" if args.check else "Generated") + f" {len(changed)} reference artifact(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
