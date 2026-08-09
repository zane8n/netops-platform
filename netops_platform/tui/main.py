"""Lazy TUI launcher used by the public NetOps entrypoint."""

from __future__ import annotations

import os
from pathlib import Path
import sys
from typing import Any


def parse_tui_args(args: list[str]) -> tuple[str, str]:
    view = "operations"
    target = ""
    index = 0
    while index < len(args):
        if args[index] == "--view" and index + 1 < len(args):
            view = args[index + 1].strip().lower(); index += 2
        elif args[index] == "--target" and index + 1 < len(args):
            target = args[index + 1].strip(); index += 2
        else:
            raise ValueError(f"Unknown TUI option: {args[index]}")
    return view, target


def launch_tui(core: Any, args: list[str] | None = None) -> int:
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print("NetOps TUI requires an interactive terminal. Use a noun-first command or --plain for non-interactive output.", file=sys.stderr)
        return 5
    if os.environ.get("TERM", "").lower() == "dumb":
        print("NetOps TUI cannot run with TERM=dumb. Use --plain or a capable terminal.", file=sys.stderr)
        return 5
    try:
        from netops_platform.service import NetOpsService
        from netops_platform.tui.app import NetOpsConsole
    except ImportError as exc:
        print(f"NetOps TUI dependency is unavailable: {exc}", file=sys.stderr)
        print("Install the packaged console with: pipx install netops-platform", file=sys.stderr)
        return 5
    try:
        view, target = parse_tui_args(list(args or []))
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        print("Usage: netop tui [--view operations|inventory|diagnostics|topology|overview|history|settings] [--target VALUE]", file=sys.stderr)
        return 2
    console = NetOpsConsole(NetOpsService(core), initial_view=view, initial_target=target)
    console.run()
    return int(console.return_code or 0)
