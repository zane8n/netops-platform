"""Installed Netrune console entrypoint."""

from __future__ import annotations

import sys


def main() -> int:
    from netops_platform.core import main as core_main

    return core_main(sys.argv[1:])


if __name__ == "__main__":
    raise SystemExit(main())
