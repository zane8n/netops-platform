"""Canonical Netrune Python API.

The implementation remains available through ``netops_platform`` during the
v8 compatibility window. New integrations should import ``netrune``.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version as distribution_version
from pathlib import Path


def version() -> str:
    try:
        return Path(__file__).resolve().parents[1].joinpath("VERSION").read_text(encoding="ascii").strip()
    except OSError:
        try:
            return distribution_version("netrune")
        except PackageNotFoundError:
            return "0.0.0+unknown"


__all__ = ["version"]
