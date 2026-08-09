"""Textual operator console for NetOps."""

from typing import Any

__all__ = ["NetOpsConsole"]


def __getattr__(name: str) -> Any:
    if name == "NetOpsConsole":
        from .app import NetOpsConsole

        return NetOpsConsole
    raise AttributeError(name)
