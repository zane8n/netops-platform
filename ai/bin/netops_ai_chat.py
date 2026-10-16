"""Compatibility launcher for :mod:`netrune_ai_chat` through v8."""

from netrune_ai_chat import *  # noqa: F401,F403
from netrune_ai_chat import main


if __name__ == "__main__":
    raise SystemExit(main())
