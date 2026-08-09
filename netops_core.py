#!/usr/bin/env python3
"""Compatibility import for :mod:`netops_platform.core` through v8.x."""

import sys

from netops_platform import core as _implementation


globals().update({name: getattr(_implementation, name) for name in dir(_implementation) if not name.startswith("__")})


if __name__ == "__main__":
    raise SystemExit(main())
sys.modules[__name__] = _implementation
