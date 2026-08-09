#!/usr/bin/env python3
"""Compatibility import for :mod:`netops_platform.devices` through v8.x."""

import os
import sys

from netops_platform import devices as _implementation


globals().update({name: getattr(_implementation, name) for name in dir(_implementation) if not name.startswith("__")})


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BrokenPipeError:
        with open(os.devnull, "w", encoding="ascii") as sink:
            os.dup2(sink.fileno(), sys.stdout.fileno())
        raise SystemExit(0)
else:
    sys.modules[__name__] = _implementation
