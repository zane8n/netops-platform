"""Compatibility import for :mod:`netops_platform.identity` through v8.x."""

import sys

from netops_platform import identity as _implementation


globals().update({name: getattr(_implementation, name) for name in dir(_implementation) if not name.startswith("__")})
sys.modules[__name__] = _implementation
