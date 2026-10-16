"""Netrune device-driver API."""

import sys
from netops_platform import devices as _implementation

globals().update({name: getattr(_implementation, name) for name in dir(_implementation) if not name.startswith("__")})
sys.modules[__name__] = _implementation
