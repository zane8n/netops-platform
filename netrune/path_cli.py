"""Netrune path command-line API."""

import sys
from netops_platform import path_cli as _implementation

globals().update({name: getattr(_implementation, name) for name in dir(_implementation) if not name.startswith("__")})
sys.modules[__name__] = _implementation
