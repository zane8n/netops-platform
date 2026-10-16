"""Netrune core API with v8 implementation compatibility."""

import sys
from netops_platform import core as _implementation

globals().update({name: getattr(_implementation, name) for name in dir(_implementation) if not name.startswith("__")})
sys.modules[__name__] = _implementation
