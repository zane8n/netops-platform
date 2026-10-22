"""Netrune excel_reports API."""

import sys
from netops_platform import excel_reports as _implementation

globals().update({name: getattr(_implementation, name) for name in dir(_implementation) if not name.startswith("__")})
sys.modules[__name__] = _implementation
