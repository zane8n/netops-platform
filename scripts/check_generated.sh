#!/usr/bin/env bash
set -euo pipefail

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
python_bin="${PYTHON:-python3}"

"$python_bin" scripts/generate_reference.py --check
"$python_bin" scripts/privacy_check.py --root .
