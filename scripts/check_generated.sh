#!/usr/bin/env bash
set -euo pipefail

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
python_bin="${PYTHON:-python3}"

"$python_bin" generate_reference.py --check
"$python_bin" privacy_check.py --root .
