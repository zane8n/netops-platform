#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
    printf 'Usage: %s <wheel>\n' "$0" >&2
    exit 2
fi

wheel=$(realpath "$1")
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
python_bin="${PYTHON:-python3}"
export HOME="$work/home"
export XDG_CONFIG_HOME="$work/config"
export XDG_STATE_HOME="$work/state"
export XDG_CACHE_HOME="$work/cache"
export XDG_DATA_HOME="$work/data"

"$python_bin" -m venv "$work/venv"
"$work/venv/bin/python" -m pip install "$wheel"
"$work/venv/bin/netrune" version
"$work/venv/bin/netrune" init --profile smoke
"$work/venv/bin/netrune" --profile smoke commands list --json >/dev/null
"$work/venv/bin/netops" version >/dev/null
for helper in netrune-connect netrune-control netrune-discovery netrune-legacy netrune-probe netrune-lib.sh; do
    test -x "$work/venv/bin/$helper"
done
"$work/venv/bin/netrune-control" --help >/dev/null
"$work/venv/bin/netrune-connect" --help >/dev/null
test -f "$XDG_CONFIG_HOME/netrune/profiles/smoke/profile.toml"
test -f "$XDG_STATE_HOME/netrune/profiles/smoke/netrune.sqlite3"
printf 'Isolated wheel smoke test passed: %s\n' "$wheel"
