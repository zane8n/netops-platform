#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
    printf 'Usage: %s <wheel>\n' "$0" >&2
    exit 2
fi

root=$(cd "$(dirname "$0")/.." && pwd)
wheel=$(realpath "$1")
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
export HOME="$work/home"
export XDG_CONFIG_HOME="$work/config"
export XDG_STATE_HOME="$work/state"
export XDG_CACHE_HOME="$work/cache"
export XDG_DATA_HOME="$work/data"
export NETRUNE_INSTALL_ROOT="$work/runtime"
export NETRUNE_BIN_DIR="$work/bin"

bash "$root/install.sh" "$wheel"
first=$(readlink -f "$NETRUNE_INSTALL_ROOT/current")
"$NETRUNE_BIN_DIR/netrune" version
"$NETRUNE_BIN_DIR/netops" version >/dev/null
bash "$root/install.sh" "$wheel"
second=$(readlink -f "$NETRUNE_INSTALL_ROOT/current")
[[ "$first" != "$second" ]]
bash "$root/install.sh" --rollback
[[ $(readlink -f "$NETRUNE_INSTALL_ROOT/current") == "$first" ]]
bash "$root/uninstall.sh"
[[ ! -e "$NETRUNE_BIN_DIR/netrune" && ! -e "$NETRUNE_BIN_DIR/netops" && -d "$NETRUNE_INSTALL_ROOT" ]]
bash "$root/uninstall.sh" --remove-runtime
[[ ! -e "$NETRUNE_INSTALL_ROOT" ]]
[[ -d "$XDG_CONFIG_HOME/netrune" && -d "$XDG_STATE_HOME/netrune" ]]
printf 'Atomic install, rollback, and uninstall smoke test passed.\n'
