#!/usr/bin/env bash
set -euo pipefail

python_bin="${PYTHON:-python3}"
runtime="${NETRUNE_INSTALL_ROOT:-${NETOPS_INSTALL_ROOT:-$HOME/.local/share/netrune/runtime}}"
bin_dir="${NETRUNE_BIN_DIR:-${NETOPS_BIN_DIR:-$HOME/.local/bin}}"
action="install"
source_spec="."

usage() {
    printf 'Usage: %s [WHEEL|SOURCE]\n       %s --rollback\n' "$0" "$0"
}

if [[ $# -gt 1 ]]; then
    usage >&2
    exit 2
elif [[ ${1:-} == "--rollback" ]]; then
    action="rollback"
elif [[ ${1:-} == "-h" || ${1:-} == "--help" ]]; then
    usage
    exit 0
elif [[ $# -eq 1 ]]; then
    source_spec="$1"
fi

if [[ -z "$runtime" || "$runtime" == "/" || -z "$bin_dir" || "$bin_dir" == "/" ]]; then
    printf 'Error: unsafe install or console directory.\n' >&2
    exit 2
fi

atomic_link() {
    local target="$1" link="$2" staged="${2}.tmp.$$"
    if [[ -e "$link" && ! -L "$link" ]]; then
        printf 'Error: refusing to replace non-symlink: %s\n' "$link" >&2
        return 1
    fi
    rm -f -- "$staged"
    ln -s -- "$target" "$staged"
    mv -Tf -- "$staged" "$link"
}

if [[ "$action" == "rollback" ]]; then
    if [[ ! -L "$runtime/current" || ! -L "$runtime/previous" ]]; then
        printf 'Error: rollback requires both current and previous installed releases.\n' >&2
        exit 1
    fi
    current_target=$(readlink -f "$runtime/current")
    previous_target=$(readlink -f "$runtime/previous")
    [[ -x "$previous_target/bin/netrune" ]] || { printf 'Error: previous Netrune release is incomplete.\n' >&2; exit 1; }
    atomic_link "$current_target" "$runtime/previous"
    atomic_link "$previous_target" "$runtime/current"
    printf 'Rolled back Netrune to %s\n' "$previous_target"
    "$runtime/current/bin/netrune" version
    exit 0
fi

if ! command -v "$python_bin" >/dev/null 2>&1; then
    printf 'Error: Python 3.11 or newer is required.\n' >&2
    exit 1
fi
"$python_bin" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' || {
    printf 'Error: Python 3.11 or newer is required.\n' >&2
    exit 1
}

mkdir -p "$runtime/releases" "$bin_dir"
stamp=$(date -u +%Y%m%dT%H%M%SZ)
release="$runtime/releases/release-${stamp}-$$"
old_current=""
[[ -L "$runtime/current" ]] && old_current=$(readlink -f "$runtime/current")
cleanup_release=true
cleanup() {
    if [[ "$cleanup_release" == true && -n "${release:-}" && -d "$release" ]]; then
        rm -rf -- "$release"
    fi
}
trap cleanup EXIT

"$python_bin" -m venv "$release"
"$release/bin/python" -m pip install "$source_spec"
installed_version=$("$release/bin/python" -c 'from importlib.metadata import version; print(version("netrune"))')
printf '%s\n' "$installed_version" > "$release/NETRUNE_VERSION"
"$release/bin/netrune" version >/dev/null

if [[ -n "$old_current" && -x "$old_current/bin/netrune" ]]; then
    atomic_link "$old_current" "$runtime/previous"
fi
atomic_link "$release" "$runtime/current"
for command in netrune netops netop; do
    atomic_link "$runtime/current/bin/$command" "$bin_dir/$command"
done

set +e
"$runtime/current/bin/netrune" init
init_status=$?
set -e
if [[ $init_status -ne 0 && $init_status -ne 3 ]]; then
    printf 'Error: profile initialization failed with exit code %s.\n' "$init_status" >&2
    if [[ -n "$old_current" ]]; then
        atomic_link "$old_current" "$runtime/current"
    else
        rm -f -- "$runtime/current"
        for command in netrune netops netop; do
            [[ -L "$bin_dir/$command" ]] && rm -f -- "$bin_dir/$command"
        done
    fi
    exit "$init_status"
fi

cleanup_release=false
printf 'Installed Netrune %s into %s\n' "$installed_version" "$release"
printf 'Current release: %s/current\n' "$runtime"
printf 'Console links: %s/netrune (canonical), %s/netops, and %s/netop\n' "$bin_dir" "$bin_dir" "$bin_dir"
if [[ ":$PATH:" != *":$bin_dir:"* ]]; then
    printf 'Add %s to PATH before using the console commands.\n' "$bin_dir"
fi
