#!/usr/bin/env bash
set -euo pipefail

runtime="${NETRUNE_INSTALL_ROOT:-${NETOPS_INSTALL_ROOT:-$HOME/.local/share/netrune/runtime}}"
bin_dir="${NETRUNE_BIN_DIR:-${NETOPS_BIN_DIR:-$HOME/.local/bin}}"
remove_runtime=false

case "${1:-}" in
    "") ;;
    --remove-runtime) remove_runtime=true ;;
    -h|--help)
        printf 'Usage: %s [--remove-runtime]\n' "$0"
        printf 'Profile data under XDG config/state/cache/data roots is always retained.\n'
        exit 0
        ;;
    *) printf 'Error: unknown option: %s\n' "$1" >&2; exit 2 ;;
esac

for command in netrune netops netop; do
    link="$bin_dir/$command"
    if [[ -L "$link" && $(readlink "$link") == "$runtime/current/bin/$command" ]]; then
        rm -f -- "$link"
    elif [[ -e "$link" ]]; then
        printf 'Notice: retained unrelated path: %s\n' "$link" >&2
    fi
done

if [[ "$remove_runtime" == true ]]; then
    if [[ -z "$runtime" || "$runtime" == "/" ]]; then
        printf 'Error: unsafe runtime directory.\n' >&2
        exit 2
    fi
    rm -rf -- "$runtime"
    printf 'Removed Netrune runtime: %s\n' "$runtime"
else
    printf 'Removed Netrune console links; retained runtime releases in %s\n' "$runtime"
fi
printf 'XDG profiles and evidence were retained.\n'
