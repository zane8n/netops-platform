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

# Completions and man pages install.sh placed (only Netrune's own names).
data_home="${XDG_DATA_HOME:-$HOME/.local/share}"
for path in "$data_home"/bash-completion/completions/{netrune,netops,netop} \
            "$data_home"/zsh/site-functions/{_netrune,_netops} \
            "$HOME"/.config/fish/completions/{netrune,netops}.fish \
            "$data_home"/man/man1/{netrune,netops}.1; do
    [[ -f "$path" ]] && rm -f -- "$path"
done
for rc in "$HOME/.zshrc" "$HOME/.bashrc"; do
    if [[ -f "$rc" ]] && grep -qF '# >>> netrune >>>' "$rc"; then
        printf 'Notice: %s still has the netrune block (between the # >>> netrune >>> markers); remove it if you no longer want it.\n' "$rc" >&2
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
