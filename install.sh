#!/usr/bin/env bash
# Netrune installer: from a fresh machine to a working console in one run.
#
#   ./install.sh                       # from a checkout: tools, Netrune, shell, profile
#   ./install.sh --import bundle.tgz   # ... and bring a profile from another machine
#   ./install.sh dist/netrune-*.whl    # a built wheel instead of the checkout
#   ./install.sh --rollback            # back to the previous release
#
# Each step that changes the system (packages through sudo, lines in your
# shell's rc file) asks first in a terminal; without one it is skipped unless
# --yes, so a scripted install never edits what it was not asked to.
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
python_bin="${PYTHON:-python3}"
runtime="${NETRUNE_INSTALL_ROOT:-${NETOPS_INSTALL_ROOT:-$HOME/.local/share/netrune/runtime}}"
bin_dir="${NETRUNE_BIN_DIR:-${NETOPS_BIN_DIR:-$HOME/.local/bin}}"
data_home="${XDG_DATA_HOME:-$HOME/.local/share}"
extras="${NETRUNE_INSTALL_EXTRAS-excel}"
action="install"
source_spec=""
deps="ask"
shell_setup="ask"
assume_yes=false
import_bundle=""

usage() {
    cat <<EOF
Usage: $0 [WHEEL|SOURCE] [--deps|--no-deps] [--no-shell] [--import BUNDLE] [--yes]
       $0 --rollback

  WHEEL|SOURCE    what to install (default: this checkout)
  --deps          install missing system tools without asking (needs sudo)
  --no-deps       never install system tools; only report what is missing
  --no-shell      leave PATH, completions, and man pages alone
  --import FILE   restore a profile written by 'netrune profile export'
  --yes           answer yes to every question (packages, shell rc)
  --rollback      make the previous release current again

Environment: PYTHON, NETRUNE_INSTALL_ROOT, NETRUNE_BIN_DIR,
NETRUNE_INSTALL_EXTRAS (default "excel"; empty for none),
NETRUNE_BUNDLE_PASSPHRASE (for an encrypted --import bundle).
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --rollback) action="rollback"; shift ;;
        -h|--help) usage; exit 0 ;;
        --deps) deps="yes"; shift ;;
        --no-deps) deps="no"; shift ;;
        --no-shell) shell_setup="no"; shift ;;
        --yes|-y) assume_yes=true; shift ;;
        --import)
            [[ $# -ge 2 ]] || { usage >&2; exit 2; }
            import_bundle=$(realpath -- "$2"); shift 2 ;;
        -*) printf 'Unknown option: %s\n' "$1" >&2; usage >&2; exit 2 ;;
        *)
            [[ -z "$source_spec" ]] || { usage >&2; exit 2; }
            source_spec="$1"; shift ;;
    esac
done
if [[ -z "$source_spec" ]]; then
    # The checkout this script came from, wherever it is run from.
    if [[ -f "$script_dir/pyproject.toml" ]]; then source_spec="$script_dir"; else source_spec="."; fi
fi

if [[ -z "$runtime" || "$runtime" == "/" || -z "$bin_dir" || "$bin_dir" == "/" ]]; then
    printf 'Error: unsafe install or console directory.\n' >&2
    exit 2
fi

interactive() { [[ -t 0 && -t 1 ]]; }

# ask QUESTION MODE: MODE is yes/no/ask; yes without a terminal only with --yes.
ask() {
    local question="$1" mode="$2" answer
    [[ "$mode" == "yes" ]] && return 0
    [[ "$mode" == "no" ]] && return 1
    $assume_yes && return 0
    interactive || return 1
    read -r -p "$question [Y/n] " answer
    [[ -z "$answer" || "$answer" =~ ^[Yy] ]]
}

step() { printf '\n==> %s\n' "$1"; }

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

# --- System tools -----------------------------------------------------------
# command -> package, per package manager. Only what is missing is installed.
declare -A apt_pkg=([python3]=python3 [snmpget]=snmp [snmpbulkwalk]=snmp [sshpass]=sshpass [gpg]=gnupg
    [expect]=expect [jq]=jq [sqlite3]=sqlite3 [curl]=curl [openssl]=openssl [traceroute]=traceroute
    [iperf3]=iperf3 [perl]=perl [ping]=iputils-ping [dig]=dnsutils [ipcalc]=ipcalc [nc]=netcat-openbsd [ip]=iproute2)
declare -A dnf_pkg=([python3]=python3 [snmpget]=net-snmp-utils [snmpbulkwalk]=net-snmp-utils [sshpass]=sshpass [gpg]=gnupg2
    [expect]=expect [jq]=jq [sqlite3]=sqlite [curl]=curl [openssl]=openssl [traceroute]=traceroute
    [iperf3]=iperf3 [perl]=perl [ping]=iputils [dig]=bind-utils [ipcalc]=ipcalc [nc]=nmap-ncat [ip]=iproute)
declare -A pacman_pkg=([python3]=python [snmpget]=net-snmp [snmpbulkwalk]=net-snmp [sshpass]=sshpass [gpg]=gnupg
    [expect]=expect [jq]=jq [sqlite3]=sqlite [curl]=curl [openssl]=openssl [traceroute]=traceroute
    [iperf3]=iperf3 [perl]=perl [ping]=iputils [dig]=bind [ipcalc]=ipcalc [nc]=openbsd-netcat [ip]=iproute2)
declare -A zypper_pkg=([python3]=python3 [snmpget]=net-snmp [snmpbulkwalk]=net-snmp [sshpass]=sshpass [gpg]=gpg2
    [expect]=expect [jq]=jq [sqlite3]=sqlite3 [curl]=curl [openssl]=openssl [traceroute]=traceroute
    [iperf3]=iperf [perl]=perl [ping]=iputils [dig]=bind-utils [ipcalc]=ipcalc [nc]=netcat-openbsd [ip]=iproute2)
tools=(python3 snmpget snmpbulkwalk sshpass gpg expect jq sqlite3 curl openssl traceroute iperf3 perl ping dig ipcalc nc ip)

package_manager() {
    local manager
    for manager in apt-get dnf pacman zypper; do
        command -v "$manager" >/dev/null 2>&1 && { printf '%s\n' "$manager"; return 0; }
    done
    return 1
}

missing=()
for tool in "${tools[@]}"; do
    command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
done
# Debian ships venv support separately; without it 'python3 -m venv' fails.
venv_missing=false
if command -v "$python_bin" >/dev/null 2>&1 && ! "$python_bin" -c 'import ensurepip' >/dev/null 2>&1; then
    venv_missing=true
fi

step "System tools"
if [[ ${#missing[@]} -eq 0 && "$venv_missing" == false ]]; then
    printf 'All present.\n'
else
    manager=$(package_manager || true)
    packages=()
    if [[ -n "$manager" ]]; then
        declare -n map="${manager%-get}_pkg"
        for tool in "${missing[@]}"; do
            [[ -n "${map[$tool]:-}" && " ${packages[*]} " != *" ${map[$tool]} "* ]] && packages+=("${map[$tool]}")
        done
        [[ "$venv_missing" == true && "$manager" == "apt-get" ]] && packages+=(python3-venv python3-pip)
    fi
    note="${missing[*]:-}"
    [[ "$venv_missing" == true ]] && note+="${note:+, }python venv support"
    printf 'Missing: %s\n' "$note"
    if [[ -z "$manager" ]]; then
        printf 'No apt-get, dnf, pacman, or zypper here: install them with your package manager.\n'
    elif [[ ${#packages[@]} -gt 0 ]] && ask "Install ${packages[*]} with $manager (sudo)?" "$deps"; then
        sudo_cmd=(); [[ $EUID -ne 0 ]] && sudo_cmd=(sudo)
        case "$manager" in
            apt-get) "${sudo_cmd[@]}" apt-get update -qq && "${sudo_cmd[@]}" apt-get install -y "${packages[@]}" ;;
            dnf) "${sudo_cmd[@]}" dnf install -y "${packages[@]}" ;;
            pacman) "${sudo_cmd[@]}" pacman -S --needed --noconfirm "${packages[@]}" ;;
            zypper) "${sudo_cmd[@]}" zypper --non-interactive install "${packages[@]}" ;;
        esac || printf 'Package install did not finish; Netrune still installs, and the commands needing those tools say so.\n'
    elif [[ ${#packages[@]} -gt 0 ]]; then
        printf 'Skipped. To add them later: sudo %s install %s\n' "$manager" "${packages[*]}"
    fi
fi

# --- Netrune itself ---------------------------------------------------------
step "Netrune"
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
# The excel extra (openpyxl) is wanted by excel sync/report; without network
# it is skipped rather than failing the install.
if [[ -n "$extras" ]] && "$release/bin/python" -m pip install -q "${source_spec}[${extras}]"; then
    :
else
    [[ -n "$extras" ]] && printf 'Installing without the %s extra (pip could not fetch it).\n' "$extras"
    "$release/bin/python" -m pip install -q "$source_spec"
fi
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

# --- Shell: completions, man pages, PATH ------------------------------------
if [[ "$shell_setup" != "no" ]]; then
    step "Shell"
    if [[ -d "$script_dir/completions" ]]; then
        mkdir -p "$data_home/bash-completion/completions" "$data_home/zsh/site-functions" "$HOME/.config/fish/completions"
        for command in netrune netops; do
            cp -f -- "$script_dir/completions/$command.bash" "$data_home/bash-completion/completions/$command"
            cp -f -- "$script_dir/completions/_$command" "$data_home/zsh/site-functions/_$command"
            cp -f -- "$script_dir/completions/$command.fish" "$HOME/.config/fish/completions/$command.fish"
        done
        cp -f -- "$script_dir/completions/netops.bash" "$data_home/bash-completion/completions/netop"
        printf 'Completions installed for bash, zsh, and fish.\n'
    fi
    if [[ -d "$script_dir/man" ]]; then
        mkdir -p "$data_home/man/man1"
        cp -f -- "$script_dir"/man/*.1 "$data_home/man/man1/"
        printf 'Man pages installed: man netrune\n'
    fi
    login_shell=$(basename -- "${SHELL:-bash}")
    case "$login_shell" in
        zsh) rc="$HOME/.zshrc" ;;
        bash) rc="$HOME/.bashrc" ;;
        *) rc="" ;;
    esac
    marker="# >>> netrune >>>"
    if [[ -n "$rc" ]] && ! grep -qF "$marker" "$rc" 2>/dev/null; then
        block="$marker"$'\n'
        [[ ":$PATH:" != *":$bin_dir:"* ]] && block+="export PATH=\"$bin_dir:\$PATH\""$'\n'
        if [[ "$login_shell" == zsh ]]; then
            block+="fpath=(\"$data_home/zsh/site-functions\" \$fpath)"$'\n'
            block+="(( \$+functions[compdef] )) && autoload -Uz _netrune _netops && compdef _netrune netrune && compdef _netops netops netop"$'\n'
        fi
        block+="# <<< netrune <<<"
        if ask "Add Netrune's PATH and completions to $rc?" "$shell_setup"; then
            touch "$rc"
            cp -p -- "$rc" "$rc.before-netrune"
            if grep -q 'zoxide init' "$rc"; then
                # zoxide wants to be initialised last: the block goes just before
                # it, above the comment lines that introduce it.
                awk -v block="$block" '
                    done { print; next }
                    /^[[:space:]]*#/ { held = held $0 "\n"; next }
                    /zoxide init/ { print block; print ""; printf "%s", held; print; done = 1; held = ""; next }
                    { printf "%s", held; held = ""; print }
                    END { printf "%s", held }' "$rc.before-netrune" > "$rc"
            else
                printf '\n%s\n' "$block" >> "$rc"
            fi
            printf 'Added to %s (previous copy: %s.before-netrune). Open a new terminal to use it.\n' "$rc" "$rc"
        elif [[ ":$PATH:" != *":$bin_dir:"* ]]; then
            printf 'Add %s to PATH before using the console commands.\n' "$bin_dir"
        fi
    fi
elif [[ ":$PATH:" != *":$bin_dir:"* ]]; then
    printf 'Add %s to PATH before using the console commands.\n' "$bin_dir"
fi

# --- Profile from another machine -------------------------------------------
netrune="$runtime/current/bin/netrune"
if [[ -n "$import_bundle" ]]; then
    step "Profile"
    "$netrune" profile import "$import_bundle"
    if interactive && ! $assume_yes && ask "Store the SSH password in this machine's vault now (netrune vault set)?" ask; then
        "$netrune" vault set || printf 'Run netrune vault set when ready.\n'
    fi
fi

step "Ready"
"$netrune" config validate >/dev/null 2>&1 && printf 'Configuration valid.\n' || printf 'Check the configuration: netrune config validate\n'
if [[ ${#missing[@]} -gt 0 ]]; then
    still=()
    for tool in "${missing[@]}"; do command -v "$tool" >/dev/null 2>&1 || still+=("$tool"); done
    [[ ${#still[@]} -gt 0 ]] && printf 'Still missing (the features using them will say so): %s\n' "${still[*]}"
fi
printf 'Try: netrune workflow morning-check   |   netrune help\n'
