#!/usr/bin/env bash
#
# Turn a Linux machine -- Arch, Debian-family, or Fedora, including a WSL2 distro
# on Windows -- into a Netrune traffic poller.
#
# A poller exists because SNMP and ICMP have to originate from the monitored
# network. It runs a stock netrune install, no fork and no stripped build, in
# its own profile.
#
# It collects and nothing else. No exposition, no time-series database, no
# dashboards: the machine that pulls from it keeps the readings and draws them.
# That means no new listener on the monitored network beyond the SSH the pull
# already rides, and nothing here to patch that was not already being patched.
#
# Every step checks before it acts. This script is for recovery and reinstall as
# much as for first setup, and running it twice must leave the machine in the
# state running it once did.
#
# Usage:
#   ./poller-install.sh                       # wheel beside this script, LAN only
#   ./poller-install.sh --collector-id site-a-poller
#   ./poller-install.sh --wheel ./netrune.whl --retention 365
#   ./poller-install.sh --dry-run
set -euo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
COLLECTOR_ID=""
PROFILE="poller"
WHEEL=""
PYPI_SPEC=""
RETENTION_DAYS="365"
VENV="${HOME}/.local/share/netrune-poller/venv"
DRY_RUN="false"
TAILSCALE_AUTHKEY=""
USE_TAILSCALE="false"

log()   { printf '\033[0;36m[poller]\033[0m %s\n' "$*"; }
ok()    { printf '\033[0;32m[  ok  ]\033[0m %s\n' "$*"; }
skip()  { printf '\033[0;90m[ skip ]\033[0m %s\n' "$*"; }
warn()  { printf '\033[0;33m[ warn ]\033[0m %s\n' "$*" >&2; }
die()   { printf '\033[0;31m[ fail ]\033[0m %s\n' "$*" >&2; exit 1; }

run() {
    if [[ "$DRY_RUN" == "true" ]]; then
        printf '\033[0;90m[ would ]\033[0m %s\n' "$*"
        return 0
    fi
    "$@"
}

usage() {
    sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'
    cat <<'EOF'

Options:
  --collector-id NAME    Identity stamped on every reading. Default: hostname.
  --profile NAME         Netrune profile to isolate poller state. Default: poller.
  --wheel PATH           Wheel to install. Default: the newest one beside this script.
  --pypi-spec SPEC       Install from PyPI instead of a wheel.
  --retention DAYS       How long the poller keeps readings. Default: 365.
  --venv PATH            Where to build the virtualenv.
  --tailscale [KEY]      Also join a tailnet, so the puller can be off-site.
  --dry-run              Print what would happen; change nothing.
  -h, --help             This text.
EOF
}

while (($#)); do
    case "$1" in
        --collector-id) COLLECTOR_ID="${2:?}"; shift 2 ;;
        --profile)      PROFILE="${2:?}"; shift 2 ;;
        --wheel)        WHEEL="${2:?}"; shift 2 ;;
        --pypi-spec)    PYPI_SPEC="${2:?}"; shift 2 ;;
        --retention)    RETENTION_DAYS="${2:?}"; shift 2 ;;
        --venv)         VENV="${2:?}"; shift 2 ;;
        --tailscale)    USE_TAILSCALE="true"
                        [[ "${2:-}" == --* || -z "${2:-}" ]] || { TAILSCALE_AUTHKEY="$2"; shift; }
                        shift ;;
        --dry-run)      DRY_RUN="true"; shift ;;
        -h|--help)      usage; exit 0 ;;
        *)              die "Unknown option: $1 (try --help)" ;;
    esac
done

[[ -n "$COLLECTOR_ID" ]] || COLLECTOR_ID="$(hostname -s 2>/dev/null || hostname)"
[[ "$COLLECTOR_ID" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || die "Collector id must be 1-64 characters of A-Z a-z 0-9 . _ -"
[[ "$RETENTION_DAYS" =~ ^[0-9]+$ ]] || die "--retention takes a number of days."

# ---------------------------------------------------------------------------
log "1/8  Where this is running"
# ---------------------------------------------------------------------------
IS_WSL="false"
if [[ -n "${WSL_DISTRO_NAME:-}" ]] || grep -qi microsoft /proc/version 2>/dev/null; then
    IS_WSL="true"
    ok "WSL detected (${WSL_DISTRO_NAME:-unknown distro})"
fi

if [[ ! -d /run/systemd/system ]]; then
    if [[ "$IS_WSL" == "true" ]]; then
        # WSL runs no init by default, so there is nothing to start a service.
        # This is the single most common reason a WSL poller looks installed and
        # never collects: the units exist, `systemctl` reports failure that gets
        # read as a permissions problem, and nothing ever runs.
        if [[ -f /etc/wsl.conf ]] && grep -q '^systemd *= *true' /etc/wsl.conf; then
            die "systemd is enabled in /etc/wsl.conf but not running yet.
       Run this in PowerShell, then start the distro again and re-run me:
           wsl --shutdown"
        fi
        warn "WSL is not running systemd, so nothing can supervise the collector."
        if [[ "$DRY_RUN" != "true" ]]; then
            log "Enabling systemd in /etc/wsl.conf"
            sudo tee -a /etc/wsl.conf >/dev/null <<'WSLCONF'

[boot]
systemd=true
WSLCONF
        fi
        die "Enabled systemd. Run this in PowerShell, then start the distro again and re-run me:
           wsl --shutdown"
    fi
    die "This machine is not running systemd, so nothing can supervise the collector."
fi
ok "systemd is running"

# ---------------------------------------------------------------------------
log "2/8  System packages"
# ---------------------------------------------------------------------------
# The collector shells out to snmpget and snmpwalk, pings for ICMP watches, and
# is reached over SSH. Everything else it needs is Python.
NEEDED=()
if command -v pacman >/dev/null 2>&1; then
    PACKAGER="pacman"
    SSH_UNIT="sshd"
    for package in python net-snmp iputils openssh; do
        pacman -Qq "$package" >/dev/null 2>&1 || NEEDED+=("$package")
    done
    ((${#NEEDED[@]} == 0)) || INSTALL_CMD=(sudo pacman -S --needed --noconfirm "${NEEDED[@]}")
elif command -v apt-get >/dev/null 2>&1; then
    PACKAGER="apt"
    SSH_UNIT="ssh"
    for package in python3 python3-venv python3-pip snmp iputils-ping openssh-server; do
        dpkg -s "$package" >/dev/null 2>&1 || NEEDED+=("$package")
    done
    ((${#NEEDED[@]} == 0)) || INSTALL_CMD=(sudo sh -c "apt-get update -qq && apt-get install -y -qq ${NEEDED[*]}")
elif command -v dnf >/dev/null 2>&1; then
    PACKAGER="dnf"
    SSH_UNIT="sshd"
    for package in python3 net-snmp-utils iputils openssh-server; do
        rpm -q "$package" >/dev/null 2>&1 || NEEDED+=("$package")
    done
    ((${#NEEDED[@]} == 0)) || INSTALL_CMD=(sudo dnf install -y "${NEEDED[@]}")
else
    die "No pacman, apt-get, or dnf here. Install python, net-snmp, iputils and openssh by hand,
       then re-run: this script only needs them present, not installed by it."
fi
if ((${#NEEDED[@]})); then
    log "Installing with $PACKAGER: ${NEEDED[*]}"
    run "${INSTALL_CMD[@]}"
    ok "Installed ${#NEEDED[@]} package(s)"
else
    skip "All required packages are present ($PACKAGER)"
fi
for binary in snmpget snmpwalk ping; do
    command -v "$binary" >/dev/null 2>&1 || [[ "$DRY_RUN" == "true" ]] || \
        die "$binary is not on PATH after installing packages; the collector cannot work without it."
done

PYTHON_OK=$(python3 -c 'import sys; print("yes" if sys.version_info >= (3,11) else "no")' 2>/dev/null || echo no)
[[ "$PYTHON_OK" == "yes" || "$DRY_RUN" == "true" ]] || \
    die "Netrune needs Python 3.11 or newer; this machine has $(python3 -V 2>&1)."
ok "Python $(python3 -V 2>&1 | cut -d' ' -f2)"

# ---------------------------------------------------------------------------
log "3/8  Virtualenv and netrune"
# ---------------------------------------------------------------------------
if [[ -z "$PYPI_SPEC" && -z "$WHEEL" ]]; then
    # A wheel copied alongside this script is the default because it needs no
    # index, no proxy, and no internet -- which is the situation a machine on a
    # management network is usually in.
    WHEEL="$(ls -1t "$HERE"/*.whl 2>/dev/null | head -1 || true)"
    [[ -n "$WHEEL" ]] || die "No wheel found beside this script and no --pypi-spec given.
       Copy the .whl next to poller-install.sh, or pass --wheel PATH."
fi

if [[ -x "$VENV/bin/netrune" ]]; then
    skip "netrune already installed at $VENV"
else
    [[ -d "$VENV" ]] || run python3 -m venv "$VENV"
    run "$VENV/bin/pip" install --quiet --upgrade pip
    if [[ -n "$WHEEL" ]]; then
        [[ -f "$WHEEL" ]] || die "No such wheel: $WHEEL"
        run "$VENV/bin/pip" install --quiet "$WHEEL"
        ok "Installed netrune from $(basename "$WHEEL")"
    else
        run "$VENV/bin/pip" install --quiet "$PYPI_SPEC"
        ok "Installed $PYPI_SPEC"
    fi
fi
NETRUNE="$VENV/bin/netrune"
[[ -x "$NETRUNE" || "$DRY_RUN" == "true" ]] || die "The install did not produce $NETRUNE."
mkdir -p "${HOME}/.local/bin"
if [[ -e "${HOME}/.local/bin/netrune" ]]; then
    skip "netrune is already on PATH at ~/.local/bin/netrune"
else
    run ln -sf "$NETRUNE" "${HOME}/.local/bin/netrune"
    ok "Linked ~/.local/bin/netrune"
fi

# ---------------------------------------------------------------------------
log "4/8  Reachability"
# ---------------------------------------------------------------------------
# The puller reaches this machine over SSH and nothing else, so all that is
# needed here is an address to tell it about.
LAN_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -1)"
[[ -n "$LAN_IP" ]] || LAN_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
[[ -n "$LAN_IP" || "$DRY_RUN" != "true" ]] || LAN_IP="192.0.2.10"
ok "LAN address: ${LAN_IP:-unknown}"

if [[ "$IS_WSL" == "true" ]]; then
    if [[ "$LAN_IP" == 172.* ]]; then
        warn "This distro is behind WSL's NAT, so ${LAN_IP} is not reachable from your laptop."
        warn "The Windows bootstrap sets up the forwarding; if you ran this by hand, see"
        warn "  scripts/poller-bootstrap.ps1 -ConfigureNetworkOnly"
    else
        ok "WSL is mirroring the host's network, so this address is reachable directly"
    fi
fi

if [[ "$USE_TAILSCALE" == "true" ]]; then
    command -v tailscale >/dev/null 2>&1 || run bash -c 'curl -fsSL https://tailscale.com/install.sh | sh'
    if tailscale status >/dev/null 2>&1; then
        skip "Already on the tailnet"
    elif [[ -n "$TAILSCALE_AUTHKEY" ]]; then
        run sudo tailscale up --authkey "$TAILSCALE_AUTHKEY" --hostname "$COLLECTOR_ID"
    else
        run sudo tailscale up --hostname "$COLLECTOR_ID"
    fi
    TAILSCALE_IP="$(tailscale ip -4 2>/dev/null | head -1 || true)"
    [[ -n "$TAILSCALE_IP" ]] && { ok "Tailnet address: $TAILSCALE_IP"; LAN_IP="$TAILSCALE_IP"; }
fi

if systemctl is-active --quiet ssh 2>/dev/null || systemctl is-active --quiet sshd 2>/dev/null; then
    skip "SSH is already running"
else
    run sudo systemctl enable --now "${SSH_UNIT:-sshd}"
    ok "Started SSH"
fi

# ---------------------------------------------------------------------------
log "5/8  Netrune profile and collector identity"
# ---------------------------------------------------------------------------
if "$NETRUNE" profile list --plain 2>/dev/null | awk 'NR>2 {print $2}' | grep -qFx "$PROFILE"; then
    skip "Profile '$PROFILE' exists"
else
    run "$NETRUNE" profile create "$PROFILE" || true
fi
run "$NETRUNE" profile use "$PROFILE"

# The collector id is what keeps this machine's readings distinguishable from
# the laptop's after they are merged. A pull refuses outright if the two match.
CURRENT_ID="$("$NETRUNE" --profile "$PROFILE" config get traffic_collector_id --plain 2>/dev/null | tail -1 || true)"
if [[ "$CURRENT_ID" == "$COLLECTOR_ID" ]]; then
    skip "Collector id is already '$COLLECTOR_ID'"
else
    run "$NETRUNE" --profile "$PROFILE" config set traffic_collector_id "$COLLECTOR_ID"
    ok "Collector id set to '$COLLECTOR_ID'"
fi
run "$NETRUNE" --profile "$PROFILE" config set traffic_retention_days "$RETENTION_DAYS"
ok "Keeping readings for ${RETENTION_DAYS} days"
run "$NETRUNE" --profile "$PROFILE" db migrate >/dev/null

# ---------------------------------------------------------------------------
log "6/8  Collector units"
# ---------------------------------------------------------------------------
run "$NETRUNE" --profile "$PROFILE" traffic stack init --role collector
run "$NETRUNE" --profile "$PROFILE" traffic stack up
ok "Installed and started the collector"

# ---------------------------------------------------------------------------
log "7/8  Linger"
# ---------------------------------------------------------------------------
# This is the step that decides whether the poller actually works.
#
# systemd --user units run inside a user manager that, by default, starts at
# login and stops when the last session closes. A poller has no session: nobody
# logs in after a reboot. Without linger the units are enabled, look correct in
# every file on disk, and simply never run. Enabling linger starts the user
# manager at boot instead, independently of any login.
#
# Do not remove this step because "the units are enabled already". Enabled and
# running are different things here, and the difference is invisible until the
# machine reboots unattended and the readings stop.
if [[ "$(loginctl show-user "$(whoami)" -p Linger --value 2>/dev/null)" == "yes" ]]; then
    skip "Linger is already enabled for $(whoami)"
else
    run sudo loginctl enable-linger "$(whoami)"
    ok "Enabled linger for $(whoami): units now survive logout and reboot"
fi

# ---------------------------------------------------------------------------
log "8/8  Verification"
# ---------------------------------------------------------------------------
if [[ "$DRY_RUN" != "true" ]]; then
    sleep 2
    "$NETRUNE" --profile "$PROFILE" traffic stack status || true
fi

cat <<EOF

$(printf '\033[0;32m%s\033[0m' "Poller ready.")

  collector id   $COLLECTOR_ID
  profile        $PROFILE
  address        ${LAN_IP:-unknown}
  ssh user       $(whoami)
  keeps readings ${RETENTION_DAYS} days

It collects only. Nothing listens here but SSH, and the machine that pulls from
it keeps and draws the readings.

On the laptop, once its key is authorised here:

  ssh-copy-id $(whoami)@${LAN_IP:-<address>}
  netrune traffic remote add ${COLLECTOR_ID} --host ${LAN_IP:-<address>} --ssh-user $(whoami) --profile-name ${PROFILE}

Then choose what it watches, and pull:

  netrune traffic remote ${COLLECTOR_ID} interfaces <switch>
  netrune traffic remote ${COLLECTOR_ID} watch <switch> <interface> --interval 30
  netrune traffic pull --remote ${COLLECTOR_ID}

EOF
