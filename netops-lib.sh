#!/usr/bin/env bash
# Netrune Unified Platform - Shared Function Library v5.3.1

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "This is a library and should not be run directly."
    exit 1
fi

NETOPS_INSTALL_DIR=$(dirname "$(realpath "${BASH_SOURCE[0]}")")
if [[ -r "$NETOPS_INSTALL_DIR/VERSION" ]]; then
    NETOPS_VERSION=$(< "$NETOPS_INSTALL_DIR/VERSION")
elif command -v netrune >/dev/null 2>&1; then
    NETOPS_VERSION=$(netrune --version 2>/dev/null | awk 'NR==1 {print $2}')
    [[ -n "$NETOPS_VERSION" ]] || NETOPS_VERSION="unknown"
else
    NETOPS_VERSION="unknown"
fi
export NETOPS_VERSION

NETOPS_CONFIG_ROOT="${XDG_CONFIG_HOME:-${HOME}/.config}/netrune"
NETOPS_STATE_ROOT="${XDG_STATE_HOME:-${HOME}/.local/state}/netrune"
NETOPS_CACHE_ROOT="${XDG_CACHE_HOME:-${HOME}/.cache}/netrune"
NETOPS_DATA_ROOT="${XDG_DATA_HOME:-${HOME}/.local/share}/netrune"
NETOPS_PROFILE="${NETRUNE_PROFILE:-${NETOPS_PROFILE:-}}"
if [[ -z "${NETOPS_PROFILE:-}" && -r "${NETOPS_CONFIG_ROOT}/active_profile" ]]; then
    IFS= read -r NETOPS_PROFILE < "${NETOPS_CONFIG_ROOT}/active_profile" || true
fi
NETOPS_PROFILE="${NETOPS_PROFILE:-default}"
[[ "$NETOPS_PROFILE" =~ ^[a-z0-9][a-z0-9_-]{0,47}$ ]] || NETOPS_PROFILE="default"
CONFIG_DIR="${NETRUNE_CONFIG_DIR:-${NETOPS_CONFIG_DIR:-${NETOPS_CONFIG_ROOT}/profiles/${NETOPS_PROFILE}}}"
CACHE_DIR="${NETRUNE_CACHE_DIR:-${NETOPS_CACHE_DIR:-${NETOPS_CACHE_ROOT}/profiles/${NETOPS_PROFILE}}}"
if [[ -n "${NETRUNE_CONFIG_DIR:-}${NETOPS_CONFIG_DIR:-}${NETRUNE_CACHE_DIR:-}${NETOPS_CACHE_DIR:-}" ]]; then
    STATE_DIR="${NETRUNE_STATE_DIR:-${NETOPS_STATE_DIR:-${CACHE_DIR}}}"
    DATA_DIR="${NETRUNE_DATA_DIR:-${NETOPS_DATA_DIR:-${STATE_DIR}}}"
else
    STATE_DIR="${NETRUNE_STATE_DIR:-${NETOPS_STATE_DIR:-${NETOPS_STATE_ROOT}/profiles/${NETOPS_PROFILE}}}"
    DATA_DIR="${NETRUNE_DATA_DIR:-${NETOPS_DATA_DIR:-${NETOPS_DATA_ROOT}/profiles/${NETOPS_PROFILE}}}"
fi
LOG_FILE="${NETRUNE_LOG_FILE:-${NETOPS_LOG_FILE:-${STATE_DIR}/netrune.log}}"

CONFIG_FILE="${CONFIG_DIR}/netsnmp.conf"
ENV_FILE="${CONFIG_DIR}/.env"
DEVICES_DB="${CACHE_DIR}/devices.db"
AP_DB="${CACHE_DIR}/ap_devices.db"
NEIGHBOR_DB="${CACHE_DIR}/neighbor.db"
SNMP_CACHE_FILE="${CACHE_DIR}/snmp_cache.db"
PASSWORD_FILE="${NETRUNE_PASSWORD_FILE:-${NETOPS_PASSWORD_FILE:-${HOME}/.ssh/sshpass_cache.gpg}}"
SECRETS_FILE="${NETRUNE_SECRETS_FILE:-${NETOPS_SECRETS_FILE:-${DATA_DIR}/secrets.gpg}}"
SECRETS_META_FILE="${NETRUNE_SECRETS_META_FILE:-${NETOPS_SECRETS_META_FILE:-${STATE_DIR}/secrets.meta}}"
SUDO_VAULT_MAGIC="NETOPS-SUDO-GPG-V1"
NAMED_SECRETS_MAGIC="NETOPS-NAMED-SECRETS-GPG-V1"
SUDO_VAULT_KEY_ROOT="/etc/netops/vault-keys"

declare -gA CONFIG=(
    ["ssh_user"]=""
    ["subnets"]=""
    ["ping_timeout"]="1"
    ["snmp_timeout"]="3"
    ["scan_workers"]="30"
    ["scan_max_hosts"]="4096"
    ["scan_host_timeout"]="20"
    ["ap_scan_workers"]="10"
    ["ap_switch_timeout"]="45"
    ["controller_walk_timeout"]="180"
    ["enable_logging"]="true"
    ["ssh_host_key_mode"]="accept-new"
    ["management_vlan"]="4"
    ["vault_password_ttl_hours"]="72"
    ["vault_session_ttl_minutes"]="15"
    ["vault_expiry_window_minutes"]="20"
    ["vault_expiry_warning_hours"]="12"
    ["core_switch_ip"]=""
    ["core_iperf_server"]=""
    ["target_abbreviation_prefix"]=""
    ["cisco_wlc_ip"]=""
    ["cisco_wlc_ap_ip_filter"]=""
    ["cisco_wlc_ap_name_contains"]=""
    ["cisco_wlc_ap_name_prefix"]=""
    ["cisco_wlc_join_stats"]="true"
    ["cisco_wlc_join_stats_cmd"]=""
    ["cisco_wlc_join_stats_timeout"]="45"
    ["ruckus_vsz_ip"]=""
    ["default_backup_dir"]="${DATA_DIR}/backups"
    ["device_writes_enabled"]="false"
    ["device_certified_firmware"]=""
    ["device_certified_firmware_min"]=""
)

declare -gA CREDS=(
    ["communities"]=""
    ["cisco_wlc_comm"]=""
    ["ruckus_vsz_comm"]=""
    ["snmp_version"]="v2c"
    ["snmpv3_user"]=""
    ["snmpv3_auth_proto"]="SHA"
    ["snmpv3_auth_pass"]=""
    ["snmpv3_priv_proto"]="AES"
    ["snmpv3_priv_pass"]=""
    ["ssh_user"]=""
)

mkdir -p "$CONFIG_DIR" "$STATE_DIR" "$CACHE_DIR" "$DATA_DIR" "$(dirname "$LOG_FILE")"
chmod 700 "$CONFIG_DIR" "$STATE_DIR" "$CACHE_DIR" "$DATA_DIR" 2>/dev/null || true
touch "$DEVICES_DB" "$AP_DB" "$NEIGHBOR_DB" "$SNMP_CACHE_FILE"
chmod 600 "$DEVICES_DB" "$AP_DB" "$NEIGHBOR_DB" "$SNMP_CACHE_FILE" 2>/dev/null || true
[[ -f "$ENV_FILE" ]] && chmod 600 "$ENV_FILE" 2>/dev/null || true

load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        while IFS='=' read -r key value; do
            [[ "$key" =~ ^# ]] || [[ -z "$key" ]] && continue
            key=$(echo "$key" | tr -d '[:space:]')
            value=$(echo "$value" | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//' -e 's/^"//' -e 's/"$//')
            if [[ -n "${CONFIG[$key]+isset}" ]]; then CONFIG["$key"]="$value"; fi
        done < "$CONFIG_FILE"
    fi
    if [[ -f "$ENV_FILE" ]]; then
        while IFS='=' read -r key value; do
            [[ "$key" =~ ^# ]] || [[ -z "$key" ]] && continue
            key=$(echo "$key" | tr -d '[:space:]')
            value=$(echo "$value" | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//' -e 's/^"//' -e 's/"$//')
            if [[ -n "${CREDS[$key]+isset}" ]]; then CREDS["$key"]="$value"; fi
        done < "$ENV_FILE"
    fi
}

save_config() {
    mkdir -p "$CONFIG_DIR"
    cat > "$CONFIG_FILE" << EOF
# Netrune Unified Configuration (Public)
subnets="${CONFIG[subnets]}"
ping_timeout="${CONFIG[ping_timeout]}"
snmp_timeout="${CONFIG[snmp_timeout]}"
scan_workers="${CONFIG[scan_workers]}"
scan_max_hosts="${CONFIG[scan_max_hosts]}"
scan_host_timeout="${CONFIG[scan_host_timeout]}"
ap_scan_workers="${CONFIG[ap_scan_workers]}"
ap_switch_timeout="${CONFIG[ap_switch_timeout]}"
enable_logging="${CONFIG[enable_logging]}"
ssh_host_key_mode="${CONFIG[ssh_host_key_mode]}"
ssh_user="${CONFIG[ssh_user]}"
vault_password_ttl_hours="${CONFIG[vault_password_ttl_hours]}"
vault_expiry_window_minutes="${CONFIG[vault_expiry_window_minutes]}"
vault_expiry_warning_hours="${CONFIG[vault_expiry_warning_hours]}"
core_switch_ip="${CONFIG[core_switch_ip]}"
core_iperf_server="${CONFIG[core_iperf_server]}"
target_abbreviation_prefix="${CONFIG[target_abbreviation_prefix]}"
cisco_wlc_ip="${CONFIG[cisco_wlc_ip]}"
cisco_wlc_ap_ip_filter="${CONFIG[cisco_wlc_ap_ip_filter]}"
cisco_wlc_ap_name_contains="${CONFIG[cisco_wlc_ap_name_contains]}"
cisco_wlc_ap_name_prefix="${CONFIG[cisco_wlc_ap_name_prefix]}"
cisco_wlc_join_stats="${CONFIG[cisco_wlc_join_stats]}"
cisco_wlc_join_stats_cmd="${CONFIG[cisco_wlc_join_stats_cmd]}"
cisco_wlc_join_stats_timeout="${CONFIG[cisco_wlc_join_stats_timeout]}"
ruckus_vsz_ip="${CONFIG[ruckus_vsz_ip]}"
default_backup_dir="${CONFIG[default_backup_dir]}"
device_writes_enabled="${CONFIG[device_writes_enabled]}"
device_certified_firmware="${CONFIG[device_certified_firmware]}"
device_certified_firmware_min="${CONFIG[device_certified_firmware_min]}"
EOF
    chmod 600 "$CONFIG_FILE"
}

run_config_wizard() {
    echo -e "\033[1;36m--- Netrune Configuration Wizard ---\033[0m"
    read -rp "Enter target subnets [${CONFIG[subnets]}]: " in_val; [[ -n "$in_val" ]] && CONFIG[subnets]="$in_val"
    read -rp "Enter Core Switch IP (for Topology/Arp) [${CONFIG[core_switch_ip]}]: " in_val; [[ -n "$in_val" ]] && CONFIG[core_switch_ip]="$in_val"
    
    echo -e "\n\033[1;33m--- Controllers ---\033[0m"
    read -rp "Cisco WLC IP [${CONFIG[cisco_wlc_ip]}]: " in_val; [[ -n "$in_val" ]] && CONFIG[cisco_wlc_ip]="$in_val"
    read -rp "Ruckus vSZ IP [${CONFIG[ruckus_vsz_ip]}]: " in_val; [[ -n "$in_val" ]] && CONFIG[ruckus_vsz_ip]="$in_val"

    save_config
    echo -e "\n\033[0;32m[SUCCESS] Public configuration saved. Use 'netrune secrets set' for credentials.\033[0m"
}

init_config() {
    if [[ -f "$CONFIG_FILE" || -f "$ENV_FILE" ]]; then
        load_config
    fi
    if [[ ! -f "$CONFIG_FILE" || ! -f "$ENV_FILE" ]]; then
        if [[ "${NETOPS_AUTO_CONFIGURE:-false}" != "true" || ! -t 0 || ! -t 1 ]]; then
            return 0
        fi
        echo "Configuration or .env missing. Running wizard..."
        run_config_wizard
    fi
    [[ -n "${NETOPS_SSH_USER:-}" ]] && CONFIG[ssh_user]="$NETOPS_SSH_USER"
    [[ -z "${CREDS[ssh_user]}" ]] && CREDS[ssh_user]="${CONFIG[ssh_user]}"
}
init_config

netops_python_helper_path() {
    local module="${1:-}" filename="${2:-}" candidate resolved python_bin
    [[ "$module" =~ ^[A-Za-z_][A-Za-z0-9_]*$ && -n "$filename" ]] || return 2
    candidate="$NETOPS_INSTALL_DIR/$filename"
    if [[ -r "$candidate" ]]; then
        printf '%s\n' "$candidate"
        return 0
    fi
    python_bin="${NETOPS_PYTHON:-python3}"
    command -v "$python_bin" >/dev/null 2>&1 || return 1
    resolved=$("$python_bin" -c '
import importlib.util
import pathlib
import sys
spec = importlib.util.find_spec(sys.argv[1])
origin = pathlib.Path(spec.origin).resolve() if spec and spec.origin else None
if origin and origin.is_file():
    print(origin)
' "$module" 2>/dev/null) || return 1
    [[ -r "$resolved" ]] || return 1
    printf '%s\n' "$resolved"
}

db_update_device() {
    local ip=$(echo "$1" | tr -d ' \r\n')
    local host="${2:-N/A}" plat="${3:-N/A}" model="${4:-N/A}" ser="${5:-N/A}" mac="${6:-N/A}" src="${7:-SNMP}"
    local status="${8:-ONLINE}"
    local ts=$(date +%s)

    local ingest_helper="${NETOPS_INGEST_HELPER:-$(netops_python_helper_path netops_ingest netops_ingest.py)}"
    [[ -r "$ingest_helper" ]] || {
        echo "Netrune inventory ingest helper is unavailable: $ingest_helper" >&2
        return 10
    }
    (
        flock -x 200 || exit 1
        local db_tmp
        db_tmp=$(mktemp "${DEVICES_DB}.tmp.XXXXXX") || exit 1
        trap 'rm -f -- "$db_tmp"' EXIT
        python3 "$ingest_helper" merge-device-record \
            --inventory "$DEVICES_DB" \
            --record "$ip|$host|$plat|$model|$ser|$mac|$src|$ts|$status" \
            --output "$db_tmp" \
            --observed-at "$ts" && mv "$db_tmp" "$DEVICES_DB"
    ) 200> "${DEVICES_DB}.lock"
}

db_get_device() { awk -F'|' -v ip="$1" '$1 == ip { print; exit }' "$DEVICES_DB" 2>/dev/null; }


snmp_cache_get() {
    local ip="$1"
    awk -F'|' -v ip="$ip" '$1==ip && $2!="" {print $2; exit}' "$SNMP_CACHE_FILE" 2>/dev/null
}

# Which SNMP transport last answered for this host, if it answered recently.
# A v3 credential that an ACL blocks costs a full timeout on every poll, so a
# recent v2c success is treated as evidence that v3 is not reachable here.
snmp_cache_version() {
    local ip="$1" now
    now=$(date +%s)
    awk -F'|' -v ip="$ip" -v now="$now" '$1==ip && $3!="" && (now - $4) < 86400 {print $3; exit}' "$SNMP_CACHE_FILE" 2>/dev/null
}

snmp_cache_put() {
    local ip="$1" comm="$2" version="${3:-v2c}" ts
    [[ -z "$ip" || -z "$comm" ]] && return 0
    ts=$(date +%s)
    (
        flock -x 201
        awk -F'|' -v OFS='|' -v ip="$ip" -v comm="$comm" -v version="$version" -v ts="$ts" '
            $1==ip { print ip, comm, version, ts, 0; found=1; next }
            { print $0 }
            END { if(!found) print ip, comm, version, ts, 0 }
        ' "$SNMP_CACHE_FILE" > "${SNMP_CACHE_FILE}.tmp" && mv "${SNMP_CACHE_FILE}.tmp" "$SNMP_CACHE_FILE"
    ) 201> "${SNMP_CACHE_FILE}.lock"
}

_build_snmp3_opts() {
    local -n destination="$1"
    destination=(-v3 -u "${CREDS[snmpv3_user]}" -a "${CREDS[snmpv3_auth_proto]}" -A "${CREDS[snmpv3_auth_pass]}")
    if [[ -n "${CREDS[snmpv3_priv_pass]}" ]]; then
        destination+=(-l authPriv -x "${CREDS[snmpv3_priv_proto]}" -X "${CREDS[snmpv3_priv_pass]}")
    else
        destination+=(-l authNoPriv)
    fi
}

# Why an SNMP read could not even be attempted. Empty when it could.
#
# "No response" and "nothing to send" look identical from the outside and lead
# somewhere very different: one is a device or an ACL, the other is a profile
# with no credentials in it. Reporting them the same way sends an operator to
# check a switch that was answering all along.
netops_snmp_credential_gap() {
    local ip="$1"
    [[ -n "$(snmp_cache_get "$ip")" ]] && return 0
    [[ -n "${CREDS[communities]}" ]] && return 0
    [[ "${CREDS[snmp_version]}" == "v3" && -n "${CREDS[snmpv3_user]}" ]] && return 0
    printf 'no SNMP credentials are configured. %s has no cached community and none are set for this profile. Add one to %s as: communities="<community>"' "$ip" "$ENV_FILE"
}

netops_snmp_get() {
    local ip="$1" oid="$2" custom_comm="$3"
    local timeout_val="${CONFIG[snmp_timeout]}"
    local res cached_comm
    
    if [[ "${CREDS[snmp_version]}" == "v3" && -n "${CREDS[snmpv3_user]}" && -z "$custom_comm" && "$(snmp_cache_version "$ip")" != "v2c" ]]; then
        local -a v3_opts=()
        _build_snmp3_opts v3_opts
        res=$(timeout "$timeout_val" snmpget "${v3_opts[@]}" -Oqv "$ip" "$oid" 2>/dev/null)
        if [[ $? -eq 0 && -n "$res" && ! "$res" =~ (No Such|Timeout|Error) ]]; then echo "$res"; return 0; fi
    fi

    if [[ -n "$custom_comm" ]]; then
        res=$(timeout "$timeout_val" snmpget -v2c -c "$custom_comm" -Oqv "$ip" "$oid" 2>/dev/null)
        if [[ $? -eq 0 && -n "$res" && ! "$res" =~ (No Such|Timeout|Error) ]]; then snmp_cache_put "$ip" "$custom_comm" "v2c"; echo "$res"; return 0; fi
    else
        cached_comm=$(snmp_cache_get "$ip")
        if [[ -n "$cached_comm" ]]; then
            res=$(timeout "$timeout_val" snmpget -v2c -c "$cached_comm" -Oqv "$ip" "$oid" 2>/dev/null)
            if [[ $? -eq 0 && -n "$res" && ! "$res" =~ (No Such|Timeout|Error) ]]; then echo "$res"; return 0; fi
        fi
        for comm in ${CREDS[communities]}; do
            [[ -n "$cached_comm" && "$comm" == "$cached_comm" ]] && continue
            res=$(timeout "$timeout_val" snmpget -v2c -c "$comm" -Oqv "$ip" "$oid" 2>/dev/null)
            if [[ $? -eq 0 && -n "$res" && ! "$res" =~ (No Such|Timeout|Error) ]]; then snmp_cache_put "$ip" "$comm" "v2c"; echo "$res"; return 0; fi
        done
    fi
    return 1
}

# Fetch several OIDs in one SNMP request and emit "OID<TAB>value" lines.
# A per-interface counter set is ten OIDs; asking for them one at a time turns a
# single round trip into ten, which dominates the cost of a collection round.
netops_snmp_get_many() {
    local ip="$1"; shift
    (($# > 0)) || return 2
    local timeout_val="${CONFIG[snmp_timeout]}"
    local res cached_comm comm
    local -a oids=("$@")

    _snmp_many_emit() {
        # -OQnU keeps one varbind per line as "OID = value" without type noise.
        awk -F' = ' 'NF >= 2 { name=$1; sub(/^[ \t]+/, "", name); value=$2
                               gsub(/^"|"$/, "", value)
                               printf "%s\t%s\n", name, value }'
    }

    if [[ "${CREDS[snmp_version]}" == "v3" && -n "${CREDS[snmpv3_user]}" && "$(snmp_cache_version "$ip")" != "v2c" ]]; then
        local -a v3_opts=()
        _build_snmp3_opts v3_opts
        res=$(timeout "$timeout_val" snmpget "${v3_opts[@]}" -OQ "$ip" "${oids[@]}" 2>/dev/null)
        if [[ $? -eq 0 && -n "$res" ]]; then printf '%s\n' "$res" | _snmp_many_emit; return 0; fi
    fi

    cached_comm=$(snmp_cache_get "$ip")
    if [[ -n "$cached_comm" ]]; then
        res=$(timeout "$timeout_val" snmpget -v2c -c "$cached_comm" -OQ "$ip" "${oids[@]}" 2>/dev/null)
        if [[ $? -eq 0 && -n "$res" ]]; then printf '%s\n' "$res" | _snmp_many_emit; return 0; fi
    fi
    for comm in ${CREDS[communities]}; do
        [[ -n "$cached_comm" && "$comm" == "$cached_comm" ]] && continue
        res=$(timeout "$timeout_val" snmpget -v2c -c "$comm" -OQ "$ip" "${oids[@]}" 2>/dev/null)
        if [[ $? -eq 0 && -n "$res" ]]; then
            snmp_cache_put "$ip" "$comm" "v2c"
            printf '%s\n' "$res" | _snmp_many_emit
            return 0
        fi
    done
    return 1
}

netops_snmp_walk() {
    local ip="$1" oid="$2" extra_flags="$3" custom_comm="$4"
    local timeout_val="15"
    local res cached_comm
    local -a walk_flags=()
    [[ -n "$extra_flags" ]] && read -r -a walk_flags <<< "$extra_flags"
    
    if [[ "${CREDS[snmp_version]}" == "v3" && -n "${CREDS[snmpv3_user]}" && -z "$custom_comm" && "$(snmp_cache_version "$ip")" != "v2c" ]]; then
        local -a v3_opts=()
        _build_snmp3_opts v3_opts
        res=$(timeout "$timeout_val" snmpwalk "${v3_opts[@]}" "${walk_flags[@]}" "$ip" "$oid" 2>/dev/null)
        if [[ -n "$res" ]]; then echo "$res"; return 0; fi
    fi

    if [[ -n "$custom_comm" ]]; then
        res=$(timeout "$timeout_val" snmpwalk -v2c -c "$custom_comm" "${walk_flags[@]}" "$ip" "$oid" 2>/dev/null)
        if [[ -n "$res" ]]; then snmp_cache_put "$ip" "$custom_comm" "v2c"; echo "$res"; return 0; fi
    else
        cached_comm=$(snmp_cache_get "$ip")
        if [[ -n "$cached_comm" ]]; then
            res=$(timeout "$timeout_val" snmpwalk -v2c -c "$cached_comm" "${walk_flags[@]}" "$ip" "$oid" 2>/dev/null)
            if [[ -n "$res" ]]; then echo "$res"; return 0; fi
        fi
        for comm in ${CREDS[communities]}; do
            [[ -n "$cached_comm" && "$comm" == "$cached_comm" ]] && continue
            res=$(timeout "$timeout_val" snmpwalk -v2c -c "$comm" "${walk_flags[@]}" "$ip" "$oid" 2>/dev/null)
            if [[ -n "$res" ]]; then snmp_cache_put "$ip" "$comm" "v2c"; echo "$res"; return 0; fi
        done
    fi
    return 1
}

# A whole controller table in one pass. netops_snmp_walk's plain snmpwalk asks
# for one value per round trip under a 15-second cap, which cut a 175-AP
# SmartZone table to 55 rows; GETBULK with 25 repetitions reads it in about
# 20 seconds. Same credential order as netops_snmp_walk; numeric OIDs, so the
# caller can decode the row index.
netops_snmp_bulkwalk() {
    local ip="$1" oid="$2" custom_comm="$3"
    local timeout_val="${CONFIG[controller_walk_timeout]:-180}" res cached_comm comm
    [[ "$timeout_val" =~ ^[0-9]+$ ]] || timeout_val=180
    local -a flags=(-On -t 10 -r 1 -Cr25)
    if [[ "${CREDS[snmp_version]}" == "v3" && -n "${CREDS[snmpv3_user]}" && -z "$custom_comm" && "$(snmp_cache_version "$ip")" != "v2c" ]]; then
        local -a v3_opts=()
        _build_snmp3_opts v3_opts
        res=$(timeout "$timeout_val" snmpbulkwalk "${v3_opts[@]}" "${flags[@]}" "$ip" "$oid" 2>/dev/null)
        if [[ "$res" == .* ]]; then echo "$res"; return 0; fi
    fi
    if [[ -n "$custom_comm" ]]; then
        res=$(timeout "$timeout_val" snmpbulkwalk -v2c -c "$custom_comm" "${flags[@]}" "$ip" "$oid" 2>/dev/null)
        if [[ "$res" == .* ]]; then snmp_cache_put "$ip" "$custom_comm" "v2c"; echo "$res"; return 0; fi
        return 1
    fi
    cached_comm=$(snmp_cache_get "$ip")
    if [[ -n "$cached_comm" ]]; then
        res=$(timeout "$timeout_val" snmpbulkwalk -v2c -c "$cached_comm" "${flags[@]}" "$ip" "$oid" 2>/dev/null)
        if [[ "$res" == .* ]]; then echo "$res"; return 0; fi
    fi
    for comm in ${CREDS[communities]}; do
        [[ -n "$cached_comm" && "$comm" == "$cached_comm" ]] && continue
        res=$(timeout "$timeout_val" snmpbulkwalk -v2c -c "$comm" "${flags[@]}" "$ip" "$oid" 2>/dev/null)
        if [[ "$res" == .* ]]; then snmp_cache_put "$ip" "$comm" "v2c"; echo "$res"; return 0; fi
    done
    return 1
}

cloud_sync_allowed() {
    return 1
}

sync_password_from_gist() {
    echo "Error: remote SSH vault sync is disabled because the legacy implementation exported credential material to a third party." >&2
    echo "Use the local encrypted vault managed by 'netrune vault set'." >&2
    return 1
}

sync_password_from_gist_upload() {
    echo "Error: remote SSH vault sync is disabled; Netrune will not export the local credential vault." >&2
    return 1
}

_vault_test_mode() {
    [[ "${NETOPS_TEST_MODE:-false}" =~ ^(1|true|yes)$ ]]
}

_vault_sudo_bin() {
    if _vault_test_mode; then
        command -v sudo
    else
        printf '%s\n' /usr/bin/sudo
    fi
}

_vault_gpg_bin() {
    if _vault_test_mode; then
        command -v gpg
    else
        printf '%s\n' /usr/bin/gpg
    fi
}

_vault_uses_fixture_sudo() {
    local sudo_bin=""
    _vault_test_mode || return 1
    sudo_bin=$(command -v sudo 2>/dev/null || true)
    [[ -n "$sudo_bin" && "$sudo_bin" != "/usr/bin/sudo" ]]
}

_sudo_vault_key_dir() {
    if _vault_uses_fixture_sudo && [[ -n "${NETOPS_SUDO_VAULT_KEY_DIR:-}" ]]; then
        printf '%s\n' "$NETOPS_SUDO_VAULT_KEY_DIR"
    else
        printf '%s\n' "$SUDO_VAULT_KEY_ROOT"
    fi
}

_sudo_vault_key_file() {
    printf '%s/%s.key\n' "$(_sudo_vault_key_dir)" "${UID:-$(/usr/bin/id -u)}"
}

_sudo_vault_key_is_secure() {
    local sudo_bin key_dir key_file owner_anchor key_metadata dir_metadata anchor_metadata
    local key_owner key_mode key_kind dir_owner dir_mode dir_kind anchor_owner anchor_mode anchor_kind
    SUDO_VAULT_KEY_ERROR=""
    sudo_bin=$(_vault_sudo_bin) || return 1
    key_dir=$(_sudo_vault_key_dir)
    key_file=$(_sudo_vault_key_file)
    owner_anchor="/etc"
    _vault_uses_fixture_sudo && owner_anchor="$key_dir"
    key_metadata=$("$sudo_bin" -n /usr/bin/stat --printf '%u:%a:%F' "$key_file" 2>/dev/null) || {
        SUDO_VAULT_KEY_ERROR="could not read key metadata"
        return 1
    }
    dir_metadata=$("$sudo_bin" -n /usr/bin/stat --printf '%u:%a:%F' "$key_dir" 2>/dev/null) || {
        SUDO_VAULT_KEY_ERROR="could not read key-directory metadata"
        return 1
    }
    anchor_metadata=$("$sudo_bin" -n /usr/bin/stat --printf '%u:%a:%F' "$owner_anchor" 2>/dev/null) || {
        SUDO_VAULT_KEY_ERROR="could not read trusted-owner metadata"
        return 1
    }
    key_metadata=${key_metadata//$'\r'/}
    dir_metadata=${dir_metadata//$'\r'/}
    anchor_metadata=${anchor_metadata//$'\r'/}
    IFS=: read -r key_owner key_mode key_kind <<< "$key_metadata"
    IFS=: read -r dir_owner dir_mode dir_kind <<< "$dir_metadata"
    IFS=: read -r anchor_owner anchor_mode anchor_kind <<< "$anchor_metadata"
    if [[ "$anchor_kind" != "directory" ]]; then
        SUDO_VAULT_KEY_ERROR="trusted owner anchor is '$anchor_kind', expected directory"
    elif [[ "$dir_kind" != "directory" ]]; then
        SUDO_VAULT_KEY_ERROR="key path parent is '$dir_kind', expected directory"
    elif [[ "$dir_mode" != "700" ]]; then
        SUDO_VAULT_KEY_ERROR="key directory mode is $dir_mode, expected 700"
    elif [[ "$key_kind" != "regular file" ]]; then
        SUDO_VAULT_KEY_ERROR="key object is '$key_kind', expected regular file"
    elif [[ ! "$key_mode" =~ ^[46]00$ ]]; then
        SUDO_VAULT_KEY_ERROR="key mode is $key_mode, expected 400 or 600"
    elif [[ "$dir_owner" != "$anchor_owner" ]]; then
        SUDO_VAULT_KEY_ERROR="key directory owner UID is $dir_owner, trusted owner UID is $anchor_owner"
    elif [[ "$key_owner" != "$dir_owner" ]]; then
        SUDO_VAULT_KEY_ERROR="key owner UID is $key_owner, key directory owner UID is $dir_owner"
    else
        return 0
    fi
    return 1
}

_vault_is_sudo_gated() {
    local marker=""
    [[ -f "$PASSWORD_FILE" ]] || return 1
    IFS= read -r marker < "$PASSWORD_FILE" || true
    [[ "$marker" == "$SUDO_VAULT_MAGIC" ]]
}

_read_secret_value() {
    local -n destination="$1"
    local prompt="$2" tty_fd=""
    destination=""
    if { exec {tty_fd}<>/dev/tty; } 2>/dev/null; then
        printf '%s' "$prompt" >&"$tty_fd"
        IFS= read -r -s destination <&"$tty_fd" || {
            printf '\n' >&"$tty_fd"
            exec {tty_fd}>&-
            return 1
        }
        printf '\n' >&"$tty_fd"
        exec {tty_fd}>&-
        return 0
    fi
    if [[ -t 0 ]]; then
        printf '%s' "$prompt" >&2
        IFS= read -r -s destination || { echo >&2; return 1; }
        echo >&2
        return 0
    fi
    if ! _vault_test_mode; then
        echo "Error: A controlling terminal is required for secret input." >&2
        return 1
    fi
    printf '%s' "$prompt" >&2
    IFS= read -r -s destination || { echo >&2; return 1; }
    echo >&2
}

_sudo_vault_authenticate() {
    local sudo_bin auth_dir auth_lock auth_fd=""
    sudo_bin=$(_vault_sudo_bin) || {
        echo "Error: 'sudo' is required for the sudo-gated SSH vault." >&2
        return 1
    }
    [[ -x "$sudo_bin" ]] || {
        echo "Error: sudo is unavailable at $sudo_bin." >&2
        return 1
    }
    if "$sudo_bin" -n -v 2>/dev/null; then
        return 0
    fi
    auth_dir="${CACHE_DIR}/.runtime"
    mkdir -p "$auth_dir" 2>/dev/null || {
        echo "Error: Could not create the private vault-auth runtime directory." >&2
        return 1
    }
    chmod 700 "$auth_dir" 2>/dev/null || return 1
    auth_lock="$auth_dir/vault-auth.lock"
    if ! exec {auth_fd}> "$auth_lock"; then
        echo "Error: Could not open the vault-auth lock." >&2
        return 1
    fi
    chmod 600 "$auth_lock" 2>/dev/null || { exec {auth_fd}>&-; return 1; }
    if ! flock -x "$auth_fd"; then
        exec {auth_fd}>&-
        echo "Error: Could not acquire the vault-auth lock." >&2
        return 1
    fi
    if "$sudo_bin" -n -v 2>/dev/null; then
        exec {auth_fd}>&-
        return 0
    fi
    if [[ "${NETOPS_VAULT_NONINTERACTIVE:-false}" =~ ^(1|true|yes)$ ]]; then
        exec {auth_fd}>&-
        echo "Error: The sudo-gated SSH vault is locked and prompting is disabled." >&2
        return 1
    fi
    if [[ -r /etc/pam.d/sudo ]] && /usr/bin/grep -q 'pam_wsl_hello\.so' /etc/pam.d/sudo 2>/dev/null; then
        echo "Unlocking the Netrune SSH vault with Windows Hello (sudo/PAM)..." >&2
    else
        echo "Unlocking the Netrune SSH vault with sudo authentication..." >&2
    fi
    if ! "$sudo_bin" -v; then
        exec {auth_fd}>&-
        echo "Error: sudo authentication failed; the SSH vault remains locked." >&2
        return 1
    fi
    exec {auth_fd}>&-
}

_sudo_vault_prepare_key() {
    local sudo_bin key_dir key_file
    _sudo_vault_authenticate || return $?
    sudo_bin=$(_vault_sudo_bin) || return 1
    key_dir=$(_sudo_vault_key_dir)
    key_file=$(_sudo_vault_key_file)
    if "$sudo_bin" -n /usr/bin/test -e "$key_file" 2>/dev/null; then
        if ! "$sudo_bin" -n /usr/bin/test -s "$key_file" 2>/dev/null; then
            echo "Error: Existing root vault key is empty: $key_file" >&2
            return 1
        fi
        if _sudo_vault_key_is_secure; then
            return 0
        fi
        echo "Error: Existing root vault key failed security validation: ${SUDO_VAULT_KEY_ERROR:-unknown reason}: $key_file" >&2
        return 1
    fi
    "$sudo_bin" -n /usr/bin/install -d -m 0700 "$key_dir" || {
        echo "Error: Could not create the root-only Netrune vault-key directory." >&2
        return 1
    }
    if ! "$sudo_bin" -n /bin/sh -c '
        set -eu
        key=$1
        if [ ! -s "$key" ]; then
            tmp="${key}.tmp.$$"
            trap '\''/usr/bin/rm -f -- "$tmp"'\'' EXIT HUP INT TERM
            umask 077
            /usr/bin/head -c 48 /dev/urandom | /usr/bin/base64 > "$tmp"
            /usr/bin/chmod 0600 "$tmp"
            /usr/bin/mv -f "$tmp" "$key"
            trap - EXIT HUP INT TERM
        fi
    ' netrune-vault-key "$key_file"; then
        echo "Error: Could not create the root-only Netrune vault key." >&2
        return 1
    fi
    if ! "$sudo_bin" -n /usr/bin/test -s "$key_file" 2>/dev/null; then
        echo "Error: The newly created root-only Netrune vault key is empty: $key_file" >&2
        return 1
    fi
    if ! _sudo_vault_key_is_secure; then
        echo "Error: The root-only Netrune vault key failed security validation: ${SUDO_VAULT_KEY_ERROR:-unknown reason}: $key_file" >&2
        return 1
    fi
}

_sudo_vault_require_key() {
    local sudo_bin key_file
    _sudo_vault_authenticate || return $?
    sudo_bin=$(_vault_sudo_bin) || return 1
    key_file=$(_sudo_vault_key_file)
    if ! "$sudo_bin" -n /usr/bin/test -s "$key_file" 2>/dev/null; then
        echo "Error: Root vault key is missing: $key_file" >&2
        echo "Restore the key from backup, or run 'netrune vault set' to replace the vault." >&2
        return 1
    fi
    _sudo_vault_key_is_secure || {
        echo "Error: Root vault key failed security validation: ${SUDO_VAULT_KEY_ERROR:-unknown reason}: $key_file" >&2
        return 1
    }
}

_sudo_vault_key_broker() {
    local sudo_bin="$1" mode="$2" key_file="$3" key_dir="$4" owner_anchor="$5"
    local -a command=("$sudo_bin")
    [[ "$mode" == "noninteractive" ]] && command+=(-n)
    command+=(/bin/sh -c '
        set -eu
        key=$1
        key_dir=$2
        owner_anchor=$3

        fail() {
            printf "Error: Root vault key failed security validation: %s: %s\n" "$1" "$key" >&2
            exit 1
        }
        split_metadata() {
            metadata=$1
            metadata_owner=${metadata%%:*}
            metadata_rest=${metadata#*:}
            metadata_mode=${metadata_rest%%:*}
            metadata_kind=${metadata_rest#*:}
        }

        if [ ! -e "$key" ]; then
            printf "Error: Root vault key is missing: %s\n" "$key" >&2
            printf "Restore the key from backup, or run '\''netrune vault set'\'' to replace the vault.\n" >&2
            exit 1
        fi
        [ -s "$key" ] || fail "key is empty"

        key_metadata=$(/usr/bin/stat --printf "%u:%a:%F" "$key" 2>/dev/null) || fail "could not read key metadata"
        dir_metadata=$(/usr/bin/stat --printf "%u:%a:%F" "$key_dir" 2>/dev/null) || fail "could not read key-directory metadata"
        anchor_metadata=$(/usr/bin/stat --printf "%u:%a:%F" "$owner_anchor" 2>/dev/null) || fail "could not read trusted-owner metadata"

        split_metadata "$key_metadata"
        key_owner=$metadata_owner
        key_mode=$metadata_mode
        key_kind=$metadata_kind
        split_metadata "$dir_metadata"
        dir_owner=$metadata_owner
        dir_mode=$metadata_mode
        dir_kind=$metadata_kind
        split_metadata "$anchor_metadata"
        anchor_owner=$metadata_owner
        anchor_kind=$metadata_kind

        [ "$anchor_kind" = "directory" ] || fail "trusted owner anchor type is $anchor_kind, expected directory"
        [ "$dir_kind" = "directory" ] || fail "key path parent type is $dir_kind, expected directory"
        [ "$dir_mode" = "700" ] || fail "key directory mode is $dir_mode, expected 700"
        [ "$key_kind" = "regular file" ] || fail "key object type is $key_kind, expected regular file"
        case "$key_mode" in
            400|600) ;;
            *) fail "key mode is $key_mode, expected 400 or 600" ;;
        esac
        [ "$dir_owner" = "$anchor_owner" ] || fail "key directory owner UID is $dir_owner, trusted owner UID is $anchor_owner"
        [ "$key_owner" = "$dir_owner" ] || fail "key owner UID is $key_owner, key directory owner UID is $dir_owner"

        /usr/bin/cat "$key"
    ' netrune-vault-key-reader "$key_file" "$key_dir" "$owner_anchor")
    "${command[@]}"
}

# --- Vault session -----------------------------------------------------------
# Every vault read otherwise costs one sudo authentication, which on a Windows
# Hello PAM stack means a biometric prompt per process. An unlocked session
# holds the root vault key in a memory-backed, user-private file for a bounded
# window so a batch of commands authenticates once.
#
# The tradeoff is explicit: during the window the key is readable by this user
# rather than only by root. It is therefore opt-in through `vault unlock`,
# never started implicitly, capped in duration, and refused unless the backing
# directory is tmpfs owned by this user at mode 0700 so it cannot reach a disk.

_vault_session_dir() {
    local base="${NETRUNE_VAULT_SESSION_DIR:-${NETOPS_VAULT_SESSION_DIR:-${XDG_RUNTIME_DIR:-}}}"
    [[ -n "$base" ]] || return 1
    printf '%s/netrune-vault' "${base%/}"
}

_vault_session_ttl_bounds() {
    printf '%s %s' "${NETRUNE_VAULT_SESSION_MIN_MINUTES:-1}" "${NETRUNE_VAULT_SESSION_MAX_MINUTES:-480}"
}

_vault_session_path_is_secure() {
    local path="$1" want_mode="$2" fstype owner mode
    fstype=$(/usr/bin/stat -f -c %T -- "$path" 2>/dev/null) || {
        VAULT_SESSION_ERROR="could not read filesystem type"
        return 1
    }
    case "$fstype" in
        tmpfs|ramfs) ;;
        *)
            VAULT_SESSION_ERROR="stored on '$fstype'; a memory-backed tmpfs is required"
            return 1
            ;;
    esac
    owner=$(/usr/bin/stat -c %u -- "$path" 2>/dev/null) || return 1
    mode=$(/usr/bin/stat -c %a -- "$path" 2>/dev/null) || return 1
    if [[ "$owner" != "$(id -u)" ]]; then
        VAULT_SESSION_ERROR="owner UID is $owner, expected $(id -u)"
        return 1
    fi
    if [[ "$mode" != "$want_mode" ]]; then
        VAULT_SESSION_ERROR="mode is $mode, expected $want_mode"
        return 1
    fi
}

_vault_session_clear() {
    local dir
    dir=$(_vault_session_dir) || return 0
    [[ -d "$dir" ]] || return 0
    if [[ -f "$dir/key" ]]; then
        command shred -u -- "$dir/key" 2>/dev/null || command rm -f -- "$dir/key" 2>/dev/null || true
    fi
    command rm -f -- "$dir/expires-at" 2>/dev/null || true
    command rmdir -- "$dir" 2>/dev/null || true
    return 0
}

_vault_session_expires_at() {
    local dir expires
    dir=$(_vault_session_dir) || return 1
    [[ -s "$dir/expires-at" ]] || return 1
    IFS= read -r expires < "$dir/expires-at" || return 1
    [[ "$expires" =~ ^[0-9]+$ ]] || return 1
    printf '%s' "$expires"
}

# Emit the cached key when a session is live. Any validation failure purges the
# session and falls back to sudo rather than trusting a suspect file.
_vault_session_read() {
    local dir expires now_ts
    dir=$(_vault_session_dir) || return 1
    [[ -d "$dir" && -s "$dir/key" && -s "$dir/expires-at" ]] || return 1
    if ! _vault_session_path_is_secure "$dir" 700 || ! _vault_session_path_is_secure "$dir/key" 600; then
        echo "Warning: Discarding the vault session (${VAULT_SESSION_ERROR:-failed validation})." >&2
        _vault_session_clear
        return 1
    fi
    expires=$(_vault_session_expires_at) || { _vault_session_clear; return 1; }
    now_ts=$(date +%s)
    if (( now_ts >= expires )); then
        _vault_session_clear
        return 1
    fi
    command cat -- "$dir/key"
}

# Store the key read from stdin for ttl_minutes. Returns the expiry on stdout.
_vault_session_store() {
    local ttl_minutes="$1" dir key_tmp expires min_ttl max_ttl
    read -r min_ttl max_ttl < <(_vault_session_ttl_bounds)
    [[ "$ttl_minutes" =~ ^[0-9]+$ ]] || {
        echo "Error: Vault session minutes must be a whole number." >&2
        return 2
    }
    if (( ttl_minutes < min_ttl || ttl_minutes > max_ttl )); then
        echo "Error: Vault session minutes must be between $min_ttl and $max_ttl." >&2
        return 2
    fi
    dir=$(_vault_session_dir) || {
        echo "Error: No per-user runtime directory is available for a vault session." >&2
        echo "Set XDG_RUNTIME_DIR to a tmpfs path owned by this user, then retry." >&2
        return 1
    }
    if ! mkdir -p -- "$dir" 2>/dev/null; then
        echo "Error: Could not create the vault session directory: $dir" >&2
        return 1
    fi
    chmod 700 -- "$dir" 2>/dev/null || return 1
    if ! _vault_session_path_is_secure "$dir" 700; then
        echo "Error: Refusing to cache the vault key: ${VAULT_SESSION_ERROR:-failed validation}: $dir" >&2
        _vault_session_clear
        return 1
    fi
    key_tmp="$dir/key.tmp.$$"
    (
        umask 077
        command cat > "$key_tmp"
    ) || { command rm -f -- "$key_tmp" 2>/dev/null; return 1; }
    if [[ ! -s "$key_tmp" ]]; then
        command rm -f -- "$key_tmp" 2>/dev/null
        echo "Error: The vault key could not be read; the session was not started." >&2
        return 1
    fi
    chmod 600 -- "$key_tmp" 2>/dev/null || { command rm -f -- "$key_tmp" 2>/dev/null; return 1; }
    command mv -f -- "$key_tmp" "$dir/key" || { command rm -f -- "$key_tmp" 2>/dev/null; return 1; }
    expires=$(( $(date +%s) + ttl_minutes * 60 ))
    ( umask 077; printf '%s\n' "$expires" > "$dir/expires-at" ) || { _vault_session_clear; return 1; }
    chmod 600 -- "$dir/expires-at" 2>/dev/null || true
    printf '%s' "$expires"
}

_sudo_vault_emit_key() {
    local sudo_bin key_dir key_file owner_anchor auth_dir auth_lock auth_fd="" broker_mode="interactive"

    # A live session answers without touching sudo, which is the entire point.
    if [[ ! "${NETRUNE_VAULT_SESSION_BYPASS:-false}" =~ ^(1|true|yes)$ ]] && _vault_session_read; then
        return 0
    fi
    sudo_bin=$(_vault_sudo_bin) || {
        echo "Error: 'sudo' is required for the sudo-gated SSH vault." >&2
        return 1
    }
    key_dir=$(_sudo_vault_key_dir)
    key_file=$(_sudo_vault_key_file)
    owner_anchor="/etc"
    _vault_uses_fixture_sudo && owner_anchor="$key_dir"

    auth_dir="${CACHE_DIR}/.runtime"
    mkdir -p "$auth_dir" 2>/dev/null || {
        echo "Error: Could not create the private vault-auth runtime directory." >&2
        return 1
    }
    chmod 700 "$auth_dir" 2>/dev/null || return 1
    auth_lock="$auth_dir/vault-auth.lock"
    if ! exec {auth_fd}> "$auth_lock"; then
        echo "Error: Could not open the vault-auth lock." >&2
        return 1
    fi
    chmod 600 "$auth_lock" 2>/dev/null || { exec {auth_fd}>&-; return 1; }
    if ! flock -x "$auth_fd"; then
        exec {auth_fd}>&-
        echo "Error: Could not acquire the vault-auth lock." >&2
        return 1
    fi

    if ! "$sudo_bin" -n -v 2>/dev/null; then
        if [[ "${NETOPS_VAULT_NONINTERACTIVE:-false}" =~ ^(1|true|yes)$ ]]; then
            exec {auth_fd}>&-
            echo "Error: The sudo-gated SSH vault is locked and prompting is disabled." >&2
            return 1
        fi
        if [[ -r /etc/pam.d/sudo ]] && /usr/bin/grep -q 'pam_wsl_hello\.so' /etc/pam.d/sudo 2>/dev/null; then
            echo "Unlocking the Netrune SSH vault with Windows Hello (sudo/PAM)..." >&2
        else
            echo "Unlocking the Netrune SSH vault with sudo authentication..." >&2
        fi
    elif [[ "${NETOPS_VAULT_NONINTERACTIVE:-false}" =~ ^(1|true|yes)$ ]]; then
        broker_mode="noninteractive"
    fi

    if _sudo_vault_key_broker "$sudo_bin" "$broker_mode" "$key_file" "$key_dir" "$owner_anchor"; then
        exec {auth_fd}>&-
        return 0
    fi
    exec {auth_fd}>&-
    return 1
}

_sudo_vault_gpg() {
    local operation="$1" gpg_bin key_fd key_reader_pid key_reader_rc rc
    gpg_bin=$(_vault_gpg_bin) || return 1
    [[ -x "$gpg_bin" ]] || {
        echo "Error: GPG is unavailable at $gpg_bin." >&2
        return 1
    }
    if ! exec {key_fd}< <(_sudo_vault_emit_key); then
        echo "Error: Could not read the root-only Netrune vault key." >&2
        return 1
    fi
    key_reader_pid=$!
    case "$operation" in
        encrypt)
            "$gpg_bin" --no-options --quiet --batch --yes --no-symkey-cache \
                --pinentry-mode loopback --passphrase-fd "$key_fd" \
                --symmetric --cipher-algo AES256 --output - -
            rc=$?
            ;;
        decrypt)
            "$gpg_bin" --no-options --quiet --batch --yes --no-symkey-cache \
                --pinentry-mode loopback --passphrase-fd "$key_fd" \
                --decrypt -
            rc=$?
            ;;
        *) rc=2 ;;
    esac
    exec {key_fd}<&-
    if wait "$key_reader_pid"; then
        key_reader_rc=0
    else
        key_reader_rc=$?
    fi
    if [[ "$rc" -eq 0 && "$key_reader_rc" -ne 0 ]]; then
        rc=$key_reader_rc
    fi
    return "$rc"
}

_named_secret_name_valid() {
    [[ "${1:-}" =~ ^[a-z0-9][a-z0-9_.-]*(/[a-z0-9][a-z0-9_.-]*)*$ ]]
}

_named_secret_encoded_name() {
    printf '%s' "$1" | /usr/bin/base64 -w0
}

_named_secret_recorded_at() {
    local encoded
    _named_secret_name_valid "$1" || return 1
    [[ -r "$SECRETS_META_FILE" ]] || return 1
    encoded=$(_named_secret_encoded_name "$1")
    awk -F'|' -v key="$encoded" '$1 == key {value=$2} END {if (value ~ /^[0-9]+$/) print value}' "$SECRETS_META_FILE"
}

_named_secrets_decrypt() {
    local marker=""
    [[ -f "$SECRETS_FILE" ]] || return 0
    chmod 600 "$SECRETS_FILE" 2>/dev/null || {
        echo "Error: Could not restrict named-secret store permissions: $SECRETS_FILE" >&2
        return 1
    }
    IFS= read -r marker < "$SECRETS_FILE" || true
    [[ "$marker" == "$NAMED_SECRETS_MAGIC" ]] || {
        echo "Error: Named-secret store has an unsupported format." >&2
        return 1
    }
    { IFS= read -r _named_marker; command cat; } < "$SECRETS_FILE" | _sudo_vault_gpg decrypt
}

_named_secrets_write_payload() {
    local payload="$1" secret_dir staged
    _sudo_vault_prepare_key || return $?
    secret_dir=$(dirname "$SECRETS_FILE")
    mkdir -p "$secret_dir" "$(dirname "$SECRETS_META_FILE")" || return 1
    chmod 700 "$secret_dir" "$(dirname "$SECRETS_META_FILE")" 2>/dev/null || true
    staged=$(mktemp "$secret_dir/.netrune-secrets.XXXXXX") || return 1
    chmod 600 "$staged" || { rm -f -- "$staged"; return 1; }
    printf '%s\n' "$NAMED_SECRETS_MAGIC" > "$staged"
    if ! printf '%s' "$payload" | _sudo_vault_gpg encrypt >> "$staged"; then
        rm -f -- "$staged"
        echo "Error: Failed to encrypt named secrets; the existing store was not changed." >&2
        return 1
    fi
    mv -f "$staged" "$SECRETS_FILE" || { rm -f -- "$staged"; return 1; }
    chmod 600 "$SECRETS_FILE" 2>/dev/null || return 1
}

_named_secret_update_metadata() {
    local name="$1" recorded_at="$2" operation="${3:-set}" encoded staged line
    encoded=$(_named_secret_encoded_name "$name")
    mkdir -p "$(dirname "$SECRETS_META_FILE")" || return 1
    staged=$(mktemp "$(dirname "$SECRETS_META_FILE")/.secrets-meta.XXXXXX") || return 1
    chmod 600 "$staged" || { rm -f -- "$staged"; return 1; }
    if [[ -r "$SECRETS_META_FILE" ]]; then
        while IFS= read -r line; do
            [[ "${line%%|*}" == "$encoded" ]] || printf '%s\n' "$line" >> "$staged"
        done < "$SECRETS_META_FILE"
    fi
    if [[ "$operation" == "set" ]]; then
        printf '%s|%s\n' "$encoded" "$recorded_at" >> "$staged"
    fi
    sort -o "$staged" "$staged"
    mv -f "$staged" "$SECRETS_META_FILE" || { rm -f -- "$staged"; return 1; }
    chmod 600 "$SECRETS_META_FILE" 2>/dev/null || return 1
}

_named_secret_commit() {
    local name="$1" payload="$2" recorded_at="$3" operation="$4"
    local store_backup="" meta_backup="" had_store=false had_meta=false rollback_failed=false
    mkdir -p "$(dirname "$SECRETS_FILE")" "$(dirname "$SECRETS_META_FILE")" || return 1
    if [[ -f "$SECRETS_FILE" ]]; then
        had_store=true
        store_backup=$(mktemp "$(dirname "$SECRETS_FILE")/.secrets-rollback.XXXXXX") || return 1
        chmod 600 "$store_backup"
        command cp -- "$SECRETS_FILE" "$store_backup" || { rm -f -- "$store_backup"; return 1; }
    fi
    if [[ -f "$SECRETS_META_FILE" ]]; then
        had_meta=true
        meta_backup=$(mktemp "$(dirname "$SECRETS_META_FILE")/.secrets-meta-rollback.XXXXXX") || {
            rm -f -- "$store_backup"
            return 1
        }
        chmod 600 "$meta_backup"
        command cp -- "$SECRETS_META_FILE" "$meta_backup" || {
            rm -f -- "$store_backup" "$meta_backup"
            return 1
        }
    fi
    if ! _named_secrets_write_payload "$payload"; then
        rm -f -- "$store_backup" "$meta_backup"
        return 1
    fi
    if ! _named_secret_update_metadata "$name" "$recorded_at" "$operation"; then
        if [[ "$had_store" == true ]]; then
            mv -f -- "$store_backup" "$SECRETS_FILE" || rollback_failed=true
            store_backup=""
        else
            rm -f -- "$SECRETS_FILE" || rollback_failed=true
        fi
        if [[ "$had_meta" == true ]]; then
            mv -f -- "$meta_backup" "$SECRETS_META_FILE" || rollback_failed=true
            meta_backup=""
        else
            rm -f -- "$SECRETS_META_FILE" || rollback_failed=true
        fi
        rm -f -- "$store_backup" "$meta_backup"
        if [[ "$rollback_failed" == true ]]; then
            echo "Error: Named-secret metadata failed and rollback was incomplete; stop and restore the profile backup." >&2
        else
            echo "Error: Named-secret metadata failed; the previous encrypted store was restored." >&2
        fi
        return 1
    fi
    rm -f -- "$store_backup" "$meta_backup"
}

_named_secret_set_value() {
    local name="$1" secret="$2" recorded_at="${3:-$(date +%s)}" payload="" output="" encoded_name encoded_value line
    _named_secret_name_valid "$name" || { echo "Error: Invalid secret name '$name'." >&2; return 2; }
    [[ -n "$secret" ]] || { echo "Error: Secret value cannot be empty." >&2; return 1; }
    if [[ -f "$SECRETS_FILE" ]]; then
        payload=$(_named_secrets_decrypt) || return 1
    fi
    encoded_name=$(_named_secret_encoded_name "$name")
    encoded_value=$(printf '%s' "$secret" | /usr/bin/base64 -w0)
    while IFS= read -r line; do
        [[ -z "$line" || "${line%%$'\t'*}" == "$encoded_name" ]] && continue
        output+="$line"$'\n'
    done <<< "$payload"
    output+="${encoded_name}"$'\t'"${encoded_value}"$'\n'
    _named_secret_commit "$name" "$output" "$recorded_at" set || return $?
}

named_secret_set() {
    local name="$1" value="" confirmation=""
    _named_secret_name_valid "$name" || { echo "Error: Invalid secret name '$name'." >&2; return 2; }
    _read_secret_value value "Enter value for $name: " || return 1
    _read_secret_value confirmation "Confirm value for $name: " || return 1
    [[ -n "$value" ]] || { echo "Error: Secret value cannot be empty." >&2; return 1; }
    [[ "$value" == "$confirmation" ]] || { echo "Error: Secret values do not match." >&2; return 1; }
    _named_secret_set_value "$name" "$value" || return $?
    unset value confirmation
    echo "Named secret recorded: $name" >&2
}

named_secret_get() {
    local name="$1" payload encoded_name encoded_value="" row_name row_value
    _named_secret_name_valid "$name" || { echo "Error: Invalid secret name '$name'." >&2; return 2; }
    [[ -f "$SECRETS_FILE" ]] || { echo "Error: Named-secret store does not exist." >&2; return 1; }
    payload=$(_named_secrets_decrypt) || return 1
    encoded_name=$(_named_secret_encoded_name "$name")
    while IFS=$'\t' read -r row_name row_value; do
        if [[ "$row_name" == "$encoded_name" ]]; then encoded_value="$row_value"; break; fi
    done <<< "$payload"
    [[ -n "$encoded_value" ]] || { echo "Error: Named secret not found: $name" >&2; return 1; }
    printf '%s' "$encoded_value" | /usr/bin/base64 -d
}

named_secret_delete() {
    local name="$1" payload output="" encoded_name line found=false
    _named_secret_name_valid "$name" || { echo "Error: Invalid secret name '$name'." >&2; return 2; }
    [[ -f "$SECRETS_FILE" ]] || { echo "Error: Named-secret store does not exist." >&2; return 1; }
    payload=$(_named_secrets_decrypt) || return 1
    encoded_name=$(_named_secret_encoded_name "$name")
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        if [[ "${line%%$'\t'*}" == "$encoded_name" ]]; then found=true; continue; fi
        output+="$line"$'\n'
    done <<< "$payload"
    [[ "$found" == true ]] || { echo "Error: Named secret not found: $name" >&2; return 1; }
    _named_secret_commit "$name" "$output" "0" delete || return $?
    echo "Named secret deleted: $name" >&2
}

named_secret_list() {
    local row_name recorded name recorded_iso
    printf 'NAME|RECORDED\n'
    [[ -r "$SECRETS_META_FILE" ]] || return 0
    while IFS='|' read -r row_name recorded; do
        [[ -n "$row_name" ]] || continue
        name=$(printf '%s' "$row_name" | /usr/bin/base64 -d 2>/dev/null) || continue
        recorded_iso="never"
        [[ "$recorded" =~ ^[0-9]+$ ]] && recorded_iso=$(_vault_iso_time "$recorded")
        printf '%s|%s\n' "$name" "$recorded_iso"
    done < "$SECRETS_META_FILE"
}

named_secret_status() {
    local mode="missing" permissions="not-applicable" sudo_state="locked" key_state="not-checked" sudo_bin key_file count=0
    if [[ -f "$SECRETS_FILE" ]]; then
        mode="sudo-gpg-v1"
        permissions=$(stat -c '%a' "$SECRETS_FILE" 2>/dev/null || printf 'unknown')
        count=$(awk -F'|' 'NF == 2 {count++} END {print count+0}' "$SECRETS_META_FILE" 2>/dev/null || printf '0')
    fi
    sudo_bin=$(_vault_sudo_bin 2>/dev/null || true)
    key_file=$(_sudo_vault_key_file)
    if [[ -n "$sudo_bin" && -x "$sudo_bin" ]] && "$sudo_bin" -n -v 2>/dev/null; then
        sudo_state="unlocked"
        if "$sudo_bin" -n /usr/bin/test -s "$key_file" 2>/dev/null && _sudo_vault_key_is_secure; then key_state="available"; else key_state="missing-or-insecure"; fi
    fi
    printf 'Named secrets: %s\nMode: %s\nPermissions: %s\nRecorded names: %s\nAuthentication: sudo/PAM\nSudo session: %s\nRoot key: %s\n' \
        "$SECRETS_FILE" "$mode" "$permissions" "$count" "$sudo_state" "$key_state"
}

named_secret_import_ssh() {
    local value="" recorded_at=""
    if _named_secret_recorded_at "ssh/default/password" >/dev/null 2>&1; then
        echo "SSH password is already mapped to ssh/default/password." >&2
        return 0
    fi
    [[ -f "$PASSWORD_FILE" ]] || { echo "Error: Legacy SSH vault not found: $PASSWORD_FILE" >&2; return 1; }
    recorded_at=$(stat -c '%Y' "$PASSWORD_FILE" 2>/dev/null || date +%s)
    if _vault_is_sudo_gated; then value=$(_decrypt_sudo_vault) || return 1; else value=$(_decrypt_legacy_vault) || return 1; fi
    [[ -n "$value" ]] || { echo "Error: Legacy SSH vault decrypted to an empty value." >&2; return 1; }
    _named_secret_set_value "ssh/default/password" "$value" "$recorded_at" || return $?
    unset value
    echo "SSH password imported as ssh/default/password. The legacy vault was left unchanged." >&2
}

_write_sudo_vault() {
    local secret="$1" vault_dir staged
    vault_dir=$(dirname "$PASSWORD_FILE")
    mkdir -p "$vault_dir" || return 1
    chmod 700 "$vault_dir" 2>/dev/null || true
    staged=$(mktemp "$vault_dir/.netrune-vault.XXXXXX") || return 1
    chmod 600 "$staged" || { rm -f -- "$staged"; return 1; }
    printf '%s\n' "$SUDO_VAULT_MAGIC" > "$staged"
    if ! printf '%s' "$secret" | _sudo_vault_gpg encrypt >> "$staged"; then
        rm -f -- "$staged"
        echo "Error: Failed to encrypt the SSH password; the existing vault was not changed." >&2
        return 1
    fi
    if ! mv -f "$staged" "$PASSWORD_FILE"; then
        rm -f -- "$staged"
        return 1
    fi
    chmod 600 "$PASSWORD_FILE" 2>/dev/null || return 1
}

_write_legacy_vault() {
    local secret="$1" vault_passphrase="" vault_passphrase_confirm="" vault_dir staged gpg_bin
    gpg_bin=$(_vault_gpg_bin) || return 1
    _read_secret_value vault_passphrase "Enter legacy GPG vault passphrase: " || return 1
    _read_secret_value vault_passphrase_confirm "Confirm legacy GPG vault passphrase: " || return 1
    [[ -n "$vault_passphrase" ]] || { echo "Error: GPG vault passphrase cannot be empty." >&2; return 1; }
    [[ "$vault_passphrase" == "$vault_passphrase_confirm" ]] || {
        echo "Error: GPG vault passphrases do not match." >&2
        return 1
    }
    vault_dir=$(dirname "$PASSWORD_FILE")
    mkdir -p "$vault_dir" || return 1
    chmod 700 "$vault_dir" 2>/dev/null || true
    staged=$(mktemp "$vault_dir/.netrune-vault.XXXXXX") || return 1
    if ! printf '%s' "$secret" | "$gpg_bin" --no-options --quiet --batch --yes \
            --pinentry-mode loopback --passphrase-fd 3 --symmetric \
            --cipher-algo AES256 -o "$staged" - 3<<<"$vault_passphrase"; then
        rm -f -- "$staged"
        echo "Error: Failed to encrypt the SSH password; the existing vault was not changed." >&2
        return 1
    fi
    chmod 600 "$staged"
    if ! mv -f "$staged" "$PASSWORD_FILE"; then
        rm -f -- "$staged"
        return 1
    fi
    unset vault_passphrase vault_passphrase_confirm
}

_decrypt_legacy_vault() {
    local decrypted="" passphrase="" gpg_bin
    gpg_bin=$(_vault_gpg_bin) || return 1
    if decrypted=$("$gpg_bin" --no-options --quiet --batch --yes \
            --pinentry-mode loopback --decrypt "$PASSWORD_FILE" 2>/dev/null); then
        printf '%s' "$decrypted"
        return 0
    fi
    _read_secret_value passphrase "Enter existing Netrune GPG vault passphrase: " || return 1
    [[ -n "$passphrase" ]] || { echo "Error: GPG vault passphrase cannot be empty." >&2; return 1; }
    if ! decrypted=$(printf '%s\n' "$passphrase" | "$gpg_bin" --no-options --quiet \
            --batch --yes --pinentry-mode loopback --passphrase-fd 0 \
            --decrypt "$PASSWORD_FILE" 2>/dev/null); then
        unset passphrase decrypted
        return 1
    fi
    unset passphrase
    printf '%s' "$decrypted"
}

_decrypt_sudo_vault() {
    local decrypted=""
    if ! decrypted=$({ IFS= read -r _vault_marker; command cat; } < "$PASSWORD_FILE" | _sudo_vault_gpg decrypt); then
        return 1
    fi
    printf '%s' "$decrypted"
}

set_password() {
    local requested_mode="${1:-${NETOPS_VAULT_MODE:-sudo-gpg}}"
    local new_pass="" new_pass_confirm=""
    case "${requested_mode,,}" in
        sudo|sudo-gpg|sudo-gpg-v1)
            _sudo_vault_prepare_key || return $?
            requested_mode="sudo-gpg"
            ;;
        legacy|legacy-gpg)
            requested_mode="legacy-gpg"
            ;;
        *)
            echo "Error: Unknown vault mode '$requested_mode' (use sudo-gpg or legacy-gpg)." >&2
            return 2
            ;;
    esac
    _read_secret_value new_pass "Enter new SSH password to save: " || {
        echo "Error: password input was cancelled." >&2
        return 1
    }
    _read_secret_value new_pass_confirm "Confirm new SSH password: " || {
        echo "Error: password confirmation was cancelled." >&2
        return 1
    }
    [[ -n "$new_pass" ]] || { echo "Error: SSH password cannot be empty." >&2; return 1; }
    [[ "$new_pass" == "$new_pass_confirm" ]] || { echo "Error: Passwords do not match." >&2; return 1; }
    if [[ "$requested_mode" == "sudo-gpg" ]]; then
        _named_secret_set_value "ssh/default/password" "$new_pass" || return $?
        echo "Password encrypted as named secret ssh/default/password." >&2
    else
        _write_legacy_vault "$new_pass" || return $?
        echo "Password encrypted in the legacy passphrase-gated local vault." >&2
    fi
    unset new_pass new_pass_confirm
    local lifecycle_status recorded_at expected_at window_start window_end remaining
    if IFS='|' read -r lifecycle_status recorded_at expected_at window_start window_end remaining < <(_vault_credential_lifecycle); then
        echo "Password rotation recorded: $(_vault_iso_time "$recorded_at")" >&2
        echo "Expected password expiry: $(_vault_iso_time "$expected_at") (estimated window $(_vault_iso_time "$window_start") to $(_vault_iso_time "$window_end"))" >&2
    fi
    return 0
}

migrate_password_store() {
    local decrypted="" recorded_at=""
    if _named_secret_recorded_at "ssh/default/password" >/dev/null 2>&1; then
        echo "SSH password is already stored as ssh/default/password." >&2
        return 0
    fi
    if [[ ! -f "$PASSWORD_FILE" ]]; then
        echo "Error: Password file not found. Run 'netrune vault set'." >&2
        return 1
    fi
    recorded_at=$(stat -c '%Y' "$PASSWORD_FILE" 2>/dev/null || true)
    _sudo_vault_prepare_key || return $?
    if _vault_is_sudo_gated; then
        decrypted=$(_decrypt_sudo_vault) || return 1
    else
        echo "Legacy GPG vault detected. One final terminal passphrase may be required." >&2
        if ! decrypted=$(_decrypt_legacy_vault); then
            echo "Error: Failed to decrypt the legacy GPG vault; it was not changed." >&2
            return 1
        fi
    fi
    [[ -n "$decrypted" ]] || {
        echo "Error: Legacy password vault decrypted to an empty value." >&2
        return 1
    }
    if ! _named_secret_set_value "ssh/default/password" "$decrypted" "${recorded_at:-$(date +%s)}"; then
        unset decrypted
        return 1
    fi
    unset decrypted
    echo "SSH password migrated to named secret ssh/default/password. The original vault was left unchanged." >&2
}

_vault_policy_integer() {
    local value="$1" fallback="$2" minimum="$3" maximum="$4"
    if [[ ! "$value" =~ ^[0-9]+$ ]] || ((10#$value < minimum || 10#$value > maximum)); then
        value="$fallback"
    fi
    printf '%s' "$((10#$value))"
}

_vault_iso_time() {
    local epoch="${1:-0}"
    [[ "$epoch" =~ ^[0-9]+$ ]] || return 1
    date -u -d "@$epoch" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null
}

_vault_credential_lifecycle() {
    local recorded_at now_epoch ttl_hours window_minutes warning_hours
    local expected_at window_start window_end warning_seconds remaining status
    if [[ -f "$SECRETS_FILE" ]]; then
        recorded_at=$(_named_secret_recorded_at "ssh/default/password") || return 1
    else
        [[ -f "$PASSWORD_FILE" ]] || return 1
        recorded_at=$(stat -c '%Y' "$PASSWORD_FILE" 2>/dev/null) || return 1
    fi
    [[ "$recorded_at" =~ ^[0-9]+$ ]] || return 1
    now_epoch="${NETOPS_VAULT_NOW_EPOCH:-$(date +%s)}"
    [[ "$now_epoch" =~ ^[0-9]+$ ]] || now_epoch=$(date +%s)
    ttl_hours=$(_vault_policy_integer "${CONFIG[vault_password_ttl_hours]:-72}" 72 1 8760)
    window_minutes=$(_vault_policy_integer "${CONFIG[vault_expiry_window_minutes]:-20}" 20 0 720)
    warning_hours=$(_vault_policy_integer "${CONFIG[vault_expiry_warning_hours]:-12}" 12 0 720)
    expected_at=$((recorded_at + ttl_hours * 3600))
    window_start=$((expected_at - window_minutes * 60))
    window_end=$((expected_at + window_minutes * 60))
    warning_seconds=$((warning_hours * 3600))
    remaining=$((expected_at - now_epoch))
    if ((now_epoch >= window_end)); then
        status="EXPIRED"
    elif ((now_epoch >= window_start)); then
        status="EXPIRY_WINDOW"
    elif ((remaining <= warning_seconds)); then
        status="DUE_SOON"
    else
        status="ACTIVE"
    fi
    printf '%s|%s|%s|%s|%s|%s\n' "$status" "$recorded_at" "$expected_at" "$window_start" "$window_end" "$remaining"
}

_vault_remaining_text() {
    local seconds="${1:-0}" sign="" days hours minutes
    [[ "$seconds" =~ ^-?[0-9]+$ ]] || { printf 'unknown'; return; }
    if ((seconds < 0)); then sign="-"; seconds=$((-seconds)); fi
    days=$((seconds / 86400))
    hours=$(((seconds % 86400) / 3600))
    minutes=$(((seconds % 3600) / 60))
    printf '%s%dd %02dh %02dm' "$sign" "$days" "$hours" "$minutes"
}

_warn_vault_credential_lifecycle() {
    local status recorded_at expected_at window_start window_end remaining
    [[ "${NETOPS_VAULT_SUPPRESS_AGE_WARNING:-false}" =~ ^(1|true|yes)$ ]] && return 0
    [[ "${NETOPS_VAULT_AGE_WARNING_SHOWN:-false}" == "true" ]] && return 0
    NETOPS_VAULT_AGE_WARNING_SHOWN=true
    IFS='|' read -r status recorded_at expected_at window_start window_end remaining < <(_vault_credential_lifecycle) || return 0
    case "$status" in
        DUE_SOON)
            echo "Warning: The switch password is due to rotate in $(_vault_remaining_text "$remaining") (expected $(_vault_iso_time "$expected_at"))." >&2
            ;;
        EXPIRY_WINDOW)
            echo "Warning: The switch password is inside its estimated expiry window ($(_vault_iso_time "$window_start") to $(_vault_iso_time "$window_end"))." >&2
            echo "If authentication is rejected, update it with 'netrune vault set' or 'connect -p'." >&2
            ;;
        EXPIRED)
            echo "Warning: The stored switch password is likely expired; expected expiry was $(_vault_iso_time "$expected_at")." >&2
            echo "Update it with 'netrune vault set' or 'connect -p'." >&2
            ;;
    esac
}

password_store_status() {
    local mode="missing" sudo_state="not-applicable" key_state="not-checked" sudo_bin key_file vault_path="$PASSWORD_FILE"
    local status="UNKNOWN" recorded_at="" expected_at="" window_start="" window_end="" remaining=""
    local recorded_iso="never" expected_iso="unknown" window_start_iso="unknown" window_end_iso="unknown" remaining_text="unknown"
    if [[ -f "$SECRETS_FILE" ]] && _named_secret_recorded_at "ssh/default/password" >/dev/null 2>&1; then
        mode="sudo-gpg-v1"
        vault_path="$SECRETS_FILE (ssh/default/password)"
    elif [[ -f "$PASSWORD_FILE" ]]; then
        mode="legacy-gpg"
        _vault_is_sudo_gated && mode="sudo-gpg-v1"
    fi
    if [[ "$mode" == "sudo-gpg-v1" ]]; then
        sudo_state="locked"
        sudo_bin=$(_vault_sudo_bin 2>/dev/null || true)
        key_file=$(_sudo_vault_key_file)
        if [[ -n "$sudo_bin" && -x "$sudo_bin" ]] && "$sudo_bin" -n -v 2>/dev/null; then
            sudo_state="unlocked"
            if "$sudo_bin" -n /usr/bin/test -s "$key_file" 2>/dev/null && _sudo_vault_key_is_secure; then
                key_state="available"
            elif "$sudo_bin" -n /usr/bin/test -e "$key_file" 2>/dev/null; then
                key_state="insecure"
            else
                key_state="missing"
            fi
        fi
    fi
    IFS='|' read -r status recorded_at expected_at window_start window_end remaining < <(_vault_credential_lifecycle) || true
    [[ "$recorded_at" =~ ^[0-9]+$ ]] && recorded_iso=$(_vault_iso_time "$recorded_at")
    [[ "$expected_at" =~ ^[0-9]+$ ]] && expected_iso=$(_vault_iso_time "$expected_at")
    [[ "$window_start" =~ ^[0-9]+$ ]] && window_start_iso=$(_vault_iso_time "$window_start")
    [[ "$window_end" =~ ^[0-9]+$ ]] && window_end_iso=$(_vault_iso_time "$window_end")
    [[ "$remaining" =~ ^-?[0-9]+$ ]] && remaining_text=$(_vault_remaining_text "$remaining")
    printf 'Vault: %s\nMode: %s\nPassword recorded: %s\nExpected expiry: %s\nExpiry window: %s to %s\nCredential state: %s\nRemaining to expected: %s\nSudo session: %s\nRoot key: %s\n' \
        "$vault_path" "$mode" "$recorded_iso" "$expected_iso" "$window_start_iso" "$window_end_iso" \
        "$status" "$remaining_text" "$sudo_state" "$key_state"
}

get_password_from_store() {
    local decrypted=""
    if [[ -f "$SECRETS_FILE" ]] && _named_secret_recorded_at "ssh/default/password" >/dev/null 2>&1; then
        _warn_vault_credential_lifecycle
        if ! decrypted=$(named_secret_get "ssh/default/password"); then
            echo "Error: Failed to decrypt named secret ssh/default/password." >&2
            SSHPASS=""
            return 1
        fi
        [[ -n "$decrypted" ]] || { echo "Error: SSH named secret decrypted to an empty value." >&2; return 1; }
        SSHPASS="$decrypted"
        unset decrypted
        export SSHPASS
        return 0
    fi
    if [[ ! -f "$PASSWORD_FILE" ]]; then
        echo "Error: SSH password not found. Run 'netrune vault set'." >&2
        return 1
    fi
    chmod 600 "$PASSWORD_FILE" 2>/dev/null || {
        echo "Error: Could not restrict SSH vault permissions: $PASSWORD_FILE" >&2
        return 1
    }
    _warn_vault_credential_lifecycle
    if _vault_is_sudo_gated; then
        if ! decrypted=$(_decrypt_sudo_vault); then
            echo "Error: Failed to decrypt the sudo-gated password vault." >&2
            SSHPASS=""
            return 1
        fi
    else
        echo "Notice: legacy GPG vault detected. Run 'netrune vault migrate' to use one sudo prompt without graphical pinentry." >&2
        if ! decrypted=$(_decrypt_legacy_vault); then
            echo "Error: Failed to decrypt the legacy password vault." >&2
            SSHPASS=""
            return 1
        fi
    fi
    [[ -n "$decrypted" ]] || { echo "Error: Password vault decrypted to an empty value." >&2; return 1; }
    SSHPASS="$decrypted"
    unset decrypted
    export SSHPASS
}

unlock_password_store() {
    local ttl_minutes="${1:-}" expires session_dir
    if [[ -z "$ttl_minutes" ]]; then
        ttl_minutes=$(_vault_policy_integer "${CONFIG[vault_session_ttl_minutes]:-15}" 15 1 480)
    fi

    # Read the key through sudo once, deliberately bypassing any existing
    # session so that unlocking always re-authenticates and the new window is
    # anchored to a fresh authentication rather than silently extended.
    session_dir=$(_vault_session_dir) || {
        echo "Error: No per-user runtime directory is available for a vault session." >&2
        return 1
    }
    if ! expires=$(NETRUNE_VAULT_SESSION_BYPASS=1 _sudo_vault_emit_key | _vault_session_store "$ttl_minutes"); then
        _vault_session_clear
        return 1
    fi

    # Prove the cached key actually opens the vault before promising a window.
    if ! get_password_from_store; then
        _vault_session_clear
        echo "Error: The vault did not decrypt with the cached key; the session was discarded." >&2
        return 1
    fi
    SSHPASS=""
    unset SSHPASS
    echo "SSH vault unlocked until $(date -d "@$expires" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || printf '%s' "$expires") (${ttl_minutes}m)." >&2
    echo "The key is held in memory at $session_dir and is readable by this user until then." >&2
    echo "Run 'netrune vault lock' to end the session early." >&2
}

lock_password_store() {
    local expires
    expires=$(_vault_session_expires_at 2>/dev/null) || expires=""
    _vault_session_clear
    if [[ -n "$expires" ]]; then
        echo "SSH vault session ended; the next command will authenticate again." >&2
    else
        echo "No SSH vault session was active." >&2
    fi
    return 0
}

netops_platform_family() {
    local evidence
    evidence=$(printf '%s %s %s' "${1:-}" "${2:-}" "${3:-}" | tr '[:lower:]' '[:upper:]')
    if [[ "$evidence" =~ (SMARTZONE|VIRTUAL[[:space:]-]*SMARTZONE|VSZ|SZ100|SZ144|SZ300) ]]; then
        printf 'ruckus-smartzone'
    elif [[ "$evidence" =~ (RUCKUS|BROCADE|FASTIRON|FOUNDRY|ICX) ]] && [[ "$evidence" =~ (ACCESS[[:space:]-]*POINT|RUCKUS[[:space:]-]*AP|ZONEFLEX|R[0-9]{3,4}|T[0-9]{3,4}|H[0-9]{3,4}) ]]; then
        printf 'ruckus-ap'
    elif [[ "$evidence" =~ (RUCKUS|BROCADE|FASTIRON|FOUNDRY|ICX) ]]; then
        printf 'ruckus-fastiron'
    elif [[ "$evidence" =~ (AOS-CX|ARUBAOS-CX|ARUBA[[:space:]-]*CX|CX[[:space:]-]*(4100|6000|6100|6200|6300|6400|8100|8320|8325|8360|8400|9300|10000)) ]]; then
        printf 'aruba-aos-cx'
    elif [[ "$evidence" =~ (ARUBA|PROCURVE|HEWLETT[[:space:]-]*PACKARD|HP[[:space:]]+(2530|2540|2920|2930|3810|5400|J[A-Z]?[0-9]{3,4}[A-Z])) ]]; then
        printf 'aruba-aos-switch'
    elif [[ "$evidence" =~ (CISCO|IOS|IOS-XE|NX-OS|CATALYST|NEXUS) ]]; then
        printf 'cisco-ios'
    else
        printf 'unknown'
    fi
}

_ssh_filter_supported_algorithms() {
    local query="$1" supported candidate output=""
    shift
    command -v ssh >/dev/null 2>&1 || return 1
    supported=$(ssh -Q "$query" 2>/dev/null) || return 1
    for candidate in "$@"; do
        if grep -Fqx -- "$candidate" <<< "$supported"; then
            [[ -n "$output" ]] && output+=","
            output+="$candidate"
        fi
    done
    printf '%s' "$output"
}

ssh_failure_kind() {
    local text="${1:-}"
    if grep -Eqi 'protocol major versions differ|remote protocol version 1\.|SSH protocol version 1' <<< "$text"; then
        printf 'LEGACY_PROTOCOL'
    elif grep -Eqi 'no matching key exchange|no matching KEX' <<< "$text"; then
        printf 'KEX'
    elif grep -Eqi 'no matching host key|no hostkey alg' <<< "$text"; then
        printf 'HOST_KEY'
    elif grep -Eqi 'no matching cipher' <<< "$text"; then
        printf 'CIPHER'
    elif grep -Eqi 'no matching MAC' <<< "$text"; then
        printf 'MAC'
    elif grep -Eqi 'Unable to negotiate|Their offer:' <<< "$text"; then
        printf 'NEGOTIATION'
    elif grep -Eqi 'Permission denied|authentication failed|access denied|login incorrect' <<< "$text"; then
        printf 'AUTHENTICATION'
    elif grep -Eqi 'REMOTE HOST IDENTIFICATION HAS CHANGED|Host key verification failed' <<< "$text"; then
        printf 'HOST_TRUST'
    else
        printf 'OTHER'
    fi
}

ssh_failure_offer() {
    local text="${1:-}"
    sed -nE 's/.*Their offer:[[:space:]]*//Ip' <<< "$text" | head -1 | tr -d '\r'
}

_build_ssh_opts() {
    local -n destination="$1"
    local mode="${NETOPS_SSH_HOST_KEY_MODE:-${CONFIG[ssh_host_key_mode]:-accept-new}}"
    local known_hosts="${NETOPS_SSH_KNOWN_HOSTS_FILE:-${CONFIG_DIR}/known_hosts}"
    local strict="accept-new"
    case "${mode,,}" in
        strict) strict="yes" ;;
        accept-new|accept_new|managed) strict="accept-new" ;;
        break-glass|break_glass|insecure)
            if [[ "${NETOPS_SSH_BREAK_GLASS:-false}" =~ ^(1|true|yes)$ ]]; then
                strict="no"
                known_hosts="/dev/null"
                echo "[WARN] SSH host-key verification is disabled for this break-glass session." >&2
            else
                echo "Error: Break-glass SSH requires NETOPS_SSH_BREAK_GLASS=true for this one process." >&2
                return 8
            fi
            ;;
        *)
            echo "Error: Unsupported ssh_host_key_mode '$mode' (use strict or accept-new)." >&2
            return 6
            ;;
    esac
    if [[ "$known_hosts" != "/dev/null" ]]; then
        mkdir -p "$(dirname "$known_hosts")" || return 1
        touch "$known_hosts" || return 1
        chmod 600 "$known_hosts" 2>/dev/null || return 1
    fi
    export NETOPS_SSH_STRICT_HOST_KEY_CHECKING="$strict"
    export NETOPS_SSH_KNOWN_HOSTS_FILE="$known_hosts"
    destination=("-o" "StrictHostKeyChecking=$strict" "-o" "UserKnownHostsFile=$known_hosts" "-o" "LogLevel=ERROR")
    export NETOPS_SSH_LEGACY_ENABLED="false"
    unset NETOPS_SSH_KEX_ALGORITHMS NETOPS_SSH_HOST_KEY_ALGORITHMS NETOPS_SSH_CIPHERS NETOPS_SSH_MACS
    if [[ "${CONFIG[legacy_ssh]}" == "true" ]]; then
        local kex host_keys ciphers macs
        kex=$(_ssh_filter_supported_algorithms kex \
            diffie-hellman-group1-sha1 diffie-hellman-group14-sha1 diffie-hellman-group-exchange-sha1)
        host_keys=$(_ssh_filter_supported_algorithms key ssh-rsa ssh-dss)
        ciphers=$(_ssh_filter_supported_algorithms cipher aes128-cbc aes192-cbc aes256-cbc 3des-cbc)
        macs=$(_ssh_filter_supported_algorithms mac hmac-sha1 hmac-sha1-96 hmac-md5 hmac-md5-96)
        [[ -n "$kex" ]] && destination+=("-o" "KexAlgorithms=+$kex")
        [[ -n "$host_keys" ]] && destination+=("-o" "HostKeyAlgorithms=+$host_keys")
        [[ -n "$ciphers" ]] && destination+=("-o" "Ciphers=+$ciphers")
        [[ -n "$macs" ]] && destination+=("-o" "MACs=+$macs")
        export NETOPS_SSH_LEGACY_ENABLED="true"
        export NETOPS_SSH_KEX_ALGORITHMS="$kex"
        export NETOPS_SSH_HOST_KEY_ALGORITHMS="$host_keys"
        export NETOPS_SSH_CIPHERS="$ciphers"
        export NETOPS_SSH_MACS="$macs"
    fi
}

_ssh_user_value() {
    local user="${CREDS[ssh_user]:-${CONFIG[ssh_user]:-}}"
    if [[ -z "$user" ]]; then
        echo "Error: SSH username is not configured for this profile." >&2
        echo "Set it with: netrune config set ssh_user <username>" >&2
        return 6
    fi
    if ((${#user} > 255)) || [[ "$user" =~ [[:space:]] ]]; then
        echo "Error: Configured SSH username is invalid; it must be 1-255 characters without whitespace." >&2
        return 6
    fi
    printf '%s' "$user"
}

netops_ssh() {
    local ip="$1"; shift
    local ssh_user
    ssh_user=$(_ssh_user_value) || return $?
    if [[ -z "$SSHPASS" ]]; then
        get_password_from_store || return $?
    fi

    local plat=$(db_get_device "$ip" | cut -d'|' -f3)
    local library_dir aruba_wrapper
    library_dir=$(dirname "$(realpath "${BASH_SOURCE[0]}")")
    aruba_wrapper="${NETOPS_ARUBA_SSH_WRAPPER:-$library_dir/netops_aruba_ssh.exp}"
    
    # Use the prompt-aware wrapper for automated Aruba command streams.
    if [[ "$plat" =~ ^(Aruba|Ruckus) && -x "$aruba_wrapper" ]]; then
        if [[ ! -t 0 || $# -gt 0 ]]; then
            netops_ssh_prompted "$ip" "$@"
            return $?
        fi
    fi

    local -a ssh_opts=()
    _build_ssh_opts ssh_opts || return $?
    if [[ "${NETOPS_SSH_SHOW_ERRORS:-false}" == "true" ]]; then
        sshpass -e ssh -tt "${ssh_opts[@]}" -l "$ssh_user" "$ip" "$@"
    else
        sshpass -e ssh -tt "${ssh_opts[@]}" -l "$ssh_user" "$ip" "$@" 2>/dev/null
    fi
}

# Run an automated command stream and wait for the device prompt after every
# command. This is required for long-running read-only commands such as ping,
# where plain piped SSH may close before the summary is emitted.
netops_ssh_prompted() {
    local ip="$1"; shift
    local ssh_user
    ssh_user=$(_ssh_user_value) || return $?
    if [[ -z "$SSHPASS" ]]; then
        get_password_from_store || return $?
    fi
    local library_dir wrapper
    library_dir=$(dirname "$(realpath "${BASH_SOURCE[0]}")")
    wrapper="${NETOPS_ARUBA_SSH_WRAPPER:-$library_dir/netops_aruba_ssh.exp}"
    [[ -x "$wrapper" ]] || {
        echo "ERROR: prompt-aware SSH wrapper is unavailable: $wrapper" >&2
        return 1
    }
    export CREDS_ssh_user="$ssh_user"
    export SSHPASS
    local -a ssh_opts=()
    _build_ssh_opts ssh_opts || return $?
    "$wrapper" "$ip" "$@"
}

export -f db_update_device db_get_device snmp_cache_get snmp_cache_put snmp_cache_version netops_snmp_get_many netops_snmp_get netops_snmp_walk _build_snmp3_opts netops_ssh netops_ssh_prompted _build_ssh_opts _ssh_user_value netops_platform_family ssh_failure_kind ssh_failure_offer

resolve_targets() {
    local input="$1" scope="${2:-DEVICES}" allow_multiple="${3:-false}"
    local resolve_mode="${NETOPS_RESOLVE_MODE:-$allow_multiple}"
    local candidates=()

    valid_ipv4() {
        local candidate="$1" octet
        [[ "$candidate" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
        IFS='.' read -r -a octets <<< "$candidate"
        for octet in "${octets[@]}"; do
            ((10#$octet >= 0 && 10#$octet <= 255)) || return 1
        done
    }

    if valid_ipv4 "$input"; then
        printf '%s\n' "$input"
        return 0
    elif [[ "$input" =~ ^([0-9]+\.){3}[0-9]+$ ]]; then
        echo "Invalid IPv4 target: $input" >&2
        return 1
    fi

    # A profile may define an IPv4 prefix for local abbreviations. Fresh
    # profiles leave this empty, so numeric-looking names are never rewritten.
    local abbreviation_prefix="${NETOPS_TARGET_ABBREVIATION_PREFIX:-${CONFIG[target_abbreviation_prefix]:-}}"
    abbreviation_prefix="${abbreviation_prefix#.}"; abbreviation_prefix="${abbreviation_prefix%.}"
    if [[ -n "$abbreviation_prefix" && "$abbreviation_prefix" =~ ^([0-9]{1,3}\.){0,2}[0-9]{1,3}$ ]]; then
        local abbreviated="${input#.}" candidate="" prefix_count suffix_count
        IFS='.' read -r -a prefix_parts <<< "$abbreviation_prefix"
        if [[ "$abbreviated" =~ ^([0-9]{1,3}\.){0,2}[0-9]{1,3}$ ]]; then
            IFS='.' read -r -a suffix_parts <<< "$abbreviated"
            prefix_count=${#prefix_parts[@]}; suffix_count=${#suffix_parts[@]}
            if ((prefix_count + suffix_count == 4)); then
                candidate="${abbreviation_prefix}.${abbreviated}"
                if valid_ipv4 "$candidate"; then printf '%s\n' "$candidate"; return 0; fi
            fi
        elif [[ "$abbreviated" =~ ^(.+)\.([0-9]{1,3})-([0-9]{1,3})$ ]]; then
            local suffix_base="${BASH_REMATCH[1]}" start=$((10#${BASH_REMATCH[2]})) end=$((10#${BASH_REMATCH[3]}))
            IFS='.' read -r -a suffix_parts <<< "$suffix_base"
            prefix_count=${#prefix_parts[@]}; suffix_count=${#suffix_parts[@]}
            if ((prefix_count + suffix_count == 3 && start >= 1 && start <= 254 && end >= start && end <= 254)); then
                candidate="${abbreviation_prefix}.${suffix_base}.1"
                if valid_ipv4 "$candidate"; then
                    for ((i=start; i<=end; i++)); do candidates+=("${abbreviation_prefix}.${suffix_base}.${i}"); done
                    printf '%s\n' "${candidates[@]}"; return 0
                fi
            fi
        fi
    fi

    if [[ "$input" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})-([0-9]{1,3})$ ]]; then
        local o1=$((10#${BASH_REMATCH[1]})) o2=$((10#${BASH_REMATCH[2]})) o3=$((10#${BASH_REMATCH[3]}))
        local start=$((10#${BASH_REMATCH[4]})) end=$((10#${BASH_REMATCH[5]}))
        if ((o1 <= 255 && o2 <= 255 && o3 <= 255 && start >= 1 && start <= 254 && end >= start && end <= 254)); then
            for ((i=start; i<=end; i++)); do candidates+=("${o1}.${o2}.${o3}.${i}"); done
            printf '%s\n' "${candidates[@]}"; return 0
        fi
        echo "Invalid IPv4 range: $input" >&2
        return 1
    elif [[ "$input" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.$ ]]; then
        local o1=$((10#${BASH_REMATCH[1]})) o2=$((10#${BASH_REMATCH[2]})) o3=$((10#${BASH_REMATCH[3]}))
        if ((o1 <= 255 && o2 <= 255 && o3 <= 255)); then
            for i in {1..254}; do candidates+=("${o1}.${o2}.${o3}.${i}"); done
            printf '%s\n' "${candidates[@]}"; return 0
        fi
        echo "Invalid IPv4 prefix: $input" >&2
        return 1
    fi

    if [[ -f "$input" ]]; then
        mapfile -t candidates < <(sed 's/\r$//' "$input" | sed '/^[[:space:]]*#/d; /^[[:space:]]*$/d')
        ((${#candidates[@]})) || { echo "Target file contains no usable entries: $input" >&2; return 1; }
        printf '%s\n' "${candidates[@]}"; return 0
    fi

    local search_files=()
    [[ "$scope" == "DEVICES" || "$scope" == "ALL" ]] && search_files+=("$DEVICES_DB")
    [[ "$scope" == "APS" || "$scope" == "ALL" ]] && search_files+=("$AP_DB")

    local matches ip unique_matches match_count
    matches=$(grep -ihF -- "$input" "${search_files[@]}" 2>/dev/null | sed 's/.*\.db://')
    if [[ -z "$matches" ]]; then
        ip=$(getent ahostsv4 "$input" 2>/dev/null | awk '{print $1; exit}')
        [[ -z "$ip" ]] && ip=$(getent hosts "$input" 2>/dev/null | awk '$1 ~ /^([0-9]+\.){3}[0-9]+$/ {print $1; exit}')
        if [[ -n "$ip" ]]; then echo "$ip"; return 0; fi
        echo "No target matched: $input" >&2
        return 1
    fi

    unique_matches=$(echo "$matches" | sort -u)
    match_count=$(echo "$unique_matches" | wc -l)
    case "$resolve_mode" in
        true|all|ALL)
            echo "$unique_matches" | cut -d'|' -f1 | sort -u
            return 0 ;;
        first|FIRST)
            echo "$unique_matches" | head -1 | cut -d'|' -f1
            return 0 ;;
    esac

    if [[ "$match_count" -eq 1 ]]; then
        echo "$unique_matches" | cut -d'|' -f1
        return 0
    fi

    echo -e "\033[1;33mFound multiple matches. Please choose one:\033[0m" >&2
    local i=1 sel
    declare -a sel_map
    while IFS='|' read -r ip host plat mod ser mac src ts st; do
        local color="\033[0;32m"; [[ "$st" == "OFFLINE" ]] && color="\033[0;31m"
        printf "  \033[1m%2d)\033[0m %b%-15s\033[0m %-20s (%s)\n" "$i" "$color" "$ip" "$host" "$plat" >&2
        sel_map[$i]="$ip"
        ((i++))
    done <<< "$unique_matches"
    echo "" >&2

    local tty_fd=""
    if { exec {tty_fd}<>/dev/tty; } 2>/dev/null; then
        read -rp "Enter number to select: " sel <&"$tty_fd"
        exec {tty_fd}>&-
    elif [[ -t 0 ]]; then
        read -rp "Enter number to select: " sel
    else
        echo "Ambiguous target '$input' and no interactive terminal is available for selection." >&2
        echo "Use an exact IP/hostname, or set NETOPS_RESOLVE_MODE=first to choose the first match." >&2
        return 2
    fi

    if [[ "$sel" =~ ^[0-9]+$ && -n "${sel_map[$sel]}" ]]; then
        echo "${sel_map[$sel]}"
        return 0
    fi
    echo "Invalid selection: $sel" >&2
    return 1
}
