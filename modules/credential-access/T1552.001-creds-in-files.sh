#!/usr/bin/env bash

MODULE_ID="T1552.001"
MODULE_TECHNIQUE="Unsecured Credentials: Credentials In Files"
MODULE_DESCRIPTION="Detect recent access to sensitive credential files such as .env files, AWS credentials, SSH private keys, and VPN configuration profiles."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../../core/output.sh"

RECENT_WINDOW_HOURS="${RECENT_WINDOW_HOURS:-24}"
ENV_SEARCH_DEPTH="${ENV_SEARCH_DEPTH:-5}"

get_atime_epoch() {
    local target="$1"
    local atime=""

    atime=$(stat -f "%a" "$target" 2>/dev/null || true)
    if ! [[ "$atime" =~ ^[0-9]+$ ]]; then
        atime=$(stat -c "%X" "$target" 2>/dev/null || true)
    fi

    if ! [[ "$atime" =~ ^[0-9]+$ ]]; then
        return 1
    fi

    printf "%s\n" "$atime"
}

format_epoch() {
    local epoch="$1"

    date -r "$epoch" "+%Y-%m-%d %H:%M:%S" 2>/dev/null || \
        date -d "@$epoch" "+%Y-%m-%d %H:%M:%S" 2>/dev/null || \
        printf "%s" "$epoch"
}

check_recent_access() {
    local label="$1"
    local target="$2"
    local now_epoch="$3"
    local window_seconds="$4"
    local atime_epoch
    local age_seconds
    local accessed_at

    [ -f "$target" ] || return 1

    atime_epoch=$(get_atime_epoch "$target") || return 1
    age_seconds=$((now_epoch - atime_epoch))
    if [ "$age_seconds" -lt 0 ]; then
        age_seconds=0
    fi

    if [ "$age_seconds" -le "$window_seconds" ]; then
        accessed_at=$(format_epoch "$atime_epoch")
        emit_finding "$MODULE_ID" "$MODULE_TECHNIQUE" "medium" \
            "Sensitive credential file accessed within the last ${RECENT_WINDOW_HOURS} hour(s)" \
            "$label was accessed at $accessed_at ($target)" \
            "Review the process or user that touched the file, rotate exposed credentials, and tighten file access permissions."
        return 0
    fi

    return 1
}

run_checks() {
    local findings=0
    local now_epoch
    local window_seconds
    local file_path
    local vpn_root

    now_epoch=$(date +%s)
    window_seconds=$((RECENT_WINDOW_HOURS * 3600))

    if check_recent_access "AWS shared credentials file" "$HOME/.aws/credentials" "$now_epoch" "$window_seconds"; then
        findings=$((findings + 1))
    fi

    if [ -d "$HOME/.ssh" ]; then
        while IFS= read -r file_path; do
            if check_recent_access "SSH private key" "$file_path" "$now_epoch" "$window_seconds"; then
                findings=$((findings + 1))
            fi
        done < <(find "$HOME/.ssh" -maxdepth 1 -type f -name "id_*" ! -name "*.pub" 2>/dev/null)
    fi

    while IFS= read -r file_path; do
        if check_recent_access ".env file" "$file_path" "$now_epoch" "$window_seconds"; then
            findings=$((findings + 1))
        fi
    done < <(
        find "$HOME" -maxdepth "$ENV_SEARCH_DEPTH" -type f \
            \( -name ".env" -o -name ".env.*" \) \
            ! -path "*/.git/*" \
            ! -path "*/node_modules/*" \
            ! -path "*/Library/*" \
            2>/dev/null
    )

    for vpn_root in \
        "$HOME/.config/openvpn" \
        "$HOME/.openvpn" \
        "$HOME/Library/Application Support/OpenVPN Connect/profiles" \
        "$HOME/.config/wireguard" \
        "$HOME/Library/Application Support/WireGuard/configurations" \
        "/etc/openvpn" \
        "/etc/openvpn/client" \
        "/etc/wireguard" \
        "/usr/local/etc/openvpn"
    do
        [ -d "$vpn_root" ] || continue
        while IFS= read -r file_path; do
            if check_recent_access "VPN configuration" "$file_path" "$now_epoch" "$window_seconds"; then
                findings=$((findings + 1))
            fi
        done < <(find "$vpn_root" -maxdepth 3 -type f \( -name "*.ovpn" -o -name "*.conf" \) 2>/dev/null)
    done

    if [ "$findings" -eq 0 ]; then
        emit_clean "$MODULE_ID" "$MODULE_TECHNIQUE"
    fi
}

run_checks
