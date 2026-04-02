#!/bin/bash

MODULE_ID="T1041"
MODULE_TECHNIQUE="Exfiltration Over C2 Channel"
MODULE_DESCRIPTION="Detect suspicious outbound channels, webhook exfiltration clues, and C2-style network behavior."

source "$(dirname "$0")/../../core/output.sh"

collect_shell_history_hits() {
    local pattern="$1"
    local history_hits=""
    local history_file

    for history_file in "$HOME/.bash_history" "$HOME/.zsh_history"; do
        [ -f "$history_file" ] || continue
        history_hits+=$(grep -iE "$pattern" "$history_file" 2>/dev/null | head -5 || true)
        history_hits+=$'\n'
    done

    printf "%s" "$history_hits" | sed '/^[[:space:]]*$/d'
}

collect_disk_hits() {
    local pattern="$1"
    local path
    local disk_hits=""
    local scan_roots="${INFOSTEALER_SCAN_PATHS:-/tmp:$HOME/Downloads:$HOME/Library/Caches}"
    local root_list=()

    IFS=':' read -r -a root_list <<< "$scan_roots"
    for path in "${root_list[@]}"; do
        [ -d "$path" ] || continue
        disk_hits+=$(grep -RilE "$pattern" "$path" 2>/dev/null | head -10 || true)
        disk_hits+=$'\n'
    done

    printf "%s" "$disk_hits" | sed '/^[[:space:]]*$/d'
}

run_checks() {
    local findings=0
    local lsof_numeric
    local lsof_host
    local suspicious_ports
    local suspicious_connections
    local service_hits
    local history_hits
    local disk_hits
    local dns_hits
    local exfil_pattern
    local doh_pattern

    lsof_numeric=$(lsof -i -nP 2>/dev/null | grep ESTABLISHED || true)
    lsof_host=$(lsof -i -P 2>/dev/null | grep ESTABLISHED || true)
    suspicious_ports="4444|5555|6666|7777|8888|9999|1337|31337|12345|54321"
    exfil_pattern='discord(app)?\.com/api/webhooks|hooks\.slack\.com/services|api\.telegram\.org/bot|pastebin\.com|transfer\.sh|file\.io|gofile\.io|steamcommunity\.com/(profiles|id)/|docs\.google\.com/forms|forms\.gle/'
    doh_pattern='cloudflare-dns\.com|dns\.google|doh\.opendns\.com'

    suspicious_connections=$(printf "%s\n" "$lsof_numeric" | grep -E ":($suspicious_ports)([^0-9]|$)" | grep -v "localhost" || true)
    if [ -n "$suspicious_connections" ]; then
        emit_finding "$MODULE_ID" "$MODULE_TECHNIQUE" "high" \
            "Established connection on a suspicious port" \
            "$suspicious_connections" \
            "Inspect the owning process and block the connection if it is unauthorized."
        findings=$((findings + 1))
    fi

    service_hits=$(printf "%s\n%s\n" "$lsof_numeric" "$lsof_host" | grep -iE "$exfil_pattern|$doh_pattern" | grep -v '^$' | sort -u | head -10 || true)
    if [ -n "$service_hits" ]; then
        emit_finding "$MODULE_ID" "$MODULE_TECHNIQUE" "high" \
            "Connection or endpoint associated with exfiltration services" \
            "$service_hits" \
            "Review the process making the connection and rotate any potentially exposed data."
        findings=$((findings + 1))
    fi

    history_hits=$(collect_shell_history_hits "$exfil_pattern")
    if [ -n "$history_hits" ]; then
        emit_finding "$MODULE_ID" "$MODULE_TECHNIQUE" "medium" \
            "Shell history references webhook or exfiltration endpoints" \
            "$history_hits" \
            "Review recent shell commands for unauthorized upload or dead-drop activity."
        findings=$((findings + 1))
    fi

    disk_hits=$(collect_disk_hits "$exfil_pattern")
    if [ -n "$disk_hits" ]; then
        emit_finding "$MODULE_ID" "$MODULE_TECHNIQUE" "medium" \
            "Webhook or exfiltration endpoints present on disk" \
            "$disk_hits" \
            "Inspect matching files for staged exfiltration logic or stolen-data upload paths."
        findings=$((findings + 1))
    fi

    dns_hits=$(log show --style compact --last 1h 2>/dev/null | grep -iE "$exfil_pattern|$doh_pattern" | head -10 || true)
    if [ -n "$dns_hits" ]; then
        emit_finding "$MODULE_ID" "$MODULE_TECHNIQUE" "medium" \
            "Recent DNS or unified log hits for exfiltration services" \
            "$dns_hits" \
            "Review the responsible process and correlate with outbound connections."
        findings=$((findings + 1))
    fi

    if [ "$findings" -eq 0 ]; then
        emit_clean "$MODULE_ID" "$MODULE_TECHNIQUE"
    fi
}

run_checks
