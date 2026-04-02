#!/bin/bash

MODULE_ID="T1041"
MODULE_TECHNIQUE="Exfiltration Over C2 Channel"
MODULE_DESCRIPTION="Detect suspicious established connections and webhook-style destinations using the v1 macOS scanner network checks."

source "$(dirname "$0")/../../core/output.sh"

run_checks() {
    local findings=0
    local lsof_net
    local suspicious_ports
    local suspicious_connections
    local webhook_connections

    lsof_net=$(lsof -i -nP 2>/dev/null | grep ESTABLISHED || true)
    suspicious_ports="4444|5555|6666|7777|8888|9999|1337|31337|12345|54321"

    suspicious_connections=$(printf "%s\n" "$lsof_net" | grep -E ":($suspicious_ports)" | grep -v "localhost" || true)
    if [ -n "$suspicious_connections" ]; then
        emit_finding "$MODULE_ID" "$MODULE_TECHNIQUE" "high" \
            "Established connection on a suspicious port" \
            "$suspicious_connections" \
            "Inspect the owning process and block the connection if it is unauthorized."
        findings=$((findings + 1))
    fi

    webhook_connections=$(printf "%s\n" "$lsof_net" | grep -iE "discord|telegram|pastebin" | head -10 || true)
    if [ -n "$webhook_connections" ]; then
        emit_finding "$MODULE_ID" "$MODULE_TECHNIQUE" "medium" \
            "Connection to a likely exfiltration service" \
            "$webhook_connections" \
            "Review the process making the connection and rotate any potentially exposed data."
        findings=$((findings + 1))
    fi

    # TODO: v1 did not include a maintained list of known C2 IPs or ranges.
    emit_info "$MODULE_ID" "TODO: Known C2 IP matching was not implemented in v1."
    # TODO: v1 only grepped Discord, Telegram, and Pastebin; Slack webhook detection was not present.
    emit_info "$MODULE_ID" "TODO: Slack webhook detection was not implemented in v1."
    # TODO: v1 did not include DNS-over-HTTPS detection.
    emit_info "$MODULE_ID" "TODO: DNS-over-HTTPS detection was not implemented in v1."

    if [ "$findings" -eq 0 ]; then
        emit_clean "$MODULE_ID" "$MODULE_TECHNIQUE"
    fi
}

run_checks
