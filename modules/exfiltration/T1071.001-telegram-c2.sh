#!/usr/bin/env bash
MODULE_ID="telegram-c2"
MODULE_TECHNIQUE="T1071.001"
MODULE_DESCRIPTION="Detect Telegram API abuse for C2 communication"
source "$(dirname "$0")/../../core/output.sh"

run_checks() {
    local findings=0

    # 1. Network connections to Telegram API from non-Telegram processes
    local tg_conns
    tg_conns=$(lsof -i -n 2>/dev/null | grep -v Telegram | grep -E "149\.154|api\.telegram" || true)
    if [ -n "$tg_conns" ]; then
        emit_finding "$MODULE_TECHNIQUE" "Non-Telegram process connecting to Telegram API" "high" \
            "$tg_conns" "Investigate and kill the process if unauthorized."
        findings=$((findings + 1))
    fi

    # 2. DNS log for api.telegram.org resolution by unexpected processes
    local dns_hits
    dns_hits=$(log show --predicate 'process != "Telegram" AND eventMessage CONTAINS "api.telegram.org"' \
        --style compact --last 1h 2>/dev/null | head -5 || true)
    if [ -n "$dns_hits" ]; then
        emit_finding "$MODULE_TECHNIQUE" "Unexpected DNS resolution of api.telegram.org" "medium" \
            "$(echo "$dns_hits" | wc -l | tr -d ' ') log entries" \
            "Review which processes are resolving Telegram API domains."
        findings=$((findings + 1))
    fi

    # 3. Telegram bot token patterns in temp/download/cache dirs (count only)
    local token_count
    token_count=$(grep -rl 'bot[0-9]\{8,\}:' /tmp ~/Downloads ~/Library/Caches 2>/dev/null | wc -l | tr -d ' ')
    if [ "$token_count" -gt 0 ] 2>/dev/null; then
        emit_finding "$MODULE_TECHNIQUE" "Telegram bot token pattern on disk" "high" \
            "${token_count} file(s) match" "Remove files and rotate exposed bot tokens."
        findings=$((findings + 1))
    fi

    # 4. Shell history curl/wget calls to api.telegram.org (count only)
    local hist_count=0
    for f in ~/.bash_history ~/.zsh_history; do
        [ -f "$f" ] && hist_count=$((hist_count + $(grep -c 'api.telegram.org' "$f" 2>/dev/null || echo 0)))
    done
    if [ "$hist_count" -gt 0 ]; then
        emit_finding "$MODULE_TECHNIQUE" "Shell history references Telegram API" "medium" \
            "${hist_count} command(s)" "Review history for unauthorized exfiltration commands."
        findings=$((findings + 1))
    fi

    [ "$findings" -eq 0 ] && emit_clean "$MODULE_TECHNIQUE" "No Telegram C2 indicators detected"
}

run_checks
