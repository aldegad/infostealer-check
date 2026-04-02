#!/usr/bin/env bash
MODULE_ID="telegram-c2"
MODULE_TECHNIQUE="T1071.001"
MODULE_DESCRIPTION="Detect Telegram API abuse for C2 communication"
source "$(dirname "$0")/../../core/output.sh"

run_checks() {
    local findings=0
    local lsof_numeric
    local lsof_host
    local tg_numeric_hits
    local tg_host_hits
    local dns_hits
    local token_hits
    local history_hits
    local path
    local scan_roots="${INFOSTEALER_SCAN_PATHS:-/tmp:$HOME/Downloads:$HOME/Library/Caches}"
    local root_list=()

    lsof_numeric=$(lsof -i -nP 2>/dev/null | grep ESTABLISHED || true)
    lsof_host=$(lsof -i -P 2>/dev/null | grep ESTABLISHED || true)

    tg_numeric_hits=$(printf "%s\n" "$lsof_numeric" | grep -viE 'Telegram($| )' | grep -E '149\.154\.|91\.108\.' || true)
    tg_host_hits=$(printf "%s\n" "$lsof_host" | grep -viE 'Telegram($| )' | grep -iE 'api\.telegram\.org|telegram\.me|t\.me' || true)
    if [ -n "$tg_numeric_hits$tg_host_hits" ]; then
        emit_finding "$MODULE_TECHNIQUE" "Non-Telegram process connecting to Telegram infrastructure" "high" \
            "$(printf "%s\n%s\n" "$tg_numeric_hits" "$tg_host_hits" | sed '/^[[:space:]]*$/d' | sort -u)" \
            "Investigate and kill the process if unauthorized."
        findings=$((findings + 1))
    fi

    dns_hits=$(log show --predicate 'eventMessage CONTAINS[c] "telegram"' --style compact --last 1h 2>/dev/null | head -10 || true)
    if [ -n "$dns_hits" ]; then
        emit_finding "$MODULE_TECHNIQUE" "Unexpected Telegram DNS or log activity" "medium" \
            "$dns_hits" \
            "Review which processes are resolving Telegram domains."
        findings=$((findings + 1))
    fi

    token_hits=""
    IFS=':' read -r -a root_list <<< "$scan_roots"
    for path in "${root_list[@]}"; do
        [ -d "$path" ] || continue
        token_hits+=$(grep -RilE 'api\.telegram\.org/bot[0-9]{8,}:|bot[0-9]{8,}:' "$path" 2>/dev/null | head -10 || true)
        token_hits+=$'\n'
    done
    token_hits=$(printf "%s" "$token_hits" | sed '/^[[:space:]]*$/d')
    if [ -n "$token_hits" ]; then
        emit_finding "$MODULE_TECHNIQUE" "Telegram bot token pattern on disk" "high" \
            "$token_hits" \
            "Remove files and rotate exposed bot tokens."
        findings=$((findings + 1))
    fi

    history_hits=""
    for path in "$HOME/.bash_history" "$HOME/.zsh_history"; do
        [ -f "$path" ] || continue
        history_hits+=$(grep -iE 'api\.telegram\.org|telegram\.me|t\.me' "$path" 2>/dev/null | head -5 || true)
        history_hits+=$'\n'
    done
    history_hits=$(printf "%s" "$history_hits" | sed '/^[[:space:]]*$/d')
    if [ -n "$history_hits" ]; then
        emit_finding "$MODULE_TECHNIQUE" "Shell history references Telegram API" "medium" \
            "$history_hits" \
            "Review history for unauthorized exfiltration commands."
        findings=$((findings + 1))
    fi

    [ "$findings" -eq 0 ] && emit_clean "$MODULE_TECHNIQUE" "No Telegram C2 indicators detected"
}

run_checks
