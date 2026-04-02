#!/usr/bin/env bash

MODULE_ID="local-data-collection"
MODULE_TECHNIQUE="T1005"
MODULE_DESCRIPTION="Detect access to crypto wallets and sensitive local data"

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
cd "$SCRIPT_DIR" || exit 1
CORE_DIR=../../core
source "${CORE_DIR}/output.sh"

run_checks() {
    local findings=0 now cutoff path atime access_ts out
    now=$(date +%s)
    cutoff=$((now - 86400))

    for path in \
        "$HOME/Library/Application Support/MetaMask/" \
        "$HOME/Library/Application Support/Exodus/" \
        "$HOME/Library/Application Support/Electrum/" \
        "$HOME/Library/Application Support/Phantom/" \
        "$HOME/Library/Application Support/Coinbase Wallet/"; do
        [ -d "$path" ] || continue
        atime=$(stat -f %a "$path" 2>/dev/null || echo 0)
        if [ "$atime" -ge "$cutoff" ]; then
            access_ts=$(date -r "$atime" "+%Y-%m-%d %H:%M:%S" 2>/dev/null || echo "$atime")
            emit_finding "$MODULE_ID" "$MODULE_TECHNIQUE" "medium" "Recent access to wallet path: $path ($access_ts)" "Review recent processes and user activity for unauthorized wallet access."
            findings=$((findings + 1))
        fi
        out=$(lsof +D "$path" 2>/dev/null | awk 'NR==1 || tolower($1) !~ /(metamask|exodus|electrum|phantom|coinbase|wallet)/' | head -10)
        if [ -n "$out" ] && [ "$(printf '%s\n' "$out" | wc -l | tr -d ' ')" -gt 1 ]; then
            emit_finding "$MODULE_ID" "$MODULE_TECHNIQUE" "high" "Non-wallet process accessing wallet directory: $path"$'\n'"$out" "Inspect and terminate unauthorized processes accessing wallet data."
            findings=$((findings + 1))
        fi
    done

    for path in \
        "$HOME/Library/Application Support/discord/Local Storage/" \
        "$HOME/Library/Group Containers"/*/Telegram/ \
        "$HOME/Library/Application Support/Slack/storage/"; do
        [ -d "$path" ] || continue
        atime=$(stat -f %a "$path" 2>/dev/null || echo 0)
        if [ "$atime" -ge "$cutoff" ]; then
            access_ts=$(date -r "$atime" "+%Y-%m-%d %H:%M:%S" 2>/dev/null || echo "$atime")
            emit_finding "$MODULE_ID" "$MODULE_TECHNIQUE" "medium" "Recent access to messaging local storage: $path ($access_ts)" "Review the accessing process and validate whether the activity was expected."
            findings=$((findings + 1))
        fi
    done

    [ "$findings" -eq 0 ] && emit_clean "$MODULE_ID" "$MODULE_TECHNIQUE"
}

run_checks
