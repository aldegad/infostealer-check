#!/usr/bin/env bash

MODULE_ID="applescript-abuse"
MODULE_TECHNIQUE="T1059.002"
MODULE_DESCRIPTION="Detect AppleScript-based password prompt social engineering"
CORE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../core" && pwd)"
source "${CORE_DIR}/output.sh"

run_checks() {
    local findings=0 matches count recent_files tcc_db tcc_hits
    matches=$(ps aux | grep -i 'osascript.*password\|osascript.*keychain\|osascript.*dialog' | grep -vi 'grep' || true)
    if [ -n "$matches" ]; then
        emit_finding "$MODULE_ID" "Suspicious osascript process" "high" "$matches" ""
        findings=$((findings + 1))
    fi
    count=$(log show --predicate 'process == "osascript"' --last 24h --style compact 2>/dev/null | grep -ic 'password\|dialog\|keychain' || true)
    if [ "${count:-0}" -gt 0 ]; then
        emit_finding "$MODULE_ID" "Recent osascript log hits: $count" "medium" "Unified log matched password/dialog/keychain terms in the last 24h." ""
        findings=$((findings + 1))
    fi
    recent_files=$(find "$HOME/Downloads" /tmp "$HOME/Desktop" -type f \( -name '*.scpt' -o -name '*.applescript' \) -mtime -7 -print 2>/dev/null || true)
    if [ -n "$recent_files" ]; then
        emit_finding "$MODULE_ID" "Recent AppleScript files found" "medium" "$recent_files" ""
        findings=$((findings + 1))
    fi
    tcc_db="$HOME/Library/Application Support/com.apple.TCC/TCC.db"
    if [ -f "$tcc_db" ]; then
        tcc_hits=$(sqlite3 "$tcc_db" "SELECT client FROM access WHERE service='kTCCServiceAccessibility' AND client LIKE '%osascript%' AND auth_value=2;" 2>/dev/null || true)
        [ -n "$tcc_hits" ] || tcc_hits=$(sqlite3 "$tcc_db" "SELECT client FROM access WHERE service='kTCCServiceAccessibility' AND client LIKE '%osascript%' AND allowed=1;" 2>/dev/null || true)
        if [ -n "$tcc_hits" ]; then
            emit_finding "$MODULE_ID" "osascript has Accessibility permission" "high" "$tcc_hits" ""
            findings=$((findings + 1))
        fi
    fi
    [ "$findings" -eq 0 ] && emit_clean "$MODULE_ID" "No AppleScript abuse indicators detected"
}

run_checks
