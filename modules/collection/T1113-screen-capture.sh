#!/usr/bin/env bash

MODULE_ID="screen-capture"
MODULE_TECHNIQUE="T1113"
MODULE_DESCRIPTION="Detect unauthorized screen capture activity"
cd "$(dirname "${BASH_SOURCE[0]}")" || exit 1
CORE_DIR=../../core
source "${CORE_DIR}/output.sh"

run_checks() {
    local findings=0 grants log_hits file_hits proc_hits
    grants=$(sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db "SELECT client FROM access WHERE service='kTCCServiceScreenCapture' AND auth_value>0" 2>/dev/null | grep -vE '^(com\.apple\.|/System/|/Applications/(Screenshot|QuickTime Player|Preview)\.app)' || true)
    if [ -n "$grants" ]; then
        emit_finding "$MODULE_ID" "Non-standard screen recording TCC grants" "high" "$grants" "Review and revoke unexpected TCC grants for screen capture."
        findings=$((findings + 1))
    fi
    log_hits=$(log show --last 24h --style compact --predicate 'process == "screencapture" OR eventMessage CONTAINS[c] "screencapture"' 2>/dev/null | head -20 || true)
    if [ -n "$log_hits" ]; then
        emit_finding "$MODULE_ID" "Recent screencapture CLI activity" "medium" "$log_hits" "Confirm whether screen capture commands were expected in the last 24 hours."
        findings=$((findings + 1))
    fi
    file_hits=$(find /tmp "$HOME/Library/Caches" -type f \( -iname '*.png' -o -iname '*.jpg' \) -mtime -1 2>/dev/null | head -20 || true)
    if [ -n "$file_hits" ]; then
        emit_finding "$MODULE_ID" "Recent image files in unexpected locations" "medium" "$file_hits" "Inspect cached or temporary screenshots for potential staging or OCR abuse."
        findings=$((findings + 1))
    fi
    proc_hits=$({ ps auxww 2>/dev/null; lsof -nP 2>/dev/null; } | grep -iE 'CGWindowListCreateImage|SCScreenshotManager|ScreenCaptureKit|screencapture|screenshot|capture.*screen' | head -20 || true)
    if [ -n "$proc_hits" ]; then
        emit_finding "$MODULE_ID" "Processes matching screen capture API heuristics" "medium" "$proc_hits" "Inspect the owning process for ScreenCaptureKit/CoreGraphics-based capture behavior."
        findings=$((findings + 1))
    fi
    [ "$findings" -eq 0 ] && emit_clean "$MODULE_ID" "$MODULE_TECHNIQUE"
}

run_checks
