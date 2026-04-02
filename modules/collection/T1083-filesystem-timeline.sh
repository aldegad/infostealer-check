#!/usr/bin/env bash

MODULE_ID="filesystem-timeline"
MODULE_TECHNIQUE="T1083"
MODULE_DESCRIPTION="Analyze filesystem timestamps to detect suspicious activity bursts"

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
cd "$SCRIPT_DIR" || exit 1
CORE_DIR=../../core
source "${CORE_DIR}/output.sh"

run_checks() {
    local findings=0 now cutoff
    now=$(date +%s); cutoff=$((now - 86400))

    # 1. Find files modified in last 24h in suspicious locations
    local recent_files=() dir
    for dir in /tmp "$HOME/Downloads" "$HOME/Library/Caches" "$HOME/Library/Application Support"; do
        [ -d "$dir" ] || continue
        while IFS= read -r -d '' f; do recent_files+=("$f"); done \
            < <(find "$dir" -maxdepth 3 -type f -mtime -1 -print0 2>/dev/null)
    done

    # 2. Detect activity bursts: >10 files in same 5-minute window
    if [ "${#recent_files[@]}" -gt 0 ]; then
        local -A wc=(); local mtime b peak=0 pk=""
        for f in "${recent_files[@]}"; do
            mtime=$(stat -f %m "$f" 2>/dev/null) || continue
            b=$((mtime / 300)); wc[$b]=$(( ${wc[$b]:-0} + 1 ))
            [ "${wc[$b]}" -gt "$peak" ] && { peak=${wc[$b]}; pk=$b; }
        done
        if [ "$peak" -gt 10 ]; then
            local wts; wts=$(date -r $((pk * 300)) "+%Y-%m-%d %H:%M" 2>/dev/null)
            emit_finding "$MODULE_TECHNIQUE" "$MODULE_ID" "high" \
                "Activity burst: ${peak} files in 5-min window at ${wts}" \
                "Investigate processes active during this window."
            findings=$((findings + 1))
        fi
    fi

    # 3. Timestomping: birth time newer than modification time
    local stomped=0
    for f in "${recent_files[@]}"; do
        local birth modify
        birth=$(stat -f %B "$f" 2>/dev/null) || continue
        modify=$(stat -f %m "$f" 2>/dev/null) || continue
        if [ "$birth" -gt "$modify" ]; then
            emit_finding "$MODULE_TECHNIQUE" "$MODULE_ID" "high" \
                "Timestomping: birth > modify on ${f##*/}" \
                "File may have been tampered to hide true creation time."
            stomped=$((stomped + 1)); findings=$((findings + 1))
            [ "$stomped" -ge 5 ] && break
        fi
    done

    # 4. Recently created hidden files (dotfiles) in home directory
    local dotfiles=()
    while IFS= read -r -d '' f; do dotfiles+=("$f"); done \
        < <(find "$HOME" -maxdepth 1 -name ".*" -type f -mtime -1 -print0 2>/dev/null)
    if [ "${#dotfiles[@]}" -gt 0 ]; then
        local names; names=$(printf '%s\n' "${dotfiles[@]}" | xargs -I{} basename {} | head -10 | paste -sd, -)
        emit_finding "$MODULE_TECHNIQUE" "$MODULE_ID" "medium" \
            "Recent dotfiles in HOME (${#dotfiles[@]}): ${names}" \
            "Review hidden files for malicious content or persistence."
        findings=$((findings + 1))
    fi

    # 5. Clean if nothing found
    [ "$findings" -eq 0 ] && emit_clean "$MODULE_TECHNIQUE" "$MODULE_ID"
}

run_checks
