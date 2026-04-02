#!/bin/bash

MODULE_ID="T1204.002"
MODULE_TECHNIQUE="User Execution: Malicious File"
MODULE_DESCRIPTION="Detect suspicious processes, unusual execution paths, and recently modified unsigned apps using the v1 macOS scanner logic."

source "$(dirname "$0")/../../core/output.sh"

run_checks() {
    local findings=0
    local proc_list
    local suspicious_procs
    local pattern
    local matches
    local unusual_paths
    local app
    local appname
    local codesign_status
    local download_item

    suspicious_procs=(
        "stealer" "keylog" "spyware" "miner" "cryptojack"
        "MacStealer" "AtomicStealer" "Amos" "Poseidon" "Banshee"
        "RealStealer" "MetaStealer" "Pureland" "MacSync"
        "amatera" "acr_stealer" "clickfix" "installfix"
        "osascript.*password" "osascript.*keychain"
        "curl.*pastebin" "curl.*discord" "curl.*telegram"
    )

    proc_list=$(ps aux 2>/dev/null || true)

    for pattern in "${suspicious_procs[@]}"; do
        matches=$(printf "%s\n" "$proc_list" | grep -i "$pattern" | grep -v "grep" | grep -v "infostealer-check" || true)
        if [ -n "$matches" ]; then
            emit_finding "$MODULE_ID" "$MODULE_TECHNIQUE" "high" \
                "Suspicious process pattern matched: $pattern" \
                "$matches" \
                "Inspect the process, terminate it if unauthorized, and investigate the backing file."
            findings=$((findings + 1))
        fi
    done

    unusual_paths=$(ps aux 2>/dev/null | awk '{for(i=11;i<=NF;i++) printf "%s ", $i; print ""}' | grep -iE '/tmp/|/var/tmp/|/private/tmp.*[^/]$|\.hidden|/Users/.*/\.' | grep -v "grep" | grep -v "com.apple" | grep -v "infostealer-check" | grep -v "claude" | grep -v "codex" | grep -v "node_modules" | grep -v "\.nvm/" | grep -v "vite" | grep -v "bun" | grep -v "broker\.mjs" | head -20 || true)
    if [ -n "$unusual_paths" ]; then
        emit_finding "$MODULE_ID" "$MODULE_TECHNIQUE" "medium" \
            "Process running from an unusual path" \
            "$unusual_paths" \
            "Review binaries launched from temporary or hidden paths and remove anything untrusted."
        findings=$((findings + 1))
    fi

    while read -r app; do
        appname=$(basename "$app")
        codesign_status=$(codesign -v "$app" 2>&1 || true)
        if echo "$codesign_status" | grep -q "invalid\|not signed\|explicit requirement"; then
            emit_finding "$MODULE_ID" "$MODULE_TECHNIQUE" "high" \
                "Recently modified application has a signing problem" \
                "$appname: $codesign_status" \
                "Remove the application if untrusted and reinstall from a verified source."
            findings=$((findings + 1))
        else
            emit_info "$MODULE_ID" "Recent application passed codesign verification: $appname"
        fi
    done < <(find /Applications -maxdepth 1 -mtime -7 -type d 2>/dev/null)

    if [ -d "$HOME/Downloads" ]; then
        while read -r download_item; do
            emit_info "$MODULE_ID" "Recent downloaded executable or installer: $download_item"
        done < <(find "$HOME/Downloads" -maxdepth 2 -mtime -7 \( -name "*.dmg" -o -name "*.pkg" -o -name "*.app" -o -name "*.command" -o -name "*.sh" \) 2>/dev/null)
    fi

    # TODO: v1 checked signatures on recently modified apps, but it did not detect ad-hoc signed running binaries.
    emit_info "$MODULE_ID" "TODO: Ad-hoc signed binary detection was not present in v1."
    # TODO: v1's unusual-path process check did not explicitly include Downloads-based execution.
    emit_info "$MODULE_ID" "TODO: Downloads execution-path heuristics were not explicitly implemented in v1."

    if [ "$findings" -eq 0 ]; then
        emit_clean "$MODULE_ID" "$MODULE_TECHNIQUE"
    fi
}

run_checks
