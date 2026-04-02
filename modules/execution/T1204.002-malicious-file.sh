#!/bin/bash

MODULE_ID="T1204.002"
MODULE_TECHNIQUE="User Execution: Malicious File"
MODULE_DESCRIPTION="Detect suspicious processes, unusual execution paths, and recently downloaded or installed untrusted apps."

source "$(dirname "$0")/../../core/output.sh"

is_lure_name() {
    local item_name
    item_name=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
    [[ "$item_name" =~ (claude([ -]?code)?|anthropic|cursor|chatgpt|openai|installfix|update) ]]
}

assess_recent_item() {
    local item_path="$1"
    local extension="${item_path##*.}"
    local assessment=""

    if command -v spctl >/dev/null 2>&1; then
        assessment=$(spctl -a -vv -t open "$item_path" 2>&1 || true)
        if printf '%s\n' "$assessment" | grep -qiE 'rejected|not notarized|no usable signature|source=no usable signature|unidentified developer'; then
            printf '%s\n' "$assessment"
            return 0
        fi
    fi

    if [[ -d "$item_path" && "$item_path" == *.app ]] && command -v codesign >/dev/null 2>&1; then
        assessment=$(codesign --verify --deep --strict "$item_path" 2>&1 || true)
        if [ -n "$assessment" ]; then
            printf '%s\n' "$assessment"
            return 0
        fi
    fi

    if [[ "$extension" == "pkg" ]] && command -v pkgutil >/dev/null 2>&1; then
        assessment=$(pkgutil --check-signature "$item_path" 2>&1 || true)
        if printf '%s\n' "$assessment" | grep -qiE 'no signature|not signed|signed by a certificate that is not trusted|could not'; then
            printf '%s\n' "$assessment"
            return 0
        fi
    fi

    return 1
}

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
    local item_path
    local item_name
    local trust_failure
    local app_dir

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

    unusual_paths=$(printf "%s\n" "$proc_list" | awk '{for(i=11;i<=NF;i++) printf "%s ", $i; print ""}' \
        | grep -iE '/tmp/|/var/tmp/|/private/tmp[^ ]*|\.hidden|/Users/.*/Downloads/|/Volumes/[^ ]+|/Users/.*/Applications/[^ ]+' \
        | grep -v "grep" | grep -v "com.apple" | grep -v "infostealer-check" | grep -v "codex" | grep -v "node_modules" | grep -v "\.nvm/" | grep -v "vite" | grep -v "bun" | grep -v "broker\.mjs" \
        | head -20 || true)
    if [ -n "$unusual_paths" ]; then
        emit_finding "$MODULE_ID" "$MODULE_TECHNIQUE" "medium" \
            "Process running from an unusual or download-backed path" \
            "$unusual_paths" \
            "Review binaries launched from temporary, mounted, or download paths and remove anything untrusted."
        findings=$((findings + 1))
    fi

    for app_dir in /Applications "$HOME/Applications"; do
        [ -d "$app_dir" ] || continue
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
        done < <(find "$app_dir" -maxdepth 1 -mtime -7 -type d -name "*.app" 2>/dev/null)
    done

    if [ -d "$HOME/Downloads" ]; then
        while read -r item_path; do
            item_name=$(basename "$item_path")
            emit_info "$MODULE_ID" "Recent downloaded executable or installer: $item_path"

            trust_failure=$(assess_recent_item "$item_path" || true)
            if [ -n "$trust_failure" ]; then
                if is_lure_name "$item_name"; then
                    emit_finding "$MODULE_ID" "$MODULE_TECHNIQUE" "high" \
                        "Recent download matches a common lure name and failed trust assessment" \
                        "$item_name: $trust_failure" \
                        "Delete the installer, review how it was downloaded, and rotate exposed credentials if it executed."
                else
                    emit_finding "$MODULE_ID" "$MODULE_TECHNIQUE" "medium" \
                        "Recent downloaded installer failed trust assessment" \
                        "$item_name: $trust_failure" \
                        "Delete the file if untrusted and obtain installers only from verified publishers."
                fi
                findings=$((findings + 1))
            fi
        done < <(find "$HOME/Downloads" -maxdepth 2 -mtime -7 \( -name "*.dmg" -o -name "*.pkg" -o -name "*.app" -o -name "*.command" -o -name "*.sh" -o -name "*.zip" -o -name "*.iso" \) 2>/dev/null)
    fi

    if [ "$findings" -eq 0 ]; then
        emit_clean "$MODULE_ID" "$MODULE_TECHNIQUE"
    fi
}

run_checks
