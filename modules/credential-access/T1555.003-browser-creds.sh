#!/bin/bash

MODULE_ID="T1555.003"
MODULE_TECHNIQUE="Credentials from Web Browsers"
MODULE_DESCRIPTION="Detect non-browser access to browser credential and cookie stores using the v1 macOS scanner's lsof- and mtime-based checks."

source "$(dirname "$0")/../../core/output.sh"

emit_store_mtime() {
    local browser="$1"
    local label="$2"
    local file_path="$3"
    local modified_at

    if [ -f "$file_path" ]; then
        modified_at=$(stat -f "%Sm" -t "%Y-%m-%d %H:%M" "$file_path" 2>/dev/null || echo "unknown")
        emit_info "$MODULE_ID" "$browser $label last modified: $modified_at ($file_path)"
    fi
}

check_store_access() {
    local browser="$1"
    local allowed_process_regex="$2"
    shift 2

    local existing_files=()
    local lsof_output
    local suspicious_access

    while [ $# -gt 0 ]; do
        if [ -f "$1" ]; then
            existing_files+=("$1")
        fi
        shift
    done

    if [ ${#existing_files[@]} -eq 0 ]; then
        return 1
    fi

    lsof_output=$(lsof "${existing_files[@]}" 2>/dev/null | grep -v "^COMMAND" || true)
    if [ -z "$lsof_output" ]; then
        return 1
    fi

    suspicious_access=$(printf "%s\n" "$lsof_output" | grep -viE "$allowed_process_regex" || true)
    if [ -n "$suspicious_access" ]; then
        emit_finding "$MODULE_ID" "$MODULE_TECHNIQUE" "high" \
            "Non-browser process accessing $browser credential store" \
            "$suspicious_access" \
            "Kill the unexpected process, rotate saved browser credentials, and revoke active sessions."
        return 0
    fi

    return 1
}

run_checks() {
    local findings=0
    local chrome_profile
    local edge_profile
    local brave_profile
    local arc_profile
    local firefox_root
    local firefox_profile

    chrome_profile="$HOME/Library/Application Support/Google/Chrome/Default"
    edge_profile="$HOME/Library/Application Support/Microsoft Edge/Default"
    brave_profile="$HOME/Library/Application Support/BraveSoftware/Brave-Browser/Default"
    arc_profile="$HOME/Library/Application Support/Arc/User Data/Default"
    firefox_root="$HOME/Library/Application Support/Firefox/Profiles"

    if [ -d "$chrome_profile" ]; then
        emit_store_mtime "Chrome" "Login Data" "$chrome_profile/Login Data"
        emit_store_mtime "Chrome" "Cookies" "$chrome_profile/Cookies"
        emit_store_mtime "Chrome" "Web Data" "$chrome_profile/Web Data"
        if check_store_access "Chrome" "Google Chrome|^Google " \
            "$chrome_profile/Login Data" \
            "$chrome_profile/Cookies" \
            "$chrome_profile/Web Data"; then
            findings=$((findings + 1))
        fi
    else
        emit_info "$MODULE_ID" "Chrome profile not found: $chrome_profile"
    fi

    if [ -d "$edge_profile" ]; then
        emit_store_mtime "Edge" "Login Data" "$edge_profile/Login Data"
        emit_store_mtime "Edge" "Cookies" "$edge_profile/Cookies"
        emit_store_mtime "Edge" "Web Data" "$edge_profile/Web Data"
        if check_store_access "Edge" "Microsoft Edge|^Microsoft " \
            "$edge_profile/Login Data" \
            "$edge_profile/Cookies" \
            "$edge_profile/Web Data"; then
            findings=$((findings + 1))
        fi
    else
        # TODO: v1 only implemented Chrome-specific browser store coverage.
        emit_info "$MODULE_ID" "TODO: Edge path coverage added from the v1 Chrome pattern; validate profile variants beyond Default."
    fi

    if [ -d "$brave_profile" ]; then
        emit_store_mtime "Brave" "Login Data" "$brave_profile/Login Data"
        emit_store_mtime "Brave" "Cookies" "$brave_profile/Cookies"
        emit_store_mtime "Brave" "Web Data" "$brave_profile/Web Data"
        if check_store_access "Brave" "Brave Browser|^Brave " \
            "$brave_profile/Login Data" \
            "$brave_profile/Cookies" \
            "$brave_profile/Web Data"; then
            findings=$((findings + 1))
        fi
    else
        # TODO: v1 did not include Brave-specific paths.
        emit_info "$MODULE_ID" "TODO: Brave profile not found or not covered in v1."
    fi

    if [ -d "$arc_profile" ]; then
        emit_store_mtime "Arc" "Login Data" "$arc_profile/Login Data"
        emit_store_mtime "Arc" "Cookies" "$arc_profile/Cookies"
        emit_store_mtime "Arc" "Web Data" "$arc_profile/Web Data"
        if check_store_access "Arc" "Arc|^Arc " \
            "$arc_profile/Login Data" \
            "$arc_profile/Cookies" \
            "$arc_profile/Web Data"; then
            findings=$((findings + 1))
        fi
    else
        # TODO: v1 did not include Arc-specific paths.
        emit_info "$MODULE_ID" "TODO: Arc profile not found or not covered in v1."
    fi

    if [ -d "$firefox_root" ]; then
        while IFS= read -r firefox_profile; do
            emit_store_mtime "Firefox" "logins.json" "$firefox_profile/logins.json"
            emit_store_mtime "Firefox" "cookies.sqlite" "$firefox_profile/cookies.sqlite"
            if check_store_access "Firefox" "firefox" \
                "$firefox_profile/logins.json" \
                "$firefox_profile/cookies.sqlite"; then
                findings=$((findings + 1))
            fi
        done < <(find "$firefox_root" -maxdepth 1 -type d \( -name "*.default" -o -name "*.default-release" -o -name "*.default-release-*" -o -name "*.default-esr" \) 2>/dev/null)
        # TODO: v1 had no Firefox-specific Web Data equivalent; extend with browser-native artifacts if needed.
    else
        # TODO: v1 only checked Chrome profile files and did not include Firefox.
        emit_info "$MODULE_ID" "TODO: Firefox profile root not found: $firefox_root"
    fi

    # TODO: v1 did not include Safari credential-store access logic. Safari passwords are Keychain-backed and need separate handling.
    emit_info "$MODULE_ID" "TODO: Safari credential DB access detection is not present in v1 and remains unimplemented here."

    if [ "$findings" -eq 0 ]; then
        emit_clean "$MODULE_ID" "$MODULE_TECHNIQUE"
    fi
}

run_checks
