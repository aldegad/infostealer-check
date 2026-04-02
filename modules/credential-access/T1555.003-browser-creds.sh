#!/bin/bash

MODULE_ID="T1555.003"
MODULE_TECHNIQUE="Credentials from Web Browsers"
MODULE_DESCRIPTION="Detect non-browser access to browser credential, cookie, and session stores."

source "$(dirname "$0")/../../core/output.sh"

emit_store_mtime() {
    local browser="$1"
    local label="$2"
    local file_path="$3"
    local modified_at

    if [ -f "$file_path" ]; then
        modified_at=$(stat -f "%Sm" -t "%Y-%m-%d %H:%M" "$file_path" 2>/dev/null || stat -c "%y" "$file_path" 2>/dev/null || echo "unknown")
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
            "Non-browser process accessing $browser credential or session store" \
            "$suspicious_access" \
            "Kill the unexpected process, rotate saved browser credentials, and revoke active sessions."
        return 0
    fi

    return 1
}

scan_chromium_profiles() {
    local browser="$1"
    local root="$2"
    local allowed_process_regex="$3"
    local findings=0
    local profile
    local found_profile=0

    if [ ! -d "$root" ]; then
        emit_info "$MODULE_ID" "$browser profile root not found: $root"
        return 1
    fi

    while IFS= read -r profile; do
        found_profile=1
        emit_store_mtime "$browser" "Login Data" "$profile/Login Data"
        emit_store_mtime "$browser" "Cookies" "$profile/Cookies"
        emit_store_mtime "$browser" "Web Data" "$profile/Web Data"
        emit_store_mtime "$browser" "Session Storage" "$profile/Session Storage"
        if check_store_access "$browser" "$allowed_process_regex" \
            "$profile/Login Data" \
            "$profile/Cookies" \
            "$profile/Web Data" \
            "$profile/Session Storage"; then
            findings=1
        fi
    done < <(
        find "$root" -mindepth 1 -maxdepth 1 -type d \
            \( -name "Default" -o -name "Profile *" -o -name "Guest Profile" -o -name "System Profile" \) \
            2>/dev/null | sort
    )

    if [ "$found_profile" -eq 0 ]; then
        emit_info "$MODULE_ID" "$browser user profiles not found under $root"
    fi

    [ "$findings" -eq 1 ]
}

scan_firefox_profiles() {
    local root="$1"
    local findings=0
    local profile
    local found_profile=0

    if [ ! -d "$root" ]; then
        emit_info "$MODULE_ID" "Firefox profile root not found: $root"
        return 1
    fi

    while IFS= read -r profile; do
        found_profile=1
        emit_store_mtime "Firefox" "logins.json" "$profile/logins.json"
        emit_store_mtime "Firefox" "cookies.sqlite" "$profile/cookies.sqlite"
        emit_store_mtime "Firefox" "key4.db" "$profile/key4.db"
        emit_store_mtime "Firefox" "sessionstore.jsonlz4" "$profile/sessionstore.jsonlz4"
        emit_store_mtime "Firefox" "recovery.jsonlz4" "$profile/sessionstore-backups/recovery.jsonlz4"
        if check_store_access "Firefox" "firefox" \
            "$profile/logins.json" \
            "$profile/cookies.sqlite" \
            "$profile/key4.db" \
            "$profile/sessionstore.jsonlz4" \
            "$profile/sessionstore-backups/recovery.jsonlz4"; then
            findings=1
        fi
    done < <(
        find "$root" -maxdepth 1 -type d \
            \( -name "*.default" -o -name "*.default-release" -o -name "*.default-release-*" -o -name "*.default-esr" \) \
            2>/dev/null | sort
    )

    if [ "$found_profile" -eq 0 ]; then
        emit_info "$MODULE_ID" "Firefox profiles not found under $root"
    fi

    [ "$findings" -eq 1 ]
}

scan_safari_stores() {
    local findings=0
    local allowed_process_regex="Safari|^Safari |WebKit|com.apple.WebKit.Networking"
    local safari_files=(
        "$HOME/Library/Cookies/Cookies.binarycookies"
        "$HOME/Library/Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies"
        "$HOME/Library/Safari/History.db"
        "$HOME/Library/Safari/LastSession.plist"
    )
    local file_path

    for file_path in "${safari_files[@]}"; do
        case "$file_path" in
            *Cookies.binarycookies) emit_store_mtime "Safari" "Cookies.binarycookies" "$file_path" ;;
            *History.db) emit_store_mtime "Safari" "History.db" "$file_path" ;;
            *LastSession.plist) emit_store_mtime "Safari" "LastSession.plist" "$file_path" ;;
        esac
    done

    if check_store_access "Safari" "$allowed_process_regex" "${safari_files[@]}"; then
        findings=1
    fi

    [ "$findings" -eq 1 ]
}

run_checks() {
    local findings=0

    if scan_chromium_profiles "Chrome" "$HOME/Library/Application Support/Google/Chrome" \
        "Google Chrome|Google Chrome Helper|^Google |Google Chrome.app"; then
        findings=$((findings + 1))
    fi

    if scan_chromium_profiles "Edge" "$HOME/Library/Application Support/Microsoft Edge" \
        "Microsoft Edge|Microsoft Edge Helper|^Microsoft |Microsoft Edge.app"; then
        findings=$((findings + 1))
    fi

    if scan_chromium_profiles "Brave" "$HOME/Library/Application Support/BraveSoftware/Brave-Browser" \
        "Brave Browser|Brave Browser Helper|^Brave |Brave Browser.app"; then
        findings=$((findings + 1))
    fi

    if scan_chromium_profiles "Arc" "$HOME/Library/Application Support/Arc/User Data" \
        "Arc|Arc Helper|^Arc "; then
        findings=$((findings + 1))
    fi

    if scan_firefox_profiles "$HOME/Library/Application Support/Firefox/Profiles"; then
        findings=$((findings + 1))
    fi

    if scan_safari_stores; then
        findings=$((findings + 1))
    fi

    if [ "$findings" -eq 0 ]; then
        emit_clean "$MODULE_ID" "$MODULE_TECHNIQUE"
    fi
}

run_checks
