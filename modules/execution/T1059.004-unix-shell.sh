#!/usr/bin/env bash

MODULE_ID="T1059.004"
MODULE_TECHNIQUE="Command and Scripting Interpreter: Unix Shell"
MODULE_DESCRIPTION="Parse bash and zsh history for suspicious download-and-execute, decoded execution, AppleScript abuse, and credential-access commands without exposing full command history."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../../core/output.sh"

HISTORY_SCAN_LINES="${HISTORY_SCAN_LINES:-5000}"

normalize_history_line() {
    local line="$1"
    local zsh_ts_re='^: [0-9]+:[0-9]+;(.*)$'

    if [[ "$line" =~ $zsh_ts_re ]]; then
        printf "%s\n" "${BASH_REMATCH[1]}"
        return 0
    fi

    printf "%s\n" "$line"
}

sanitize_command() {
    local command_text="$1"
    local sanitized

    sanitized=$(printf "%s" "$command_text" | sed -E \
        -e 's#https?://[^[:space:]]+#<url>#g' \
        -e 's#ftp://[^[:space:]]+#<url>#g' \
        -e 's/"[^"]+"/"<redacted>"/g' \
        -e "s/'[^']+'/'<redacted>'/g" \
        -e 's/[A-Za-z0-9_+=\/.-]{24,}/<token>/g')

    if [ "${#sanitized}" -gt 180 ]; then
        sanitized="${sanitized:0:180}..."
    fi

    printf "%s\n" "$sanitized"
}

register_match() {
    local category="$1"
    local history_file="$2"
    local command_text="$3"
    local sanitized

    sanitized=$(sanitize_command "$command_text")

    case "$category" in
        remote_shell)
            remote_shell_count=$((remote_shell_count + 1))
            if [ -z "$remote_shell_sample" ]; then
                remote_shell_sample="$sanitized"
                remote_shell_file="$history_file"
            fi
            ;;
        base64_exec)
            base64_exec_count=$((base64_exec_count + 1))
            if [ -z "$base64_exec_sample" ]; then
                base64_exec_sample="$sanitized"
                base64_exec_file="$history_file"
            fi
            ;;
        osascript)
            osascript_count=$((osascript_count + 1))
            if [ -z "$osascript_sample" ]; then
                osascript_sample="$sanitized"
                osascript_file="$history_file"
            fi
            ;;
        keychain_cli)
            keychain_cli_count=$((keychain_cli_count + 1))
            if [ -z "$keychain_cli_sample" ]; then
                keychain_cli_sample="$sanitized"
                keychain_cli_file="$history_file"
            fi
            ;;
    esac
}

scan_history_file() {
    local history_file="$1"
    local line
    local command_text

    [ -f "$history_file" ] || return 0

    while IFS= read -r line; do
        command_text=$(normalize_history_line "$line")
        [ -n "$command_text" ] || continue

        if printf "%s\n" "$command_text" | grep -Eiq '(^|[;&[:space:]])(curl|wget)\b.*\|\s*((/usr/bin/|/bin/)?bash|(/usr/bin/|/bin/)?sh|zsh)\b'; then
            register_match "remote_shell" "$history_file" "$command_text"
        fi

        if printf "%s\n" "$command_text" | grep -Eiq 'base64\b.*(-d|--decode).*\|\s*((/usr/bin/|/bin/)?bash|(/usr/bin/|/bin/)?sh|zsh)\b'; then
            register_match "base64_exec" "$history_file" "$command_text"
        fi

        if printf "%s\n" "$command_text" | grep -Eiq '(^|[;&[:space:]])osascript\b'; then
            register_match "osascript" "$history_file" "$command_text"
        fi

        if printf "%s\n" "$command_text" | grep -Eiq '(^|[;&[:space:]])security\b.*\bfind-generic-password\b'; then
            register_match "keychain_cli" "$history_file" "$command_text"
        fi
    done < <(tail -n "$HISTORY_SCAN_LINES" "$history_file" 2>/dev/null)
}

run_checks() {
    local findings=0

    remote_shell_count=0
    remote_shell_sample=""
    remote_shell_file=""
    base64_exec_count=0
    base64_exec_sample=""
    base64_exec_file=""
    osascript_count=0
    osascript_sample=""
    osascript_file=""
    keychain_cli_count=0
    keychain_cli_sample=""
    keychain_cli_file=""

    scan_history_file "$HOME/.zsh_history"
    scan_history_file "$HOME/.bash_history"

    if [ "$remote_shell_count" -gt 0 ]; then
        emit_finding "$MODULE_ID" "$MODULE_TECHNIQUE" "high" \
            "Shell history contains curl or wget piped directly to a shell" \
            "$remote_shell_count redacted match(es); first seen in $remote_shell_file: $remote_shell_sample" \
            "Review the execution chain, validate the downloaded content, and remove any unauthorized persistence or payloads."
        findings=$((findings + 1))
    fi

    if [ "$base64_exec_count" -gt 0 ]; then
        emit_finding "$MODULE_ID" "$MODULE_TECHNIQUE" "high" \
            "Shell history contains base64-decoded content piped to execution" \
            "$base64_exec_count redacted match(es); first seen in $base64_exec_file: $base64_exec_sample" \
            "Investigate the decoded payload, revoke any exposed secrets, and confirm no secondary payloads were launched."
        findings=$((findings + 1))
    fi

    if [ "$osascript_count" -gt 0 ]; then
        emit_finding "$MODULE_ID" "$MODULE_TECHNIQUE" "medium" \
            "Shell history contains osascript execution" \
            "$osascript_count redacted match(es); first seen in $osascript_file: $osascript_sample" \
            "Confirm the AppleScript usage was expected and review for fake password prompts or automation abuse."
        findings=$((findings + 1))
    fi

    if [ "$keychain_cli_count" -gt 0 ]; then
        emit_finding "$MODULE_ID" "$MODULE_TECHNIQUE" "high" \
            "Shell history contains security find-generic-password usage" \
            "$keychain_cli_count redacted match(es); first seen in $keychain_cli_file: $keychain_cli_sample" \
            "Verify the command origin, audit Keychain access, and rotate credentials if the usage was not authorized."
        findings=$((findings + 1))
    fi

    if [ "$findings" -eq 0 ]; then
        emit_clean "$MODULE_ID" "$MODULE_TECHNIQUE"
    fi
}

run_checks
