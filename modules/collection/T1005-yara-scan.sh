#!/usr/bin/env bash
MODULE_ID="T1005-yara"
MODULE_TECHNIQUE="T1005"
MODULE_DESCRIPTION="YARA rule-based file scanning for known infostealer artifacts"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/../../core/output.sh"

run_checks() {
    if ! command -v yara &>/dev/null; then
        emit_info "$MODULE_TECHNIQUE" "YARA not installed — skipping (brew install yara)"
        return 0
    fi

    local RULES_FILE="${SCRIPT_DIR}/../../signatures/yara/infostealer-families.yar"
    if [[ ! -f "$RULES_FILE" ]]; then
        emit_info "$MODULE_TECHNIQUE" "YARA rules file not found: $RULES_FILE"
        return 0
    fi

    local scan_dirs=(
        "$HOME/Downloads/"
        "/tmp/"
        "$HOME/Library/Caches/"
        "$HOME/Library/Application Support/"
        "$HOME/Desktop/"
    )

    local total_matches=0
    local total_dirs=0

    for scan_dir in "${scan_dirs[@]}"; do
        [[ -d "$scan_dir" ]] || continue
        ((total_dirs++))

        local output
        output=$(timeout 10 yara -r -s -w "$RULES_FILE" "$scan_dir" 2>/dev/null) || continue
        [[ -z "$output" ]] && continue

        while IFS=' ' read -r rule_name file_path; do
            [[ -z "$rule_name" || "$rule_name" == 0x* ]] && continue
            ((total_matches++))
            emit_finding "$MODULE_TECHNIQUE" "YARA match: $rule_name" "critical" \
                "File: $file_path matched rule $rule_name" \
                "Quarantine file and investigate with antivirus"
        done <<< "$output"
    done

    if [[ $total_matches -eq 0 ]]; then
        emit_clean "$MODULE_TECHNIQUE" "No YARA matches found"
    fi

    emit_info "$MODULE_TECHNIQUE" "Scanned $total_dirs directories, $total_matches match(es) found"
}

run_checks
