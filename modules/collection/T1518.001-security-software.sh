#!/usr/bin/env bash

MODULE_ID="security-software-status"
MODULE_TECHNIQUE="T1518.001"
MODULE_DESCRIPTION="Check macOS security software and protection status"
cd "$(dirname "${BASH_SOURCE[0]}")" || exit 1
CORE_DIR=../../core
source "${CORE_DIR}/output.sh"

run_checks() {
    local findings=0 sip gatekeeper xprotect fv firewall mrt
    sip=$(csrutil status 2>/dev/null)
    [[ "$sip" == *"enabled"* ]] || { emit_finding "$MODULE_TECHNIQUE" "System Integrity Protection disabled" "high" "${sip:-csrutil status unavailable.}" "Re-enable SIP from Recovery Mode with csrutil enable."; findings=$((findings + 1)); }
    gatekeeper=$(spctl --status 2>/dev/null)
    [[ "$gatekeeper" == *"assessments enabled"* ]] || { emit_finding "$MODULE_TECHNIQUE" "Gatekeeper disabled" "high" "${gatekeeper:-spctl status unavailable.}" "Re-enable Gatekeeper with spctl --master-enable."; findings=$((findings + 1)); }
    xprotect=$(system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A2 XProtect | head -3)
    emit_info "$MODULE_TECHNIQUE" "XProtect Version" "${xprotect:-XProtect install history not found.}"
    fv=$(fdesetup status 2>/dev/null || echo "FileVault status unavailable.")
    emit_info "$MODULE_TECHNIQUE" "FileVault Status" "$fv"
    firewall=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null)
    [[ "$firewall" == *"enabled"* ]] || { emit_finding "$MODULE_TECHNIQUE" "Firewall disabled" "medium" "${firewall:-Firewall status unavailable.}" "Enable the macOS application firewall in System Settings."; findings=$((findings + 1)); }
    mrt=$(log show --last 30d --style compact --predicate 'process == "MRT" OR eventMessage CONTAINS[c] "Malware Removal Tool"' 2>/dev/null | head -1)
    if [ -n "$mrt" ]; then
        emit_info "$MODULE_TECHNIQUE" "MRT Activity" "$mrt"
    else
        emit_finding "$MODULE_TECHNIQUE" "MRT did not run recently" "low" "No Malware Removal Tool log entries found in the last 30 days." "Confirm MRT/XProtect updates are working and review software update policy."
        findings=$((findings + 1))
    fi
    [ "$findings" -eq 0 ] && emit_clean "$MODULE_TECHNIQUE" "All core macOS protections are enabled"
}

run_checks
