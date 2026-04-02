#!/usr/bin/env bash
MODULE_ID="keychain-abuse"
MODULE_TECHNIQUE="T1555.001"
MODULE_DESCRIPTION="Detect unauthorized macOS Keychain access"
cd "$(dirname "$0")" || exit 1
CORE_DIR=../../core
source "${CORE_DIR}/output.sh"

run_checks() {
  local findings=0 c ts now hits tcc_db tcc n
  c=$(log show --predicate 'process == "security"' --last 24h --style compact 2>/dev/null | grep -ci 'find-generic-password\|find-internet-password\|dump-keychain' || true)
  if [ "${c:-0}" -gt 0 ]; then
    emit_finding "$MODULE_TECHNIQUE" "security CLI Keychain queries" "high" "count=${c}; evidence=security find-generic-password/find-internet-password/dump-keychain activity in last 24h" "Review parent processes, isolate the host, and rotate exposed secrets."
    findings=$((findings + 1))
  fi
  ts=$(stat -f %a "$HOME/Library/Keychains/login.keychain-db" 2>/dev/null || echo 0); now=$(date +%s)
  if [ "$ts" -gt 0 ] && [ $((now - ts)) -lt 86400 ]; then
    emit_finding "$MODULE_TECHNIQUE" "Recent login.keychain-db access" "medium" "count=1; evidence=login.keychain-db access time epoch ${ts}" "Validate expected Keychain usage and investigate recent credential access."
    findings=$((findings + 1))
  fi
  hits=$(lsof +D "$HOME/Library/Keychains" 2>/dev/null | awk 'NR>1{print $1"\t"$2"\t"$9}' | while IFS=$'\t' read -r cmd pid path; do comm=$(ps -p "$pid" -o comm= 2>/dev/null); codesign -dv "$comm" 2>&1 | grep -q 'Authority=Apple' || echo "$cmd pid=$pid path=$path"; done | head -n 5)
  if [ -n "$hits" ]; then
    n=$(printf '%s\n' "$hits" | wc -l | tr -d ' ')
    emit_finding "$MODULE_TECHNIQUE" "Non-Apple process touching Keychain files" "high" "count=${n}; evidence=$(printf '%s' "$hits" | tr '\n' ';')" "Terminate unexpected processes and rotate Keychain-backed credentials."
    findings=$((findings + 1))
  fi
  tcc_db="$HOME/Library/Application Support/com.apple.TCC/TCC.db"
  tcc=$(command -v sqlite3 >/dev/null && [ -f "$tcc_db" ] && sqlite3 "$tcc_db" "SELECT client||'|'||service FROM access WHERE service LIKE 'kTCCServiceSystemPolicy%';" 2>/dev/null | grep -Ei 'atomic|stealer|osascript|python|node|bash|zsh' | head -n 5 || true)
  if [ -n "$tcc" ]; then
    n=$(printf '%s\n' "$tcc" | wc -l | tr -d ' ')
    emit_finding "$MODULE_TECHNIQUE" "Suspicious TCC grants near Keychain data" "medium" "count=${n}; evidence=$(printf '%s' "$tcc" | tr '\n' ';')" "Review and revoke unnecessary TCC permissions for suspicious clients."
    findings=$((findings + 1))
  fi
  [ "$findings" -eq 0 ] && emit_clean "$MODULE_TECHNIQUE" "$MODULE_DESCRIPTION"
}

run_checks
