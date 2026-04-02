#!/usr/bin/env bash
MODULE_ID="T1055"
MODULE_TECHNIQUE="T1055"
MODULE_DESCRIPTION="Fileless execution indicators — memory-only payloads and process injection"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/../../core/output.sh"

run_checks() {
  # 1. Endpoint Security Framework status
  if command -v eslogger &>/dev/null; then
    emit_clean "$MODULE_ID" "esf_available" "Endpoint Security Framework (eslogger) is available"
  else
    emit_finding "$MODULE_ID" "esf_missing" "medium" "eslogger not found — ESF may be unavailable"
  fi

  # 2. In-memory execution via /dev/fd
  local fd_hits
  fd_hits=$(lsof +D /dev/fd 2>/dev/null | grep -i 'deleted\|memfd' || true)
  if [[ -n "$fd_hits" ]]; then
    emit_finding "$MODULE_ID" "memfd_exec" "high" "Suspicious /dev/fd activity: $(echo "$fd_hits" | head -3)"
  else
    emit_clean "$MODULE_ID" "memfd_exec" "No suspicious /dev/fd file descriptor usage detected"
  fi

  # 3. Suspicious dylib injection
  local inject_hits dyld_hits
  inject_hits=$(launchctl print system 2>/dev/null | grep -i inject || true)
  dyld_hits=$(ps -eww -o pid,command 2>/dev/null | grep DYLD_INSERT | grep -v grep || true)
  if [[ -n "$inject_hits" || -n "$dyld_hits" ]]; then
    emit_finding "$MODULE_ID" "dylib_injection" "critical" "Dylib injection indicators: ${inject_hits}${dyld_hits}"
  else
    emit_clean "$MODULE_ID" "dylib_injection" "No DYLD_INSERT_LIBRARIES or injection flags detected"
  fi

  # 4. Process with no backing binary
  local orphan_procs=""
  while IFS= read -r pid; do
    [[ -z "$pid" ]] && continue
    local comm
    comm=$(ps -p "$pid" -o comm= 2>/dev/null) || continue
    [[ -z "$comm" ]] && continue
    if [[ "$comm" == /* ]] && [[ ! -f "$comm" ]]; then
      orphan_procs+="PID $pid ($comm) "
    fi
  done < <(ps -eo pid= 2>/dev/null | head -200)
  if [[ -n "$orphan_procs" ]]; then
    emit_finding "$MODULE_ID" "no_backing_binary" "high" "Processes without backing binary: $orphan_procs"
  else
    emit_clean "$MODULE_ID" "no_backing_binary" "All sampled processes have valid backing binaries"
  fi

  # 5. Recent core dumps / crash reports mentioning injection
  local crash_hits=""
  for d in /cores/ "$HOME/Library/Logs/DiagnosticReports/"; do
    [[ -d "$d" ]] || continue
    crash_hits+=$(find "$d" -type f -mtime -7 -exec grep -li 'inject\|DYLD_INSERT\|dlopen\|mmap.*PROT_EXEC' {} + 2>/dev/null || true)
  done
  if [[ -n "$crash_hits" ]]; then
    emit_finding "$MODULE_ID" "injection_crashes" "medium" "Crash reports with injection terms: $crash_hits"
  else
    emit_clean "$MODULE_ID" "injection_crashes" "No recent crash reports mentioning injection patterns"
  fi
}

run_checks
