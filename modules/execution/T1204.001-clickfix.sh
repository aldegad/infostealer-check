#!/usr/bin/env bash
MODULE_ID="clickfix-detection"
MODULE_TECHNIQUE="T1204.001"
MODULE_DESCRIPTION="Detect ClickFix clipboard-paste social engineering attacks"
CORE_DIR=../../core
source "${CORE_DIR}/output.sh"

run_checks() {
  local findings=0 clip="" history="" f status
  [ "$(uname -s)" = "Darwin" ] && command -v pbpaste >/dev/null 2>&1 && clip=$(pbpaste 2>/dev/null || true)
  for f in "curl|bash::(curl|wget).*\|[[:space:]]*(bash|sh)" \
           "powershell-encoded::powershell(.* )?(-enc|--encodedcommand)[[:space:]]+[A-Za-z0-9+/=]{20,}" \
           "base64|exec::base64(.* )?(-d|--decode).*\|[[:space:]]*(bash|sh|zsh)"; do
    [[ "$clip" =~ ${f#*::} ]] && emit_finding "$MODULE_ID" "$MODULE_TECHNIQUE" "high" \
      "Suspicious clipboard command pattern matched: ${f%%::*}" \
      "Clear the clipboard, avoid pasting unknown commands, and investigate the lure page." && findings=$((findings+1))
  done
  history=$( { tail -n 20 "$HOME/.zsh_history" 2>/dev/null | sed 's/^: [0-9]*:[0-9]*;//'; tail -n 20 "$HOME/.bash_history" 2>/dev/null; } | tail -n 20 )
  if printf '%s\n' "$history" | awk 'length($0)>120 && /(curl|wget)/ && /\|[[:space:]]*(bash|sh)/{found=1} END{exit !found}'; then
    emit_finding "$MODULE_ID" "$MODULE_TECHNIQUE" "high" \
      "Shell history contains a long pasted one-liner with curl/wget piped to a shell." \
      "Review the command history, revoke affected credentials, and inspect spawned processes."; findings=$((findings+1))
  fi
  printf '%s\n' "$history" | grep -Eiq '([A-Za-z0-9-]+\.)?(pages|workers)\.dev|([A-Za-z0-9-]+\.)?(squarespace\.com|square\.site)' && \
    emit_finding "$MODULE_ID" "$MODULE_TECHNIQUE" "medium" \
      "Shell history references a suspicious lure-hosting domain pattern." \
      "Validate the domain, review the downloaded content, and remove untrusted installers." && findings=$((findings+1))
  while read -r f; do
    status=$(codesign --verify "$f" 2>&1 || true)
    [ -n "$status" ] && emit_finding "$MODULE_ID" "$MODULE_TECHNIQUE" "medium" \
      "Recent download failed codesign verification: $(basename "$f")" \
      "Delete the file if untrusted and obtain installers only from verified publishers." && findings=$((findings+1))
  done < <(find "$HOME/Downloads" -maxdepth 1 -type f -mtime -2 \( -name "*.dmg" -o -name "*.pkg" -o -name "*.iso" \) 2>/dev/null)
  [ "$findings" -eq 0 ] && emit_clean "$MODULE_ID" "$MODULE_TECHNIQUE"
}

run_checks
