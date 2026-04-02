#!/usr/bin/env bash
MODULE_ID="T1070.006"
MODULE_TECHNIQUE="T1070.006"
MODULE_DESCRIPTION="Timestomping detection — birth/modify/access time anomalies"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/../../core/output.sh"

run_checks() {
  local findings=0 f b m a remed
  remed="Inspect provenance, compare with backups/FSEvents, and on Windows review NTFS \$STANDARD_INFORMATION vs \$FILE_NAME plus MFT/USN Journal deltas."
  hit() { emit_finding "$MODULE_TECHNIQUE" "$1" "medium" "$2" "$remed"; findings=$((findings+1)); }
  recent_files() { find "$HOME/Downloads" /tmp "$HOME/Library/Application Support" -mtime -7 -maxdepth 2 -type f 2>/dev/null; }

  # Windows note: NTFS timestomping often leaves $STANDARD_INFORMATION and $FILE_NAME mismatches.
  while IFS= read -r f; do
    read -r b m a <<<"$(stat -f '%B %m %a' "$f" 2>/dev/null)"
    [ -n "${b:-}" ] || continue
    [ "$b" -gt "$m" ] && hit "Birth newer than modify time" "path=$f birth=$b modify=$m"
    [ "$a" -lt "$b" ] && hit "Access older than birth time" "path=$f access=$a birth=$b"
    [ -f "$f" ] && [ -x "$f" ] && ! xattr -l "$f" 2>/dev/null | grep -qi quarantine &&
      hit "Recent executable missing quarantine xattr" "path=$f birth=$b modify=$m"
  done < <(recent_files)

  while IFS= read -r line; do
    [ -n "$line" ] && hit "Cluster of identical modify timestamps" "$line"
  done < <(
    find "$HOME/Downloads" -mtime -7 -maxdepth 2 -type f -exec stat -f '%m %N' {} + 2>/dev/null | awk '
      { p=$0; sub(/^[^ ]+ /,"",p); c[$1]++; s[$1]=(s[$1]?s[$1]"; ":"")p }
      END { for (k in c) if (c[k] >= 3) print "modify=" k " count=" c[k] " files=" s[k] }
    '
  )

  [ "$findings" -eq 0 ] && emit_clean "$MODULE_TECHNIQUE" "No timestomping indicators detected"
}

run_checks
