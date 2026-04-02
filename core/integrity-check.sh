#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CHECKSUM_FILE="$SCRIPT_DIR/checksums.sha256"

collect_files() {
  find "$SCRIPT_DIR" -maxdepth 1 -name '*.sh' -type f | sort
  find "$PROJECT_DIR/modules" -name '*.sh' -type f 2>/dev/null | sort
}

generate() {
  local tmpfile
  tmpfile=$(mktemp)
  while IFS= read -r f; do
    rel="${f#"$PROJECT_DIR/"}"
    shasum -a 256 "$f" | awk -v r="$rel" '{print $1"  "r}'
  done < <(collect_files) > "$tmpfile"
  mv "$tmpfile" "$CHECKSUM_FILE"
  echo "Checksums generated"
}

verify() {
  [[ ! -f "$CHECKSUM_FILE" ]] && { generate; return 0; }
  local fail=0
  while IFS='  ' read -r expected rel; do
    full="$PROJECT_DIR/$rel"
    [[ ! -f "$full" ]] && { echo "TAMPERED (missing): $rel"; fail=1; continue; }
    actual=$(shasum -a 256 "$full" | awk '{print $1}')
    [[ "$actual" != "$expected" ]] && { echo "TAMPERED: $rel"; fail=1; }
  done < "$CHECKSUM_FILE"
  [[ $fail -eq 0 ]] && echo "All files OK"
  return $fail
}

case "${1:---verify}" in
  --generate) generate ;;
  --verify)   verify ;;
  *) echo "Usage: integrity-check.sh [--generate | --verify]"; exit 2 ;;
esac
