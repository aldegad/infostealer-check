#!/usr/bin/env bash
set -euo pipefail

usage() { echo "Usage: $(basename "$0") <report-dir> [--key <public-key-file>]" >&2; exit 1; }

command -v gpg >/dev/null 2>&1 || { echo "Error: gpg is not installed" >&2; exit 1; }

[ $# -eq 1 ] || [ $# -eq 3 ] || usage

report_dir="$1"
[ -d "$report_dir" ] || { echo "Error: report directory not found: $report_dir" >&2; exit 1; }

base="$(cd "$(dirname "$report_dir")" && pwd)"
name="$(basename "$report_dir")"

if [ "${2:-}" = "--key" ] && [ -n "${3:-}" ]; then
  key_file="$3"
  [ -f "$key_file" ] || { echo "Error: public key file not found: $key_file" >&2; exit 1; }
  out="${report_dir%/}.tar.gz.gpg"
  tar -czf - -C "$base" "$name" \
    | gpg --batch --yes --encrypt --recipient-file "$key_file" -o "$out"
elif [ $# -eq 1 ]; then
  out="${report_dir%/}.tar.gz.enc"
  tar -czf - -C "$base" "$name" \
    | gpg --batch --yes --symmetric -o "$out"
else
  usage
fi

printf '%s\n' "$out"
