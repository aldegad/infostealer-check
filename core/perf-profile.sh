#!/usr/bin/env bash
# Performance profiler for infostealer-check v2
# Usage: bash core/perf-profile.sh [--threshold 30]
set -euo pipefail

threshold=30 json=0
while [ $# -gt 0 ]; do
  case "$1" in
    --threshold) threshold="${2:-30}"; shift 2 ;;
    --json) json=1; shift ;;
    -h|--help) sed -n '1,3p' "$0"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"
mapfile -t modules < <(find modules -name '*.sh' -type f | sort)
[ "${#modules[@]}" -gt 0 ] || { echo "No modules found" >&2; exit 1; }

names=() times=() statuses=() total_ns=0
for module in "${modules[@]}"; do
  start=$(date +%s%N)
  if bash "$module" --format json >/dev/null 2>&1; then status="OK"; else status="FAIL"; fi
  elapsed_ns=$(( $(date +%s%N) - start ))
  total_ns=$(( total_ns + elapsed_ns ))
  names+=("$(basename "$module")")
  times+=("$(awk -v ns="$elapsed_ns" 'BEGIN { printf "%.1f", ns/1000000000 }')")
  statuses+=("$status")
done

total_s=$(awk -v ns="$total_ns" 'BEGIN { printf "%.1f", ns/1000000000 }')
pass=$(awk -v t="$total_s" -v th="$threshold" 'BEGIN { print (t < th) ? 1 : 0 }')
summary=$([ "$pass" -eq 1 ] && printf 'PASS (< %ss)' "$threshold" || printf 'FAIL (>= %ss)' "$threshold")

if [ "$json" -eq 1 ]; then
  printf '[\n'
  for i in "${!names[@]}"; do
    printf '  {"module":"%s","time_seconds":%s,"status":"%s"},\n' "${names[$i]}" "${times[$i]}" "${statuses[$i]}"
  done
  printf '  {"module":"TOTAL","time_seconds":%s,"status":"%s"}\n]\n' "$total_s" "$summary"
else
  printf '%-35s %7s  %s\n' "Module" "Time(s)" "Status"
  printf '%.0s─' {1..53}; printf '\n'
  for i in "${!names[@]}"; do
    printf '%-35s %7s  %s\n' "${names[$i]}" "${times[$i]}" "${statuses[$i]}"
  done
  printf '%.0s─' {1..53}; printf '\n'
  printf '%-35s %7s  %s\n' "TOTAL" "$total_s" "$summary"
fi

exit $(( pass ? 0 : 1 ))
