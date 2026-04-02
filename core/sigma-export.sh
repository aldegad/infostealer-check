#!/usr/bin/env bash
# sigma-export.sh — Convert NDJSON findings to Sigma-compatible log events
# Usage: cat findings.ndjson | ./sigma-export.sh

set -euo pipefail

if ! command -v jq &>/dev/null; then
  echo "ERROR: jq is required but not found in PATH" >&2
  exit 1
fi

HOST="${HOSTNAME:-$(hostname)}"

jq -c --arg host "$HOST" '{
  EventTime:      (.timestamp // (.time // (now | strftime("%Y-%m-%dT%H:%M:%SZ")))),
  EventType:      "infostealer-check-finding",
  MitreTechnique: (.mitre_technique // .mitre // "T1555"),
  Severity:       (.severity // "medium"),
  Title:          (.title // .rule // "Infostealer indicator detected"),
  Evidence:       (.evidence // .detail // .message // ""),
  Host:           $host,
  DetectionTool:  "infostealer-check-v2"
}'
