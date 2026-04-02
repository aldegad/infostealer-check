#!/usr/bin/env bash
set -euo pipefail

jq -Rn '
  def lvl($s):
    ($s // "" | ascii_downcase) as $v
    | if $v=="critical" or $v=="high" then "error"
      elif $v=="medium" then "warning"
      else "note" end;
  {
    version: "2.1.0",
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [{
      tool: {driver: {name: "infostealer-check", version: "2.0.0"}},
      results: [
        inputs
        | select(length > 0)
        | fromjson as $f
        | {
            ruleId: $f.technique_id,
            level: lvl($f.severity),
            message: {text: ($f.title + ": " + ($f.evidence // ""))},
            rule: {id: $f.technique_id},
            properties: {
              severity: $f.severity,
              remediation: $f.remediation,
              timestamp: $f.timestamp,
              hostname: $f.hostname
            }
          }
      ]
    }]
  }'
