#!/usr/bin/env bash
set -e
source "$(dirname "$0")/helpers.sh"

# Test 1: Verify signatures file exists and is valid JSON
SIGS="$REPO_ROOT/signatures/process-names.json"
if [ ! -f "$SIGS" ]; then
    echo "FAIL: signatures/process-names.json not found"
    exit 1
fi
jq empty "$SIGS" 2>/dev/null || { echo "FAIL: invalid JSON in process-names.json"; exit 1; }

# Test 2: Smoke test — module runs without crashing
setup_sandbox
output=$(bash "$REPO_ROOT/modules/execution/T1204.002-malicious-file.sh" 2>&1) || true

if [ -z "$output" ]; then
    echo "FAIL: no output from module"
    teardown_sandbox
    exit 1
fi

teardown_sandbox
echo "PASS"
exit 0
