#!/usr/bin/env bash
set -e
source "$(dirname "$0")/helpers.sh"

# Smoke test: module should run without crashing
# C2 detection checks live network state, can't mock easily
# Just verify it executes and produces some output

setup_sandbox

output=$(bash "$REPO_ROOT/modules/exfiltration/T1041-c2-channel.sh" 2>&1) || true

# Should produce some output (either findings or clean message)
if [ -z "$output" ]; then
    echo "FAIL: no output from module"
    teardown_sandbox
    exit 1
fi

# Should contain the technique ID somewhere in output
if ! echo "$output" | grep -qE "T1041|clean|no.*found|connection"; then
    echo "FAIL: output doesn't reference technique or results"
    teardown_sandbox
    exit 1
fi

teardown_sandbox
echo "PASS"
exit 0
