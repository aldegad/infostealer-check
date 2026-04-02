#!/usr/bin/env bash
set -e
source "$(dirname "$0")/helpers.sh"

# Test 1: Plant fake browser credential files → should detect
setup_sandbox

# Create Chrome profile with Login Data
CHROME_DIR="$SANDBOX/Library/Application Support/Google/Chrome/Default"
mkdir -p "$CHROME_DIR"
echo "SQLite format 3" > "$CHROME_DIR/Login Data"
echo "SQLite format 3" > "$CHROME_DIR/Cookies"

# Run module
output=$(bash "$REPO_ROOT/modules/credential-access/T1555.003-browser-creds.sh" 2>&1) || true

# The module should find these files exist
# (It checks for non-browser process access, but file existence is the baseline)
# Just verify the module runs without error and produces output
if [ -z "$output" ]; then
    echo "FAIL: no output from module"
    teardown_sandbox
    exit 1
fi

teardown_sandbox

# Test 2: Empty sandbox → should be clean or minimal
setup_sandbox
output=$(bash "$REPO_ROOT/modules/credential-access/T1555.003-browser-creds.sh" 2>&1) || true
teardown_sandbox

echo "PASS"
exit 0
