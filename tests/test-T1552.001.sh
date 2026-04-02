#!/usr/bin/env bash
set -e
source "$(dirname "$0")/helpers.sh"

# Test 1: Plant credential files → should detect
setup_sandbox

# Plant fake credential files
echo "AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7FAKE" > "$SANDBOX/.env"
mkdir -p "$SANDBOX/.aws"
echo -e "[default]\naws_secret_access_key = wJalrXUtnFEMI/FAKE" > "$SANDBOX/.aws/credentials"
echo "-----BEGIN RSA PRIVATE KEY-----" > "$SANDBOX/.ssh/id_rsa"
echo "_authToken=npm_FAKETOKEN123456" > "$SANDBOX/.npmrc"

output=$(bash "$REPO_ROOT/modules/credential-access/T1552.001-creds-in-files.sh" 2>&1) || true
assert_detected "T1552.001" "$output" || { teardown_sandbox; exit 1; }

teardown_sandbox

# Test 2: No creds planted → should be clean
setup_sandbox
output=$(bash "$REPO_ROOT/modules/credential-access/T1552.001-creds-in-files.sh" 2>&1) || true
# Should run without error even if nothing found
teardown_sandbox

echo "PASS"
exit 0
