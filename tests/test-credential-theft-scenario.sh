#!/usr/bin/env bash
set -e
source "$(dirname "$0")/helpers.sh"
PASS=0; FAIL=0

echo "=== Credential Theft Campaign Scenario Test ==="

# --- Test 1: Credential files scattered across HOME ---
setup_sandbox
echo "DB_PASSWORD=hunter2" > "$SANDBOX/.env"
echo "GITHUB_TOKEN=ghp_fakefakefakefake1234" >> "$SANDBOX/.env"
mkdir -p "$SANDBOX/.aws"
echo -e "[default]\naws_access_key_id=AKIA1234\naws_secret_access_key=secret" > "$SANDBOX/.aws/credentials"
echo "-----BEGIN OPENSSH PRIVATE KEY-----" > "$SANDBOX/.ssh/id_rsa"
echo "//registry.npmjs.org/:_authToken=npm_FAKETOKEN" > "$SANDBOX/.npmrc"
mkdir -p "$SANDBOX/.config/filezilla"
echo '<?xml version="1.0"?><FileZilla3><Servers><Server><Pass encoding="base64">cGFzc3dvcmQ=</Pass></Server></Servers></FileZilla3>' > "$SANDBOX/.config/filezilla/sitemanager.xml"

output=$(bash "$REPO_ROOT/modules/credential-access/T1552.001-creds-in-files.sh" 2>&1) || true
if echo "$output" | grep -qi "T1552.001"; then
    echo "  [PASS] Credential files detected"; PASS=$((PASS+1))
else
    echo "  [FAIL] Credential files not detected"; FAIL=$((FAIL+1))
fi
teardown_sandbox

# --- Test 2: Multi-browser credential DBs ---
setup_sandbox
for browser_dir in \
    "Library/Application Support/Google/Chrome/Default" \
    "Library/Application Support/Firefox/Profiles/abc123.default" \
    "Library/Application Support/BraveSoftware/Brave-Browser/Default" \
    "Library/Application Support/Microsoft Edge/Default"; do
    mkdir -p "$SANDBOX/$browser_dir"
    echo "SQLite format 3" > "$SANDBOX/$browser_dir/Login Data" 2>/dev/null || true
    echo "SQLite format 3" > "$SANDBOX/$browser_dir/Cookies" 2>/dev/null || true
done
echo '{"logins":[]}' > "$SANDBOX/Library/Application Support/Firefox/Profiles/abc123.default/logins.json"

output=$(bash "$REPO_ROOT/modules/credential-access/T1555.003-browser-creds.sh" 2>&1) || true
if [ -n "$output" ]; then
    echo "  [PASS] Multi-browser credential scan ran"; PASS=$((PASS+1))
else
    echo "  [FAIL] No output from multi-browser scan"; FAIL=$((FAIL+1))
fi
teardown_sandbox

# --- Test 3: Browser extensions audit ---
setup_sandbox
mkdir -p "$SANDBOX/Library/Application Support/Google/Chrome/Default/Extensions/abcdefghijklmnop"
echo '{"name":"Suspicious Extension","permissions":["tabs","cookies","webRequest","<all_urls>"]}' \
    > "$SANDBOX/Library/Application Support/Google/Chrome/Default/Extensions/abcdefghijklmnop/manifest.json"
output=$(bash "$REPO_ROOT/modules/persistence/T1176-browser-extensions.sh" 2>&1) || true
if echo "$output" | grep -qi "T1176\\|extension"; then
    echo "  [PASS] Suspicious extension detected"; PASS=$((PASS+1))
else
    echo "  [FAIL] Suspicious extension not detected"; FAIL=$((FAIL+1))
fi
teardown_sandbox

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
