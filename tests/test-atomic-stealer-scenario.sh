#!/usr/bin/env bash
set -e
source "$(dirname "$0")/helpers.sh"
PASS=0; FAIL=0

echo "=== Atomic Stealer (AMOS) Scenario Test ==="

# --- Test 1: AppleScript password prompt in shell history ---
setup_sandbox
cat > "$SANDBOX/.bash_history" << 'HIST'
osascript -e 'display dialog "Enter your password" default answer "" with hidden answer'
security find-generic-password -ga "Chrome" 
osascript -e 'tell application "System Events" to keystroke "password"'
HIST
output=$(bash "$REPO_ROOT/modules/execution/T1059.002-applescript.sh" 2>&1) || true
if echo "$output" | grep -qi "T1059.002\|applescript\|osascript"; then
    echo "  [PASS] AppleScript prompt detection"; PASS=$((PASS+1))
else
    echo "  [FAIL] AppleScript prompt not detected"; FAIL=$((FAIL+1))
fi
teardown_sandbox

# --- Test 2: Keychain access patterns ---
setup_sandbox
cat > "$SANDBOX/.bash_history" << 'HIST'
security find-generic-password -ga "Chrome Safe Storage"
security dump-keychain -d login.keychain-db
HIST
output=$(bash "$REPO_ROOT/modules/credential-access/T1555.001-keychain.sh" 2>&1) || true
if echo "$output" | grep -qi "T1555.001\|keychain"; then
    echo "  [PASS] Keychain abuse detection"; PASS=$((PASS+1))
else
    echo "  [FAIL] Keychain abuse not detected"; FAIL=$((FAIL+1))
fi
teardown_sandbox

# --- Test 3: Browser credential DB exists (Chrome) ---
setup_sandbox
mkdir -p "$SANDBOX/Library/Application Support/Google/Chrome/Default"
echo "SQLite format 3" > "$SANDBOX/Library/Application Support/Google/Chrome/Default/Login Data"
echo "SQLite format 3" > "$SANDBOX/Library/Application Support/Google/Chrome/Default/Cookies"
output=$(bash "$REPO_ROOT/modules/credential-access/T1555.003-browser-creds.sh" 2>&1) || true
if [ -n "$output" ]; then
    echo "  [PASS] Browser credential detection ran"; PASS=$((PASS+1))
else
    echo "  [FAIL] No output from browser creds module"; FAIL=$((FAIL+1))
fi
teardown_sandbox

# --- Test 4: Crypto wallet paths exist ---
setup_sandbox
mkdir -p "$SANDBOX/Library/Application Support/Exodus/exodus.wallet"
mkdir -p "$SANDBOX/Library/Application Support/atomic/Local Storage"
echo "fake-wallet-data" > "$SANDBOX/Library/Application Support/Exodus/exodus.wallet/seed.seco"
output=$(bash "$REPO_ROOT/modules/collection/T1005-local-data.sh" 2>&1) || true
if echo "$output" | grep -qi "T1005\|wallet\|crypto"; then
    echo "  [PASS] Crypto wallet detection"; PASS=$((PASS+1))
else
    echo "  [FAIL] Crypto wallet not detected"; FAIL=$((FAIL+1))
fi
teardown_sandbox

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
