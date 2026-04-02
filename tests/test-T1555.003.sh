#!/usr/bin/env bash
set -e
source "$(dirname "$0")/helpers.sh"

setup_sandbox
setup_mock_bin

CHROME_DIR="$SANDBOX/Library/Application Support/Google/Chrome/Profile 1"
mkdir -p "$CHROME_DIR"
echo "SQLite format 3" > "$CHROME_DIR/Login Data"
echo "SQLite format 3" > "$CHROME_DIR/Cookies"
cat > "$SANDBOX/mockbin/lsof" <<EOF
#!/usr/bin/env bash
printf '%s\n' 'COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME'
printf '%s\n' 'python3 4242 tester 12r REG 1,4 0 0 $CHROME_DIR/Login Data'
printf '%s\n' 'python3 4242 tester 13r REG 1,4 0 0 $CHROME_DIR/Cookies'
EOF
chmod +x "$SANDBOX/mockbin/lsof"

output=$(bash "$REPO_ROOT/modules/credential-access/T1555.003-browser-creds.sh" 2>&1) || true
assert_detected "T1555.003" "$output"
assert_contains "Profile 1" "$output"
assert_contains "credential or session store" "$output"
teardown_sandbox

setup_sandbox
setup_mock_bin
mkdir -p "$SANDBOX/Library/Application Support/Google/Chrome/Default"
echo "SQLite format 3" > "$SANDBOX/Library/Application Support/Google/Chrome/Default/Login Data"
cat > "$SANDBOX/mockbin/lsof" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$SANDBOX/mockbin/lsof"

output=$(bash "$REPO_ROOT/modules/credential-access/T1555.003-browser-creds.sh" 2>&1) || true
assert_clean "T1555.003" "$output"
teardown_sandbox

echo "PASS"
exit 0
