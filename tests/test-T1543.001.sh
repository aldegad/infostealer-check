#!/usr/bin/env bash
set -e
source "$(dirname "$0")/helpers.sh"

# Test 1: Plant suspicious LaunchAgent
setup_sandbox

cat > "$SANDBOX/Library/LaunchAgents/com.malware.update.plist" << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.malware.update</string>
    <key>ProgramArguments</key>
    <array>
        <string>/tmp/.hidden/payload</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
PLIST

output=$(bash "$REPO_ROOT/modules/persistence/T1543.001-launch-agent.sh" 2>&1) || true
assert_detected "T1543.001" "$output" || { teardown_sandbox; exit 1; }

teardown_sandbox

# Test 2: No agents
setup_sandbox
output=$(bash "$REPO_ROOT/modules/persistence/T1543.001-launch-agent.sh" 2>&1) || true
teardown_sandbox

echo "PASS"
exit 0
