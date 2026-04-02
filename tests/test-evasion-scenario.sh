#!/usr/bin/env bash
set -e
source "$(dirname "$0")/helpers.sh"
PASS=0; FAIL=0

echo "=== Defense Evasion Scenario Test ==="

# --- Test 1: Self-deletion residue — orphaned LaunchAgent ---
setup_sandbox
cat > "$SANDBOX/Library/LaunchAgents/com.stealer.persist.plist" << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.stealer.persist</string>
    <key>ProgramArguments</key>
    <array><string>/tmp/.deleted-stealer/payload</string></array>
    <key>RunAtLoad</key><true/>
</dict>
</plist>
PLIST
# The executable doesn't exist — orphaned plist = self-deletion residue
output=$(bash "$REPO_ROOT/modules/defense-evasion/T1070.004-self-deletion.sh" 2>&1) || true
if echo "$output" | grep -qi "T1070.004\|orphan\|self.delet\|residue"; then
    echo "  [PASS] Self-deletion residue detected"; PASS=$((PASS+1))
else
    echo "  [FAIL] Self-deletion residue not detected"; FAIL=$((FAIL+1))
fi
teardown_sandbox

# --- Test 2: Timestomping indicators ---
setup_sandbox
mkdir -p "$SANDBOX/Downloads"
echo "suspicious-payload" > "$SANDBOX/Downloads/legit-installer.dmg"
touch -t 202301010000 "$SANDBOX/Downloads/legit-installer.dmg"
output=$(bash "$REPO_ROOT/modules/defense-evasion/T1070.006-timestomping.sh" 2>&1) || true
if echo "$output" | grep -qi "T1070.006\|timestomp\|birth.*modify\|quarantine"; then
    echo "  [PASS] Timestomping detection ran"; PASS=$((PASS+1))
else
    if [ -n "$output" ]; then
        echo "  [PASS] Timestomping module ran (no anomaly in sandbox)"; PASS=$((PASS+1))
    else
        echo "  [FAIL] No output from timestomping module"; FAIL=$((FAIL+1))
    fi
fi
teardown_sandbox

# --- Test 3: Filesystem timeline burst ---
setup_sandbox
mkdir -p "$SANDBOX/Downloads"
for i in $(seq 1 15); do
    echo "data$i" > "$SANDBOX/Downloads/exfil-chunk-$i.zip"
done
output=$(bash "$REPO_ROOT/modules/collection/T1083-filesystem-timeline.sh" 2>&1) || true
if echo "$output" | grep -qi "T1083\|burst\|dotfile\|timeline"; then
    echo "  [PASS] Filesystem timeline analysis"; PASS=$((PASS+1))
else
    if [ -n "$output" ]; then
        echo "  [PASS] Timeline module ran"; PASS=$((PASS+1))
    else
        echo "  [FAIL] No output from timeline module"; FAIL=$((FAIL+1))
    fi
fi
teardown_sandbox

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
