#!/usr/bin/env bash
set -e
source "$(dirname "$0")/helpers.sh"

# Test 1: Verify signatures file exists and is valid JSON
SIGS="$REPO_ROOT/signatures/process-names.json"
if [ ! -f "$SIGS" ]; then
    echo "FAIL: signatures/process-names.json not found"
    exit 1
fi
if command -v jq >/dev/null 2>&1; then
    jq empty "$SIGS" 2>/dev/null || { echo "FAIL: invalid JSON in process-names.json"; exit 1; }
else
    python - "$SIGS" <<'EOF' || { echo "FAIL: invalid JSON in process-names.json"; exit 1; }
import json
import pathlib
import sys

with pathlib.Path(sys.argv[1]).open("r", encoding="utf-8") as handle:
    json.load(handle)
EOF
fi

# Test 2: Fake Claude installer from Downloads should be flagged
setup_sandbox
setup_mock_bin
mkdir -p "$HOME/Downloads"
printf 'fake dmg' > "$HOME/Downloads/Claude-Code.dmg"

cat > "$SANDBOX/mockbin/ps" <<EOF
#!/usr/bin/env bash
cat <<'PSOUT'
USER       PID  %CPU %MEM      VSZ    RSS   TT  STAT STARTED      TIME COMMAND
tester    4242   0.0  0.1   100000   4096   ??  S     1:00PM   0:00.01 $HOME/Downloads/Claude Code.app/Contents/MacOS/Claude Code
PSOUT
EOF
chmod +x "$SANDBOX/mockbin/ps"

cat > "$SANDBOX/mockbin/codesign" <<'EOF'
#!/usr/bin/env bash
if printf '%s ' "$@" | grep -q 'Claude Code.app'; then
  echo 'code object is not signed at all'
  exit 1
fi
exit 0
EOF
chmod +x "$SANDBOX/mockbin/codesign"

cat > "$SANDBOX/mockbin/spctl" <<'EOF'
#!/usr/bin/env bash
echo 'rejected'
echo 'source=no usable signature'
exit 1
EOF
chmod +x "$SANDBOX/mockbin/spctl"

cat > "$SANDBOX/mockbin/find" <<'EOF'
#!/usr/bin/env bash
/usr/bin/find "$@"
EOF
chmod +x "$SANDBOX/mockbin/find"

output=$(bash "$REPO_ROOT/modules/execution/T1204.002-malicious-file.sh" 2>&1) || true
assert_detected "T1204.002" "$output"
assert_contains "Claude-Code.dmg" "$output"
assert_contains "lure name" "$output"
teardown_sandbox

# Test 3: Clean sandbox should stay clean
setup_sandbox
setup_mock_bin
cat > "$SANDBOX/mockbin/ps" <<'EOF'
#!/usr/bin/env bash
cat <<'PSOUT'
USER       PID  %CPU %MEM      VSZ    RSS   TT  STAT STARTED      TIME COMMAND
tester    1111   0.0  0.1   100000   4096   ??  S     1:00PM   0:00.01 /Applications/Safari.app/Contents/MacOS/Safari
PSOUT
EOF
chmod +x "$SANDBOX/mockbin/ps"
cat > "$SANDBOX/mockbin/codesign" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$SANDBOX/mockbin/codesign"
cat > "$SANDBOX/mockbin/spctl" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$SANDBOX/mockbin/spctl"
cat > "$SANDBOX/mockbin/find" <<'EOF'
#!/usr/bin/env bash
/usr/bin/find "$@"
EOF
chmod +x "$SANDBOX/mockbin/find"

output=$(bash "$REPO_ROOT/modules/execution/T1204.002-malicious-file.sh" 2>&1) || true
assert_clean "T1204.002" "$output"
teardown_sandbox

echo "PASS"
exit 0
