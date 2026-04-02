#!/usr/bin/env bash
# Test helpers — sourced by each test-*.sh

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SANDBOX=""
ORIGINAL_HOME="$HOME"

setup_sandbox() {
    SANDBOX=$(mktemp -d "${TMPDIR:-/tmp}/isc-test.XXXXXX")
    export HOME="$SANDBOX"
    # Create standard macOS directory structure
    mkdir -p "$SANDBOX/Library/LaunchAgents"
    mkdir -p "$SANDBOX/Library/Application Support"
    mkdir -p "$SANDBOX/Library/Caches"
    mkdir -p "$SANDBOX/Downloads"
    mkdir -p "$SANDBOX/.ssh"
}

teardown_sandbox() {
    export HOME="$ORIGINAL_HOME"
    [ -n "$SANDBOX" ] && rm -rf "$SANDBOX"
}

assert_detected() {
    local technique="$1" output="$2"
    if echo "$output" | grep -q "$technique"; then
        return 0
    else
        echo "  FAIL: expected technique $technique in output"
        echo "  OUTPUT: $(echo "$output" | head -5)"
        return 1
    fi
}

assert_clean() {
    local technique="$1" output="$2"
    if echo "$output" | grep -qi "clean\|no.*found\|no.*detected"; then
        return 0
    else
        echo "  FAIL: expected clean result"
        return 1
    fi
}
