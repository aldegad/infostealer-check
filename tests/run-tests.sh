#!/usr/bin/env bash
# Test runner for infostealer-check
# Usage: bash tests/run-tests.sh

TESTS_DIR="$(cd "$(dirname "$0")" && pwd)"
PASS=0
FAIL=0
ERRORS=()

echo "=== infostealer-check test suite ==="
echo ""

for test_file in "$TESTS_DIR"/test-*.sh; do
    [ -f "$test_file" ] || continue
    test_name=$(basename "$test_file" .sh)
    printf "%-40s " "$test_name"
    
    output=$(bash "$test_file" 2>&1)
    if [ $? -eq 0 ]; then
        echo "PASS"
        PASS=$((PASS + 1))
    else
        echo "FAIL"
        FAIL=$((FAIL + 1))
        ERRORS+=("$test_name: $output")
    fi
done

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="

if [ ${#ERRORS[@]} -gt 0 ]; then
    echo ""
    echo "=== Failures ==="
    for err in "${ERRORS[@]}"; do
        echo "  $err"
    done
    exit 1
fi

exit 0
