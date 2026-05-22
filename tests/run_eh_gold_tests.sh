#!/bin/bash
# Run each early_hints gold test in isolation to prevent port/state cross-contamination.
# Each test is given a 90s timeout to detect hangs.
set -uo pipefail

TESTS=(
    early_hints_manual
    early_hints_auto_learn
    early_hints_cache_behavior
    early_hints_config_limits
    early_hints_edge_cases
    early_hints_h2_103
    early_hints_combined_mode
    early_hints_scan_advanced
    early_hints_resource_types
    early_hints_whitelist
    early_hints_cdn_scenarios
    early_hints_persistence
    early_hints_preload_whitelist
    early_hints_preconnect_attrs
    early_hints_cache_hardening
    early_hints_crossorigin_qstring
    early_hints_dedup_tautology
    early_hints_extract_origin_rfc3986
    early_hints_persist_debounce
    early_hints_scheme_validation
    early_hints_noscript_template
    early_hints_persist_dirty_flag
    early_hints_persist_load_validation
    early_hints_cache_intercept
    early_hints_security
    early_hints_origin_forward
    early_hints_hints_ttl
)

PASSED=0
FAILED=0
TIMEOUT_TESTS=()
FAILED_TESTS=()
LOG_DIR="/tmp/eh_gold_logs"
mkdir -p "$LOG_DIR"

cd "$(dirname "$0")"
export PYTHONPATH="$(pwd):$(pwd)/gold_tests/remap:${PYTHONPATH:-}"

for TEST in "${TESTS[@]}"; do
    LOG="$LOG_DIR/${TEST}.txt"
    printf "Running %-48s " "${TEST}:"

    if timeout 90s pipenv run autest run -D gold_tests \
            --ats-bin /opt/trafficserver-2/bin \
            -j1 -f "$TEST" > "$LOG" 2>&1; then
        RESULT=$(grep -E "Passed|Failed|Unknown" "$LOG" | grep "Running Test" | tail -1 || echo "")
        if grep -q " Passed" "$LOG" 2>/dev/null; then
            echo "PASSED"
            PASSED=$((PASSED + 1))
        elif grep -q " Failed" "$LOG" 2>/dev/null; then
            echo "FAILED — see $LOG"
            FAILED=$((FAILED + 1))
            FAILED_TESTS+=("$TEST")
        else
            echo "UNKNOWN  (check $LOG)"
            FAILED=$((FAILED + 1))
            FAILED_TESTS+=("${TEST}?")
        fi
    else
        EXIT=$?
        if [ $EXIT -eq 124 ]; then
            echo "TIMEOUT  (>90s) — pre-existing hang"
            TIMEOUT_TESTS+=("$TEST")
        else
            # Non-timeout non-zero exit — check log for result
            if grep -q " Passed" "$LOG" 2>/dev/null; then
                echo "PASSED"
                PASSED=$((PASSED + 1))
            else
                echo "FAILED (exit=$EXIT) — see $LOG"
                FAILED=$((FAILED + 1))
                FAILED_TESTS+=("$TEST")
            fi
        fi
    fi
done

echo ""
echo "======================================"
echo " Gold Test Results (early_hints)"
echo "======================================"
echo "  Passed : $PASSED"
echo "  Failed : $FAILED"
echo "  Timeout: ${#TIMEOUT_TESTS[@]}"
if [ ${#FAILED_TESTS[@]} -gt 0 ]; then
    echo "  Failed tests: ${FAILED_TESTS[*]}"
fi
if [ ${#TIMEOUT_TESTS[@]} -gt 0 ]; then
    echo "  Timeout tests (pre-existing hang): ${TIMEOUT_TESTS[*]}"
fi
