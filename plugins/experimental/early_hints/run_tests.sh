#!/usr/bin/env bash
# run_tests.sh  -- Early Hints plugin test runner
#
# Usage:
#   ./run_tests.sh              # unit tests only (fast, no ATS needed)
#   ./run_tests.sh --gold       # unit tests + gold tests (requires ATS install)
#   ./run_tests.sh --gold-only  # gold tests only
#   ./run_tests.sh --filter "keyword"  # pass Catch2 filter to unit tests
#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"        # trafficserver-custom/
PLUGINS_DIR="${BUILD_ROOT}/plugins"
BINARY_DIR="${SCRIPT_DIR}"
GOLD_DIR="${BUILD_ROOT}/tests/gold_tests/pluginTest/early_hints"

# -- Colour helpers -------------------------------------------------------------
GREEN="\033[0;32m"; RED="\033[0;31m"; YELLOW="\033[1;33m"; RESET="\033[0m"
ok()   { echo -e "${GREEN}✓${RESET} $*"; }
fail() { echo -e "${RED}✗${RESET} $*"; }
info() { echo -e "${YELLOW}▶${RESET} $*"; }

# -- Argument parsing -----------------------------------------------------------
RUN_UNIT=true
RUN_GOLD=false
CATCH_FILTER=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --gold)       RUN_GOLD=true  ;;
    --gold-only)  RUN_GOLD=true; RUN_UNIT=false ;;
    --filter)     CATCH_FILTER="$2"; shift ;;
    -h|--help)
      sed -n '2,12p' "$0" | sed 's/^# \?//'
      exit 0 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
  shift
done

UNIT_PASS=0
UNIT_FAIL=0
GOLD_RESULT=""

# -- Unit tests -----------------------------------------------------------------
if [[ "${RUN_UNIT}" == "true" ]]; then
  info "Building unit test binaries …"
  set +e  # build failure is non-fatal if binaries already exist
  make -C "${PLUGINS_DIR}" \
    experimental/early_hints/test_early_hints \
    experimental/early_hints/test_transform \
    experimental/early_hints/test_plugin_hooks \
    -j"$(nproc)" --no-print-directory 2>&1 | \
    grep -E 'CXX |CXXLD |error:|Error' || true
  set -e

  echo ""
  info "Running: test_early_hints …"
  FILTER_ARGS=()
  [[ -n "${CATCH_FILTER}" ]] && FILTER_ARGS=("${CATCH_FILTER}")

  EH_LOG=$(mktemp /tmp/eh_test_XXXXXX.log)
  "${BINARY_DIR}/test_early_hints" \
    --reporter compact "${FILTER_ARGS[@]+"${FILTER_ARGS[@]}"}" \
    > "${EH_LOG}" 2>&1
  EH_EXIT=$?
  cat "${EH_LOG}"
  rm -f "${EH_LOG}"
  if [[ "${EH_EXIT}" -eq 0 ]]; then
    UNIT_PASS=$((UNIT_PASS + 1))
    ok "test_early_hints PASSED"
  else
    UNIT_FAIL=$((UNIT_FAIL + 1))
    fail "test_early_hints FAILED (exit=${EH_EXIT})"
  fi

  echo ""
  info "Running: test_transform …"
  TF_LOG=$(mktemp /tmp/tf_test_XXXXXX.log)
  "${BINARY_DIR}/test_transform" \
    --reporter compact "${FILTER_ARGS[@]+"${FILTER_ARGS[@]}"}" \
    > "${TF_LOG}" 2>&1
  TF_EXIT=$?
  cat "${TF_LOG}"
  rm -f "${TF_LOG}"
  if [[ "${TF_EXIT}" -eq 0 ]]; then
    UNIT_PASS=$((UNIT_PASS + 1))
    ok "test_transform PASSED"
  else
    UNIT_FAIL=$((UNIT_FAIL + 1))
    fail "test_transform FAILED (exit=${TF_EXIT})"
  fi

  echo ""
  info "Running: test_plugin_hooks …"
  PH_LOG=$(mktemp /tmp/ph_test_XXXXXX.log)
  "${BINARY_DIR}/test_plugin_hooks" \
    --reporter compact "${FILTER_ARGS[@]+"${FILTER_ARGS[@]}"}" \
    > "${PH_LOG}" 2>&1
  PH_EXIT=$?
  cat "${PH_LOG}"
  rm -f "${PH_LOG}"
  if [[ "${PH_EXIT}" -eq 0 ]]; then
    UNIT_PASS=$((UNIT_PASS + 1))
    ok "test_plugin_hooks PASSED"
  else
    UNIT_FAIL=$((UNIT_FAIL + 1))
    fail "test_plugin_hooks FAILED (exit=${PH_EXIT})"
  fi
fi

# -- Gold tests (per-test isolation, 90s timeout each) ------------------------
if [[ "${RUN_GOLD}" == "true" ]]; then
  echo ""
  info "Building and installing plugin for gold tests …"
  set +e
  BUILD_LOG=$(mktemp /tmp/eh_build_XXXXXX.log)
  sudo make -C "${PLUGINS_DIR}" install -j"$(nproc)" > "${BUILD_LOG}" 2>&1
  if [[ $? -ne 0 ]]; then
    fail "Plugin build/install failed"
    cat "${BUILD_LOG}"
    rm -f "${BUILD_LOG}"
    exit 1
  fi
  rm -f "${BUILD_LOG}"
  ok "Plugin installed successfully"

  echo ""
  info "Running gold tests (44 test files, isolated) …"

  GOLD_TESTS=(
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
    early_hints_scheme_validation
    early_hints_noscript_template
    early_hints_persist_load_validation
    early_hints_security
    early_hints_origin_forward
    early_hints_hints_ttl
    early_hints_purge_header
    early_hints_origin_forward_self_heal
    early_hints_origin_forward_ttl_refresh
    early_hints_backslash_rcdata
    early_hints_modulepreload
    early_hints_persist_hardening
    early_hints_scanner_correctness
    early_hints_link_parser_fixes
    early_hints_scanner_boundary
    early_hints_path_case_dedup
    early_hints_bare_crossorigin
    early_hints_stale_eviction
    early_hints_purge_rate_limit
    early_hints_purge_rate_limit_window
    early_hints_origin_forward_multi_link_dedup
    early_hints_fetchpriority
    early_hints_navigate_only
    early_hints_prior_plugin
    early_hints_multi_instance
    early_hints_stats
  )

  ATS_BIN="${ATS_BIN:-$(command -v traffic_server 2>/dev/null | xargs dirname 2>/dev/null || echo /opt/trafficserver-2/bin)}"
  GOLD_LOG_DIR="/tmp/eh_gold_logs"
  mkdir -p "${GOLD_LOG_DIR}"

  GOLD_PASS=0
  GOLD_FAIL=0
  GOLD_TIMEOUT=0
  GOLD_FAILED_NAMES=()
  GOLD_TIMEOUT_NAMES=()

  # Run from tests/ directory so relative -D gold_tests path resolves
  TESTS_DIR="${BUILD_ROOT}/tests"

  # run_gold_test TEST → returns 0 on pass, 1 on fail, 2 on timeout
  # Retries up to MAX_RETRIES times with a cooldown between attempts.
  run_gold_test() {
    local TEST="$1"
    local LOG="${GOLD_LOG_DIR}/${TEST}.txt"
    local MAX_RETRIES=2
    local ATTEMPT=0
    local RESULT=1

    while [[ "${ATTEMPT}" -le "${MAX_RETRIES}" ]]; do
      if [[ "${ATTEMPT}" -gt 0 ]]; then
        # Cooldown: let OS reclaim ports from previous attempt
        sleep 5
        printf "(retry %d) " "${ATTEMPT}"
      fi

      # Clear previous sandbox so the test starts fresh
      rm -rf "${BUILD_ROOT}/tests/_sandbox/${TEST}" 2>/dev/null || true

      local EXIT=0
      (cd "${TESTS_DIR}" && timeout 90s pipenv run autest run \
          -D gold_tests \
          --ats-bin "${ATS_BIN}" \
          -j1 -f "${TEST}") \
          > "${LOG}" 2>&1 || EXIT=$?

      if [[ "${EXIT}" -eq 124 ]]; then
        RESULT=2
        break  # timeout  -- no point retrying
      fi

      if grep -q "Failed: 0" "${LOG}" 2>/dev/null && ! grep -qE "Failed: [1-9]|Exception: [1-9]" "${LOG}" 2>/dev/null; then
        RESULT=0
        break
      fi

      ATTEMPT=$((ATTEMPT + 1))
    done

    return "${RESULT}"
  }

  for TEST in "${GOLD_TESTS[@]}"; do
    printf "  %-52s " "${TEST}:"

    RESULT=0
    run_gold_test "${TEST}" || RESULT=$?

    if [[ "${RESULT}" -eq 0 ]]; then
      echo "PASSED"
      GOLD_PASS=$((GOLD_PASS + 1))
    elif [[ "${RESULT}" -eq 2 ]]; then
      echo "TIMEOUT (>90s)"
      GOLD_TIMEOUT=$((GOLD_TIMEOUT + 1))
      GOLD_TIMEOUT_NAMES+=("${TEST}")
    else
      echo "FAILED  -- ${GOLD_LOG_DIR}/${TEST}.txt"
      GOLD_FAIL=$((GOLD_FAIL + 1))
      GOLD_FAILED_NAMES+=("${TEST}")
    fi
  done

  if [[ "${GOLD_FAIL}" -eq 0 && "${GOLD_TIMEOUT}" -eq 0 ]]; then
    GOLD_RESULT="PASSED (${GOLD_PASS}/${#GOLD_TESTS[@]})"
    ok "Gold tests PASSED"
  else
    GOLD_RESULT="FAILED (passed=${GOLD_PASS} failed=${GOLD_FAIL} timeout=${GOLD_TIMEOUT})"
    fail "Gold tests FAILED"
    [[ ${#GOLD_FAILED_NAMES[@]} -gt 0 ]]  && echo "  Failed  : ${GOLD_FAILED_NAMES[*]}"
    [[ ${#GOLD_TIMEOUT_NAMES[@]} -gt 0 ]] && echo "  Timeout : ${GOLD_TIMEOUT_NAMES[*]}"
    echo "  Logs in : ${GOLD_LOG_DIR}/"
  fi
fi

# -- Summary --------------------------------------------------------------------
echo ""
echo "----------------------------------------"
echo " Early Hints Plugin  -- Test Summary"
echo "----------------------------------------"

if [[ "${RUN_UNIT}" == "true" ]]; then
  echo " Unit test suites : passed=${UNIT_PASS}  failed=${UNIT_FAIL}"
fi
if [[ "${RUN_GOLD}" == "true" ]]; then
  echo " Gold tests       : ${GOLD_RESULT}"
fi
echo "----------------------------------------"

# Exit non-zero if anything failed
[[ "${UNIT_FAIL}" -eq 0 ]] || exit 1
[[ "${GOLD_RESULT}" != "FAILED" ]] || exit 1
exit 0
