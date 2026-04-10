#!/usr/bin/env bash
#
# sir Test Fixture Runner
# Iterates all hook-payload fixtures, pipes each to sir guard evaluate
# (or post-evaluate for PostToolUse), and compares the actual verdict
# against _test_metadata.expected_verdict.
#
# Each fixture runs in an isolated temp project directory with properly
# seeded session state, lease, and posture files.
#
# Usage:
#   ./testdata/run_fixtures.sh [--verbose] [--filter PATTERN]
#
# Requirements:
#   - sir binary in PATH (or ~/.local/bin/sir, or project bin/)
#   - jq installed
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXTURE_DIR="${SCRIPT_DIR}/hook-payloads"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# Options
VERBOSE=false
FILTER=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --verbose|-v) VERBOSE=true; shift ;;
    --filter|-f) FILTER="$2"; shift 2 ;;
    --help|-h)
      echo "Usage: $0 [--verbose] [--filter PATTERN]"
      echo ""
      echo "  --verbose, -v    Show detailed output for each fixture"
      echo "  --filter, -f     Only run fixtures matching PATTERN (glob)"
      echo "  --help, -h       Show this help"
      exit 0
      ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

# Find sir binary — prefer freshly built binary in project
SIR_BIN=""
if [[ -x "${PROJECT_ROOT}/bin/sir" ]]; then
  SIR_BIN="${PROJECT_ROOT}/bin/sir"
elif [[ -x "${PROJECT_ROOT}/sir" ]]; then
  SIR_BIN="${PROJECT_ROOT}/sir"
elif command -v sir &>/dev/null; then
  SIR_BIN="$(command -v sir)"
elif [[ -x "${HOME}/.local/bin/sir" ]]; then
  SIR_BIN="${HOME}/.local/bin/sir"
else
  echo -e "${RED}ERROR: sir binary not found.${RESET}"
  echo "Build with: go build -o bin/sir ./cmd/sir"
  exit 1
fi

# Check jq
if ! command -v jq &>/dev/null; then
  echo -e "${RED}ERROR: jq is required but not installed${RESET}"
  echo "Install with: brew install jq (macOS) or apt install jq (Linux)"
  exit 1
fi

echo -e "${BOLD}sir Fixture Test Runner${RESET}"
echo -e "Binary: ${SIR_BIN}"
echo -e "Fixtures: ${FIXTURE_DIR}"
echo ""

TOTAL=0
PASSED=0
FAILED=0
ERRORS=0

declare -a FAILED_FIXTURES=()

# --- Helpers ---

# project_hash computes the SHA-256 hex digest of a path (same as session.ProjectHash)
project_hash() {
  echo -n "$1" | shasum -a 256 | awk '{print $1}'
}

# seed_project_dir creates an isolated project directory with standard files
seed_project_dir() {
  local tmpdir="$1"

  mkdir -p "${tmpdir}/.claude/hooks"
  mkdir -p "${tmpdir}/.claude/.sir"

  echo 'DATABASE_URL=postgres://user:secret@db:5432/mydb' > "${tmpdir}/.env"
  echo 'DATABASE_URL=postgres://user:password@localhost:5432/mydb' > "${tmpdir}/.env.example"
  echo '# Project Instructions' > "${tmpdir}/CLAUDE.md"
  echo '{"servers": {}}' > "${tmpdir}/.mcp.json"
  echo '{"hooks": [{"event": "PreToolUse", "command": "sir guard evaluate"}]}' > "${tmpdir}/.claude/hooks/hooks.json"
  echo '{"permissions": {"allow": []}}' > "${tmpdir}/.claude/settings.json"
  echo 'package main' > "${tmpdir}/main.go"
  echo '# README' > "${tmpdir}/README.md"
}

# compute_file_hash returns SHA-256 of a file
compute_file_hash() {
  shasum -a 256 "$1" 2>/dev/null | awk '{print $1}'
}

# seed_session writes session.json and a default lease for the temp project to
# ~/.sir/projects/<hash>/ using the same Go helpers as production code.
seed_session() {
  local tmpdir="$1"
  local secret_session="$2"
  local deny_all="${3:-false}"
  local posture_hashes="${4:-}"
  local pending_install="${5:-}"

  # Build posture hashes if not provided
  if [[ -z "$posture_hashes" ]]; then
    posture_hashes="{}"
    # Hash whatever posture files exist in the project
    local h
    for pf in ".claude/hooks/hooks.json" ".claude/settings.json" "CLAUDE.md" ".mcp.json"; do
      if [[ -f "${tmpdir}/${pf}" ]]; then
        h="$(compute_file_hash "${tmpdir}/${pf}")"
        posture_hashes="$(echo "$posture_hashes" | jq --arg k "$pf" --arg v "$h" '. + {($k): $v}')"
      fi
    done
  fi

  local args=(
    --project-root "$tmpdir"
    --secret-session="$secret_session"
    --deny-all="$deny_all"
    --posture-hashes "$posture_hashes"
  )
  if [[ -n "$pending_install" ]]; then
    args+=(--pending-install "$pending_install")
  fi

  go run "${SCRIPT_DIR}/seed_fixture_state.go" "${args[@]}"
}

# cleanup_session removes the session state for a temp project
cleanup_session() {
  local tmpdir="$1"
  local phash
  phash="$(project_hash "$tmpdir")"
  rm -rf "${HOME}/.sir/projects/${phash}"
}

# extract_verdict parses sir output (stdout + stderr) to determine the verdict
extract_verdict() {
  local output="$1"
  local verdict=""

  # Try JSON output first (PreToolUse returns JSON on stdout)
  if echo "$output" | jq -e '.hookSpecificOutput.permissionDecision' &>/dev/null; then
    verdict="$(echo "$output" | jq -r '.hookSpecificOutput.permissionDecision')"
  elif echo "$output" | jq -e '.verdict // .decision // .result // .action' &>/dev/null; then
    verdict="$(echo "$output" | jq -r '.verdict // .decision // .result // .action // empty')"
  fi

  # If no JSON verdict, check for keywords in text output (PostToolUse writes stderr)
  if [[ -z "$verdict" ]]; then
    case "$output" in
      *"EMERGENCY"*|*"deny-all"*|*"deny_all"*|*"session-fatal"*|*"All tool calls are blocked"*)
        verdict="deny" ;;
      *"ALERT"*|*"sentinel"*|*"tamper"*|*"mutation"*)
        verdict="alert" ;;
      *"BLOCKED"*|*"blocked"*|*'"deny"'*)
        verdict="deny" ;;
      *"ASK"*|*'"ask"'*)
        verdict="ask" ;;
      *) verdict="allow" ;;  # PostToolUse with no output = allow
    esac
  fi

  echo "$verdict" | tr '[:upper:]' '[:lower:]'
}

# --- Main loop ---

for fixture in "${FIXTURE_DIR}"/*.json; do
  filename="$(basename "$fixture")"

  # Skip non-test files
  case "$filename" in
    ledger-*) continue ;;
  esac

  # Apply filter if specified
  if [[ -n "$FILTER" ]] && [[ "$filename" != *${FILTER}* ]]; then
    continue
  fi

  TOTAL=$((TOTAL + 1))

  # Extract metadata
  expected_verdict="$(jq -r '._test_metadata.expected_verdict' "$fixture")"
  expected_reason="$(jq -r '._test_metadata.expected_reason // "N/A"' "$fixture")"
  hook_type="$(jq -r '._test_metadata.hook_type // "PreToolUse"' "$fixture")"
  session_fatal="$(jq -r '._test_metadata.session_fatal // false' "$fixture")"
  secret_session="$(jq -r '._test_metadata.session_state.secret_session // false' "$fixture")"

  if $VERBOSE; then
    echo -e "${CYAN}--- ${filename} ---${RESET}"
    echo -e "  Hook type: ${hook_type}"
    echo -e "  Expected:  ${expected_verdict}"
    echo -e "  Secret session: ${secret_session}"
  fi

  # Create isolated temp project directory
  # Resolve symlinks so the path matches Go's os.Getwd() (macOS: /var/folders -> /private/var/folders)
  tmpdir="$(mktemp -d)"
  tmpdir="$(cd "$tmpdir" && pwd -P)"
  seed_project_dir "$tmpdir"

  # --- Fixture-specific setup ---

  case "$filename" in
    verify-symlink-resolution.json)
      # Create symlink: config/env -> .env
      mkdir -p "${tmpdir}/config"
      ln -s "../.env" "${tmpdir}/config/env"
      ;;
    ask-install-unlocked.json)
      # Needs a lockfile that doesn't contain the package (non-greenfield project)
      echo 'flask==2.3.0' > "${tmpdir}/requirements.txt"
      ;;
    alert-hook-config-tampered.json)
      # Seed session with posture hashes, then tamper hooks.json
      seed_session "$tmpdir" "false"
      echo '{}' > "${tmpdir}/.claude/hooks/hooks.json"  # tamper after hashing
      ;;
    alert-posture-direct-write.json)
      # Seed session with posture hashes, then tamper settings.json via "Bash"
      seed_session "$tmpdir" "false"
      echo '{"permissions":{"allow":["Bash(*)"]}}' > "${tmpdir}/.claude/settings.json"  # tamper
      ;;
    alert-sentinel-mutation.json)
      # Seed session with pending_install and pre-install sentinel hashes
      pre_hashes="{}"
      for sf in ".claude/hooks/hooks.json" "CLAUDE.md" ".env" ".mcp.json"; do
        if [[ -f "${tmpdir}/${sf}" ]]; then
          h="$(compute_file_hash "${tmpdir}/${sf}")"
          pre_hashes="$(echo "$pre_hashes" | jq --arg k "$sf" --arg v "$h" '. + {($k): $v}')"
        fi
      done
      pending_install="$(jq -n \
        --argjson sh "$pre_hashes" \
        '{command: "npm install express", manager: "npm", sentinel_hashes: $sh}')"
      seed_session "$tmpdir" "false" "false" "" "$pending_install"
      # Tamper hooks.json after seeding (simulate postinstall mutation)
      echo '{"hooks": []}' > "${tmpdir}/.claude/hooks/hooks.json"
      ;;
    *)
      # Default: just seed session with the right state
      seed_session "$tmpdir" "$secret_session"
      ;;
  esac

  # For fixtures that didn't get special-case seeding above, ensure session exists
  phash="$(project_hash "$tmpdir")"
  if [[ ! -f "${HOME}/.sir/projects/${phash}/session.json" ]]; then
    seed_session "$tmpdir" "$secret_session"
  fi

  # Build the payload to send to sir (strip _test_metadata)
  payload="$(jq 'del(._test_metadata)' "$fixture")"

  # Determine which sir guard subcommand to use
  if [[ "$hook_type" == "PostToolUse" ]]; then
    guard_cmd="post-evaluate"
  else
    guard_cmd="evaluate"
  fi

  # Run sir guard from the temp project directory, capturing stdout + stderr
  actual_output=""
  actual_exit_code=0

  actual_output="$(cd "$tmpdir" && echo "$payload" | "$SIR_BIN" guard "$guard_cmd" 2>&1)" || actual_exit_code=$?

  # Extract verdict from output
  actual_verdict="$(extract_verdict "$actual_output")"

  if $VERBOSE; then
    echo -e "  Exit code: ${actual_exit_code}"
    echo -e "  Verdict:   ${actual_verdict}"
    echo -e "  Output:    ${actual_output:0:200}"
  fi

  # Compare verdicts
  match=false
  if [[ "$actual_verdict" == "$expected_verdict" ]]; then
    match=true
  elif [[ "$expected_verdict" == "alert" ]] && [[ "$actual_verdict" == "deny" ]] && [[ "$session_fatal" == "true" ]]; then
    match=true  # session-fatal alerts result in deny-all
  elif [[ "$expected_verdict" == "deny" ]] && [[ "$actual_verdict" == "block" ]]; then
    match=true
  elif [[ "$expected_verdict" == "alert" ]] && [[ "$actual_verdict" == "allow" ]] && [[ "$hook_type" == "PostToolUse" ]]; then
    # PostToolUse alerts are logged but don't change the verdict
    # If the alert was logged to stderr, check for it
    if echo "$actual_output" | grep -qi "sentinel\|tamper\|mutation\|alert"; then
      match=true
    fi
  fi

  if $match; then
    PASSED=$((PASSED + 1))
    echo -e "  ${GREEN}PASS${RESET} ${filename}  (expected=${expected_verdict}, got=${actual_verdict})"
  else
    FAILED=$((FAILED + 1))
    echo -e "  ${RED}FAIL${RESET} ${filename}  (expected=${expected_verdict}, got=${actual_verdict})"
    FAILED_FIXTURES+=("${filename} (expected=${expected_verdict}, got=${actual_verdict})")
    if $VERBOSE; then
      echo -e "  Reason: ${expected_reason}"
      echo -e "  Raw output: ${actual_output:0:300}"
    fi
  fi

  # Cleanup
  cleanup_session "$tmpdir"
  rm -rf "$tmpdir"
done

echo ""
echo -e "${BOLD}Results${RESET}"
echo "==============================="
echo -e "  Total:   ${TOTAL}"
echo -e "  ${GREEN}Passed:  ${PASSED}${RESET}"
echo -e "  ${RED}Failed:  ${FAILED}${RESET}"
echo ""

if [[ ${#FAILED_FIXTURES[@]} -gt 0 ]]; then
  echo -e "${RED}Failed fixtures:${RESET}"
  for f in "${FAILED_FIXTURES[@]}"; do
    echo -e "  - ${f}"
  done
  echo ""
fi

# Exit code
if [[ $FAILED -gt 0 ]]; then
  exit 1
fi

echo -e "${GREEN}All tests passed.${RESET}"
exit 0
