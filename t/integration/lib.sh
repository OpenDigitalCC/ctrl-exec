#!/bin/bash
# lib.sh - shared functions for ctrl-exec integration tests
#
# Source this file at the top of each test script:
#   source "$(dirname "$0")/lib.sh"
#
# Agent discovery:
#   Agents are discovered from "ctrl-exec-dispatcher list-agents" at startup.
#   No hostnames are hardcoded here or in any test file.
#
# Exported arrays (populated by discover_agents, called from run-tests.sh):
#   AGENTS        all reachable agents at suite start
#   AGENT1        first reachable agent  (or empty)
#   AGENT2        second reachable agent (or empty)
#
# Each test script calls require_agents <n> near the top to skip the
# entire file if fewer than n agents are reachable.

DISPATCHER="${DISPATCHER:-ctrl-exec-dispatcher}"
_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- counters ---

_PASS=0
_FAIL=0
_SKIP=0
_TEST_NAME=""

# --- output helpers ---

_green()  { printf '\033[32m%s\033[0m\n' "$*"; }
_red()    { printf '\033[31m%s\033[0m\n' "$*"; }
_yellow() { printf '\033[33m%s\033[0m\n' "$*"; }
_bold()   { printf '\033[1m%s\033[0m\n'  "$*"; }

describe() {
    _TEST_NAME="$*"
    printf '\n'
    _bold "--- $* ---"
}

pass() {
    _PASS=$((_PASS + 1))
    _green "  PASS: ${1:-$_TEST_NAME}"
}

fail() {
    _FAIL=$((_FAIL + 1))
    _red   "  FAIL: ${1:-$_TEST_NAME}"
    if [ -n "${2:-}" ]; then
        printf '        %s\n' "$2"
    fi
}

skip() {
    _SKIP=$((_SKIP + 1))
    _yellow "  SKIP: ${1:-$_TEST_NAME}"
    if [ -n "${2:-}" ]; then
        printf '        %s\n' "$2"
    fi
}

summary() {
    printf '\n'
    _bold "Results: $_PASS passed, $_FAIL failed, $_SKIP skipped"
    if [ "$_FAIL" -gt 0 ]; then
        return 1
    fi
    return 0
}

# _list_agent_hostnames: extract hostnames from "ctrl-exec-dispatcher list-agents" output.
# Skips the header and separator lines.
_list_agent_hostnames() {
    sudo "$DISPATCHER" list-agents 2>/dev/null \
        | awk 'NR > 2 && /^[A-Za-z0-9]/ { print $1 }'
}

# _ping_agent <hostname>: returns 0 if agent responds to ctrl-exec-dispatcher ping.
_ping_agent() {
    local agent="$1"
    sudo "$DISPATCHER" ping "$agent" > /dev/null 2>&1
}

# discover_agents: ping all registered agents, populate AGENTS, AGENT1, AGENT2.
# Called once by run-tests.sh before any test file runs.
# Also called automatically when AGENT1 is unset (standalone test execution).
# Exports results so sourced test scripts inherit them.
discover_agents() {
    printf 'Discovering agents from ctrl-exec-dispatcher list-agents...\n'

    local all_agents=()
    while IFS= read -r hostname; do
        [ -n "$hostname" ] && all_agents+=("$hostname")
    done < <(_list_agent_hostnames)

    if [ "${#all_agents[@]}" -eq 0 ]; then
        printf 'ERROR: No agents registered. Run "ctrl-exec-dispatcher list-agents" to check.\n' >&2
        exit 1
    fi

    printf 'Registered agents: %s\n' "${all_agents[*]}"
    printf 'Pinging to confirm reachability...\n'

    AGENTS=()
    for agent in "${all_agents[@]}"; do
        if _ping_agent "$agent"; then
            AGENTS+=("$agent")
            printf '  %-30s  reachable\n' "$agent"
        else
            printf '  %-30s  UNREACHABLE - excluded\n' "$agent"
        fi
    done

    AGENT1="${AGENTS[0]:-}"
    AGENT2="${AGENTS[1]:-}"

    export AGENT1 AGENT2 DISPATCHER

    printf '\n%d of %d agents reachable: %s\n\n' \
        "${#AGENTS[@]}" "${#all_agents[@]}" "${AGENTS[*]:-none}"
}

# require_agents <n>: skip this test file entirely if fewer than n agents
# are reachable. Call at the top of each test script after sourcing lib.sh.
require_agents() {
    local needed="$1"
    local available="${#AGENTS[@]}"
    if [ "$available" -lt "$needed" ]; then
        _yellow "SKIP: this test requires $needed reachable agent(s), only $available available"
        exit 0
    fi
}

# check_agents_still_reachable: ping all AGENTS, populate AGENTS_LOST.
# Returns 0 if all still reachable, 1 if any have gone away.
check_agents_still_reachable() {
    AGENTS_LOST=()
    for agent in "${AGENTS[@]}"; do
        if ! _ping_agent "$agent"; then
            AGENTS_LOST+=("$agent")
        fi
    done
    export AGENTS_LOST
    [ "${#AGENTS_LOST[@]}" -eq 0 ]
}

# assert_agents_reachable: call before any describe block that dispatches to
# live agents. If any have gone away since the suite started, reports the loss
# and prompts whether to continue with the remaining agents.
# In non-interactive mode, stops immediately.
assert_agents_reachable() {
    if ! check_agents_still_reachable; then
        printf '\n'
        _red "WARNING: agent(s) no longer reachable: ${AGENTS_LOST[*]}"
        printf '\n'

        if [ -t 0 ]; then
            printf 'Continue testing with remaining agents? [y/N] '
            read -r answer
            if [[ ! "$answer" =~ ^[Yy] ]]; then
                printf 'Stopping at user request.\n'
                summary
                exit 1
            fi
        else
            printf 'Non-interactive mode - stopping on agent loss.\n'
            summary
            exit 1
        fi

        # Rebuild AGENTS without the lost ones
        local remaining=()
        for agent in "${AGENTS[@]}"; do
            local lost=0
            for gone in "${AGENTS_LOST[@]}"; do
                [ "$agent" = "$gone" ] && lost=1
            done
            [ "$lost" -eq 0 ] && remaining+=("$agent")
        done
        AGENTS=("${remaining[@]}")
        AGENT1="${AGENTS[0]:-}"
        AGENT2="${AGENTS[1]:-}"
        export AGENTS AGENT1 AGENT2

        if [ "${#AGENTS[@]}" -eq 0 ]; then
            printf 'No agents remaining. Stopping.\n'
            summary
            exit 1
        fi
        printf 'Continuing with: %s\n' "${AGENTS[*]}"
    fi
}

# --- assertion helpers ---

# assert_exit <expected> <actual> <label>
assert_exit() {
    local expected="$1" actual="$2" label="${3:-exit code}"
    if [ "$actual" -eq "$expected" ]; then
        pass "$label (exit $actual)"
    else
        fail "$label" "expected exit $expected, got $actual"
    fi
}

# assert_contains <string> <substring> <label>
assert_contains() {
    local haystack="$1" needle="$2" label="${3:-contains}"
    if echo "$haystack" | grep -qF "$needle"; then
        pass "$label"
    else
        fail "$label" "expected to contain: $needle"
        printf '        actual output: %s\n' "$(echo "$haystack" | head -5)"
    fi
}

# assert_not_contains <string> <substring> <label>
assert_not_contains() {
    local haystack="$1" needle="$2" label="${3:-not contains}"
    if echo "$haystack" | grep -qF "$needle"; then
        fail "$label" "expected NOT to contain: $needle"
    else
        pass "$label"
    fi
}

# assert_json_field <json> <field> <expected_value> <label>
# Extracts a top-level string or number field using grep/sed only (no jq).
assert_json_field() {
    local json="$1" field="$2" expected="$3" label="${4:-json field $field}"
    local actual
    actual=$(echo "$json" | grep -o "\"${field}\":[^,}]*" | head -1 \
        | sed 's/^"[^"]*":[[:space:]]*//' \
        | sed 's/^"\(.*\)"$/\1/' \
        | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    if [ "$actual" = "$expected" ]; then
        pass "$label"
    else
        fail "$label" "expected '$expected', got '$actual'"
    fi
}

# assert_json_valid <json> <label>
assert_json_valid() {
    local json="$1" label="${2:-valid JSON}"
    if python3 -c "import sys,json; json.load(sys.stdin)" <<< "$json" 2>/dev/null; then
        pass "$label"
    else
        fail "$label" "output is not valid JSON"
        printf '        output: %s\n' "$(echo "$json" | head -3)"
    fi
}

# --- connection tracking ---
#
# _CONN_TOTAL counts every run_dispatcher call across the entire suite run.
# _CONN_AGENT_<name> counts calls to each specific agent (name with non-
# alphanumerics replaced by underscores).
# _FAIL_STREAK counts consecutive run_dispatcher calls where the output
# contained "no response from child" - the signature of a rate-block.
# These are exported so run-tests.sh can report them in the summary.

_CONN_TOTAL=0
_FAIL_STREAK=0
_FAIL_STREAK_START=0   # _CONN_TOTAL value when the streak began

_conn_key() {
    # Produce a shell-safe variable name suffix from an agent hostname.
    printf '%s' "$1" | tr -c 'A-Za-z0-9' '_'
}

_conn_increment() {
    local agent="$1"
    _CONN_TOTAL=$((_CONN_TOTAL + 1))
    local key="_CONN_AGENT_$(_conn_key "$agent")"
    local cur="${!key:-0}"
    printf -v "$key" '%d' $(( cur + 1 ))
    export "$key"
}

_conn_for_agent() {
    local key="_CONN_AGENT_$(_conn_key "$1")"
    printf '%d' "${!key:-0}"
}

# _check_rate_warning: called after every run_dispatcher invocation.
# Inspects OUT for the "no response from child" signature. If the failure
# streak grows beyond 2 consecutive calls, prints a rate-limit warning
# once per streak start so the output is not flooded.
_check_rate_warning() {
    if echo "${OUT:-}" | grep -qF "no response from child"; then
        if [ "$_FAIL_STREAK" -eq 0 ]; then
            _FAIL_STREAK_START="$_CONN_TOTAL"
        fi
        _FAIL_STREAK=$((_FAIL_STREAK + 1))
        if [ "$_FAIL_STREAK" -eq 3 ]; then
            printf '\n'
            _yellow "  WARNING: 3 consecutive \"no response from child\" errors"
            _yellow "  (started at connection $_FAIL_STREAK_START of $_CONN_TOTAL total)"
            _yellow "  This is consistent with agent rate-limiting blocking the ctrl-exec IP."
            _yellow "  Set 'disable_rate_limit = 1' in agent.conf and reload, then re-run."
            printf '\n'
        fi
    else
        _FAIL_STREAK=0
    fi
}

export _CONN_TOTAL _FAIL_STREAK _FAIL_STREAK_START

# run_dispatcher <args...> - runs ctrl-exec, sets OUT, ERR, RC
# Passes ENVEXEC_TOKEN explicitly so sudo does not strip it.
# Tracks per-agent and total connection counts; detects rate-limit signatures.
run_dispatcher() {
    local token_env=""
    if [ -n "${ENVEXEC_TOKEN:-}" ]; then
        token_env="ENVEXEC_TOKEN=${ENVEXEC_TOKEN}"
    fi

    # Extract the agent name from the argument list for per-agent counting.
    # Argument pattern is: run_dispatcher <verb> <agent> [...]
    #                   or: run_dispatcher ping <agent> [...]
    # The agent is always $2 in the arg list passed to this function.
    local _verb="${1:-}" _agent="${2:-}"
    if [ -n "$_agent" ] && [ "$_verb" != "--json" ]; then
        _conn_increment "$_agent"
    fi

    OUT=$(sudo env $token_env "$DISPATCHER" "$@" 2>/tmp/_disp_err); RC=$?
    ERR=$(cat /tmp/_disp_err)

    _check_rate_warning
}

# elapsed_seconds <start_seconds>
elapsed_seconds() {
    echo $(( $(date +%s) - $1 ))
}

# --- agent discovery and reachability ---

# Auto-discover if running standalone (AGENT1 not set by parent runner).
# Placed at end of file so all helper functions are defined before this runs.
if [ -z "${AGENT1:-}" ]; then
    discover_agents
fi