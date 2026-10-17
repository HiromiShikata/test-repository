#!/usr/bin/env bash
# Proves .github/workflows/temp_create_issue_from_comment.yml's two run:
# steps that interpolate github.event.comment.body cannot be used for shell
# command injection, while the legitimate behaviour for a benign comment
# body stays unaffected (regression pin).
#
# Run with: bash scripts/temp-create-issue-from-comment-injection.test.sh
#
# Each case reads the real workflow file from disk at run time through
# temp-create-issue-from-comment-injection-helper.py (never a hardcoded copy
# of its script text), so the test stays coupled to the real file and would
# catch drift. The helper reproduces GitHub Actions' real two-tier `${{ }}`
# semantics: an expression occurring literally inside a step's run: text is
# spliced as raw text into the generated shell script (the vulnerable path
# when nothing redirects it through env:), while an expression occurring
# only inside the step's env: block is exported as a real process
# environment variable before the script runs (the safe path).
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
WORKFLOW_FILE="$REPO_ROOT/.github/workflows/temp_create_issue_from_comment.yml"
HELPER_PY="$SCRIPT_DIR/temp-create-issue-from-comment-injection-helper.py"

if [ ! -f "$WORKFLOW_FILE" ]; then
  echo "FAIL: workflow file not found at $WORKFLOW_FILE" >&2
  exit 1
fi
if [ ! -f "$HELPER_PY" ]; then
  echo "FAIL: helper script not found at $HELPER_PY" >&2
  exit 1
fi

pass_count=0
fail_count=0

# run_step_script <step-selector> <payload-file> <workdir> <lines: all|first> [capture-var]
#
# Extracts the named step's run: text with the payload substituted per the
# real two-tier semantics described above, then executes it in a real bash
# subprocess inside an isolated <workdir>. The subprocess's own exit code is
# deliberately not surfaced: the Update Date Field step's later lines make
# real network calls (curl to the GraphQL API) that are expected to fail in
# this sandbox for lack of a real token, and that failure must not prevent
# observing whether an earlier injected command already ran.
run_step_script() {
  local selector="$1" payload_file="$2" workdir="$3" lines="$4" capture_var="${5:-}"
  local script_file="$workdir/script.sh"
  local run_file="$workdir/to_run.sh"

  python3 "$HELPER_PY" build-script "$WORKFLOW_FILE" "$selector" "$payload_file" "$script_file"

  if [ "$lines" = "first" ]; then
    sed -n '1p' "$script_file" >"$run_file"
  else
    cp "$script_file" "$run_file"
  fi

  if [ -n "$capture_var" ]; then
    printf '\nprintf "%%s" "$%s" > "%s"\n' "$capture_var" "$workdir/captured_value.txt" >>"$run_file"
  fi

  local -a env_assignments=()
  while IFS= read -r env_name; do
    [ -z "$env_name" ] && continue
    env_assignments+=("$env_name")
  done < <(python3 "$HELPER_PY" env-names "$WORKFLOW_FILE" "$selector")

  local payload
  payload="$(cat "$payload_file")"

  (
    for env_name in "${env_assignments[@]}"; do
      export "$env_name=$payload"
    done
    cd "$workdir" && timeout 10 bash "$run_file" >"$workdir/stdout.txt" 2>"$workdir/stderr.txt"
  )
  return 0
}

assert_marker_not_created() {
  local case_name="$1" marker="$2"
  if [ -e "$marker" ]; then
    echo "FAIL: $case_name - injected command executed, marker file was created at $marker"
    fail_count=$((fail_count + 1))
  else
    echo "PASS: $case_name - injected command did not execute, marker file absent"
    pass_count=$((pass_count + 1))
  fi
}

assert_equal() {
  local case_name="$1" actual="$2" expected="$3"
  if [ "$actual" = "$expected" ]; then
    echo "PASS: $case_name - got expected value ${expected@Q}"
    pass_count=$((pass_count + 1))
  else
    echo "FAIL: $case_name - expected ${expected@Q}, got ${actual@Q}"
    fail_count=$((fail_count + 1))
  fi
}

# Table-driven cases: name|step-selector|check-mode
# check-mode "injection" proves a shell-metacharacter payload cannot run a
# command; "stdout"/"date" pin the legitimate behaviour for a benign body.
cases=(
  "echo_step_malicious_comment_body_is_not_executed|unnamed|injection"
  "echo_step_benign_comment_body_is_echoed_verbatim|unnamed|stdout"
  "date_step_malicious_comment_body_is_not_executed|Update Date Field|injection"
  "date_step_benign_date_is_extracted|Update Date Field|date"
)

for case_spec in "${cases[@]}"; do
  IFS='|' read -r case_name selector check_mode <<<"$case_spec"
  workdir="$(mktemp -d)"

  case "$check_mode" in
  injection)
    marker="$workdir/injected-marker"
    payload="foo\"; touch \"$marker\"; echo \""
    printf '%s' "$payload" >"$workdir/payload.txt"
    run_step_script "$selector" "$workdir/payload.txt" "$workdir" "all"
    assert_marker_not_created "$case_name" "$marker"
    ;;
  stdout)
    expected="benign comment body with no shell metacharacters"
    printf '%s' "$expected" >"$workdir/payload.txt"
    run_step_script "$selector" "$workdir/payload.txt" "$workdir" "all"
    actual="$(cat "$workdir/stdout.txt")"
    assert_equal "$case_name" "$actual" "$expected"
    ;;
  date)
    expected="20261225"
    printf '%s' "/movenextactiondateto 20261225" >"$workdir/payload.txt"
    run_step_script "$selector" "$workdir/payload.txt" "$workdir" "first" "DATE_STRING"
    actual="$(cat "$workdir/captured_value.txt")"
    assert_equal "$case_name" "$actual" "$expected"
    ;;
  *)
    echo "FAIL: $case_name - unknown check mode $check_mode"
    fail_count=$((fail_count + 1))
    ;;
  esac

  rm -rf "$workdir"
done

echo ""
echo "Results: $pass_count passed, $fail_count failed"
if [ "$fail_count" -ne 0 ]; then
  exit 1
fi
exit 0
