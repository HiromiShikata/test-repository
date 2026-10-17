#!/usr/bin/env python3
"""Helper for scripts/temp-create-issue-from-comment-injection.test.sh.

Reads the live .github/workflows/temp_create_issue_from_comment.yml at test
run time (never a hardcoded copy) and reproduces GitHub Actions' real
two-tier `${{ }}` substitution semantics for one step:

  - `${{ github.event.comment.body }}` (flexible whitespace inside the
    braces) occurring literally inside the step's `run:` text is spliced as
    raw, unescaped text into the generated shell script before the shell
    ever runs it. This is the vulnerable path when nothing redirects the
    expression through `env:`.
  - The same expression occurring only inside the step's `env:` block is,
    instead, exported as a real process environment variable and never
    spliced into the script text. This is the safe path.

This module does not implement a general GitHub Actions expression
evaluator. Every other `${{ ... }}` expression (github.repository,
secrets.GH_TOKEN, env.project_v2_id, ...) is unrelated to the one
attacker-controlled input in scope for this test and is replaced with a
fixed inert placeholder so the extracted script stays syntactically valid
shell.
"""
import re
import sys

import yaml

COMMENT_BODY_EXPR = re.compile(r"\$\{\{\s*github\.event\.comment\.body\s*\}\}")
ANY_EXPR = re.compile(r"\$\{\{[^}]*\}\}")
COMMENT_BODY_ENV_VALUE = re.compile(
    r"^\s*\$\{\{\s*github\.event\.comment\.body\s*\}\}\s*$"
)


def find_step(workflow_path, selector):
    with open(workflow_path, "r", encoding="utf-8") as handle:
        workflow = yaml.safe_load(handle)
    for job in workflow["jobs"].values():
        for step in job["steps"]:
            if selector == "unnamed":
                if "name" not in step:
                    return step
            elif step.get("name") == selector:
                return step
    raise SystemExit(f"step not found for selector {selector!r}")


def command_env_names(workflow_path, selector):
    step = find_step(workflow_path, selector)
    names = []
    for name, value in (step.get("env") or {}).items():
        if isinstance(value, str) and COMMENT_BODY_ENV_VALUE.match(value):
            names.append(name)
    return names


def build_script(workflow_path, selector, payload_path, out_path):
    step = find_step(workflow_path, selector)
    run_text = step.get("run")
    if run_text is None:
        raise SystemExit(f"step {selector!r} has no run: field")
    with open(payload_path, "r", encoding="utf-8") as handle:
        payload = handle.read()
    # Replacement is a function, not a string, so backslashes or other
    # characters in the attacker-controlled payload are never reinterpreted
    # as re.sub backreference syntax: the payload lands byte-for-byte.
    substituted = COMMENT_BODY_EXPR.sub(lambda _match: payload, run_text)
    substituted = ANY_EXPR.sub("DUMMYVALUE", substituted)
    with open(out_path, "w", encoding="utf-8") as handle:
        handle.write(substituted)


def main(argv):
    command = argv[1]
    if command == "env-names":
        _, _, workflow_path, selector = argv
        for name in command_env_names(workflow_path, selector):
            print(name)
    elif command == "build-script":
        _, _, workflow_path, selector, payload_path, out_path = argv
        build_script(workflow_path, selector, payload_path, out_path)
    else:
        raise SystemExit(f"unknown command {command!r}")


if __name__ == "__main__":
    main(sys.argv)
