#!/usr/bin/env python3
"""PreToolUse hook: block secret leakage and tampering with the audit log.

Claude Code invokes this before Bash/Edit/Write/MultiEdit tool calls, passing a
JSON payload on stdin. Exit code 2 blocks the tool call and returns the message
(on stderr) to the agent so it can self-correct. Exit 0 allows the call.

This is a transparency/safety guardrail that works for every industry profile.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import sys

# High-signal secret patterns. Deliberately conservative to avoid false blocks.
SECRET_PATTERNS = [
    r"AKIA[0-9A-Z]{16}",                         # AWS access key id
    r"(?i)aws_secret_access_key\s*=\s*\S+",      # AWS secret
    r"ghp_[A-Za-z0-9]{36}",                      # GitHub PAT
    r"github_pat_[A-Za-z0-9_]{22,}",             # GitHub fine-grained PAT
    r"xox[baprs]-[A-Za-z0-9-]{10,}",             # Slack token
    r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
    r"(?i)(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*[\"']?[A-Za-z0-9/\+=_\-]{12,}",
]

# Commands that are never allowed from the agent.
FORBIDDEN_CMD = [
    r"\bgh\s+pr\s+(merge|review\s+--approve)\b",
    r"rm\s+-rf\s+/(?!\w)",
]

PROTECTED_WRITE = (".sre/audit.jsonl",)
READ_ONLY_AUDIT_COMMANDS = {"cat", "diff", "file", "grep", "head", "less",
                            "sha256sum", "stat", "tail", "wc"}


def _shell_tokens(command: str) -> list[str]:
    lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|<>")
    lexer.whitespace_split = True
    lexer.commenters = ""
    return list(lexer)


def _is_force_push(command: str) -> bool:
    try:
        tokens = _shell_tokens(command)
    except ValueError:
        return False

    separators = {";", "&&", "||", "|", "&"}
    for index, token in enumerate(tokens):
        if os.path.basename(token) != "git":
            continue

        command_index = index + 1
        while command_index < len(tokens) and tokens[command_index] not in separators:
            option = tokens[command_index]
            if option == "push":
                args = []
                for arg in tokens[command_index + 1:]:
                    if arg in separators:
                        break
                    args.append(arg)
                if any(arg in {"--force", "--force-with-lease", "--force-if-includes", "-f"}
                       or arg.startswith(("--force=", "--force-with-lease="))
                       or (not arg.startswith("-") and arg.startswith("+"))
                       for arg in args):
                    return True
                break
            if option.startswith("-"):
                command_index += 2 if option in {"-C", "-c", "--git-dir",
                                                 "--work-tree", "--namespace"} else 1
            else:
                break
    return False


def _references_protected_audit(command: str) -> bool:
    normalized = command.replace("\\", "/")
    return any(
        re.search(
            rf"(?:^|[\s\"'=])(?:[^\s\"';|&<>]*/)?{re.escape(path)}(?=$|[\s\"';|&<>])",
            normalized,
        )
        for path in PROTECTED_WRITE
    )


def _is_read_only_audit_command(command: str) -> bool:
    try:
        tokens = _shell_tokens(command)
    except ValueError:
        return False
    if any(token in {";", "&&", "||", "|", "&", ">", ">>", ">|", "&>", "<"}
           for token in tokens):
        return False

    index = 0
    while index < len(tokens) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", tokens[index]):
        index += 1
    args = tokens[index:]
    if len(args) >= 4 and os.path.basename(args[0]) in {"python", "python3"}:
        if args[1:4] == ["-m", "sre_governance.cli", "verify-audit"]:
            return True
    return bool(args and os.path.basename(args[0]) in READ_ONLY_AUDIT_COMMANDS)


def _bash_mutates_protected_audit(command: str) -> bool:
    return (_references_protected_audit(command)
            and not _is_read_only_audit_command(command))


def _blob(tool_input: dict) -> str:
    parts = []
    for key in ("command", "content", "new_string", "file_text"):
        v = tool_input.get(key)
        if isinstance(v, str):
            parts.append(v)
    return "\n".join(parts)


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except Exception:
        print("BLOCKED: unable to parse hook input; secret and audit-path checks "
              "were not performed.", file=sys.stderr)
        return 2

    if (not isinstance(payload, dict)
            or not isinstance(payload.get("tool_name"), str)
            or not payload.get("tool_name")
            or not isinstance(payload.get("tool_input"), dict)):
        print("BLOCKED: malformed hook input; secret and audit-path checks "
              "were not performed.", file=sys.stderr)
        return 2

    tool_input = payload.get("tool_input", {}) or {}
    target = tool_input.get("file_path", "") or ""
    blob = _blob(tool_input)

    if any(target.replace("\\", "/").endswith(p) for p in PROTECTED_WRITE):
        print("BLOCKED: the audit log (.sre/audit.jsonl) is append-only and may "
              "not be edited by the agent.", file=sys.stderr)
        return 2

    command = tool_input.get("command")
    if isinstance(command, str) and _bash_mutates_protected_audit(command):
        print("BLOCKED: Bash commands may not modify the append-only audit log "
              "(.sre/audit.jsonl).", file=sys.stderr)
        return 2

    if isinstance(command, str) and _is_force_push(command):
        print("BLOCKED: changes must land via reviewed pull request; "
              "never force-push.", file=sys.stderr)
        return 2

    for pat in FORBIDDEN_CMD:
        if re.search(pat, blob):
            print(f"BLOCKED: forbidden command pattern /{pat}/. Changes must land "
                  "via reviewed pull request; never force-push or self-merge.",
                  file=sys.stderr)
            return 2

    for pat in SECRET_PATTERNS:
        if re.search(pat, blob):
            print("BLOCKED: content appears to contain a secret/credential. "
                  "Never write or transmit secrets. Use a secret manager and "
                  "reference values indirectly.", file=sys.stderr)
            return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
