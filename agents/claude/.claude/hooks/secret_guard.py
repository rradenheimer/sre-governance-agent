#!/usr/bin/env python3
"""PreToolUse hook: block secret leakage and tampering with the audit log.

Claude Code invokes this before Bash/Edit/Write/MultiEdit tool calls, passing a
JSON payload on stdin. Exit code 2 blocks the tool call and returns the message
(on stderr) to the agent so it can self-correct. Exit 0 allows the call.

This is a transparency/safety guardrail that works for every industry profile.
"""
from __future__ import annotations

import json
import re
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
    r"git\s+push\s+(--force|-f)\b",
    r"\bgh\s+pr\s+(merge|review\s+--approve)\b",
    r"rm\s+-rf\s+/(?!\w)",
]

SENSITIVE_PATH_PATTERNS = [
    r"(?i)(?<![\w])\.env(?:\.[\w.-]+)?(?![\w])",
    r"(?i)(?<![\w])(?:\.ssh|\.aws)(?:[/\\][\w./\\-]+)?",
    r"(?i)(?<![\w])id_(?:rsa|ed25519)[\w.-]*",
    r"(?i)(?<![\w])\.git-credentials(?![\w])",
    r"(?i)(?<![\w])[\w.-]+\.(?:pem|key|p12|pfx)(?![\w])",
    r"(?i)(?<![\w])(?:secrets?|credentials?)(?:[/\\][\w./\\-]+|[._-](?:ya?ml|json|toml|txt))",
]

PROTECTED_WRITE = (".sre/audit.jsonl", ".sre/audit.jsonl.head")


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
        return 0  # fail-open on malformed payloads; never crash the agent

    tool_input = payload.get("tool_input", {}) or {}
    target = tool_input.get("file_path", "") or ""
    blob = _blob(tool_input)

    if any(target.replace("\\", "/").endswith(p) for p in PROTECTED_WRITE):
        print("BLOCKED: the audit log (.sre/audit.jsonl) is append-only and may "
              "not be edited by the agent.", file=sys.stderr)
        return 2

    for pat in FORBIDDEN_CMD:
        if re.search(pat, blob):
            print(f"BLOCKED: forbidden command pattern /{pat}/. Changes must land "
                  "via reviewed pull request; never force-push or self-merge.",
                  file=sys.stderr)
            return 2

    if payload.get("tool_name") == "Bash" and any(
        re.search(pat, blob) for pat in SENSITIVE_PATH_PATTERNS
    ):
        print("BLOCKED: Bash commands may not access sensitive credential paths. "
              "Use the approved secret manager instead.", file=sys.stderr)
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
