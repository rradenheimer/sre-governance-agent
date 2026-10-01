#!/usr/bin/env python3
"""PostToolUse / Stop hook: append an immutable, hash-chained audit record.

Mirrors src/sre_governance/audit.py so the Claude agent's actions are recorded in
the SAME tamper-evident format the engine verifies (`cli verify-audit`). Runs
standalone — no dependency on the engine package — so it works in any governed
repo. Never raises; auditing must not break the agent.
"""
from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

AUDIT_PATH = Path(".sre/audit.jsonl")
GENESIS_HASH = "0" * 64


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _last_hash() -> str:
    if not AUDIT_PATH.exists():
        return GENESIS_HASH
    last = GENESIS_HASH
    for line in AUDIT_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                last = json.loads(line).get("hash", GENESIS_HASH)
            except Exception:
                pass
    return last


def _compute_hash(record: dict) -> str:
    payload = {k: v for k, v in record.items() if k != "hash"}
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def main() -> int:
    event = "session_stop" if "--event" in sys.argv else "tool_use"
    try:
        payload = json.load(sys.stdin)
    except Exception:
        payload = {}

    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {}) or {}
    target = tool_input.get("file_path") or tool_name or "-"

    record = {
        "ts": _now(),
        "actor": "claude-agent",
        "action": event if event == "session_stop" else f"tool:{tool_name}",
        "target": str(target),
        "outcome": "success",
        "details": {"session_id": payload.get("session_id", "")},
        "prev_hash": _last_hash(),
        "hash": "",
    }
    record["hash"] = _compute_hash(record)

    try:
        AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
        with AUDIT_PATH.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")
    except Exception:
        pass  # never break the agent on audit failure

    return 0


if __name__ == "__main__":
    sys.exit(main())
