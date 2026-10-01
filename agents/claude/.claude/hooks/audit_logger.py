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
AUDIT_HEAD_PATH = Path(".sre/audit.jsonl.head")
GENESIS_HASH = "0" * 64


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _last_hash() -> str:
    if not AUDIT_PATH.exists():
        if AUDIT_HEAD_PATH.exists():
            raise ValueError("audit head anchor exists without an audit log")
        return GENESIS_HASH
    lines = [line.strip() for line in AUDIT_PATH.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not lines:
        raise ValueError("audit log is empty")
    previous = GENESIS_HASH
    record = None
    required = {"ts", "actor", "action", "target", "outcome", "details", "prev_hash", "hash"}
    for index, line in enumerate(lines, 1):
        record = json.loads(line)
        if not isinstance(record, dict) or set(record) != required:
            raise ValueError(f"malformed audit record {index}")
        if record["prev_hash"] != previous or record["hash"] != _compute_hash(record):
            raise ValueError(f"broken audit chain at record {index}")
        previous = record["hash"]
    if not AUDIT_HEAD_PATH.exists():
        raise ValueError("audit head anchor is missing")
    anchor = json.loads(AUDIT_HEAD_PATH.read_text(encoding="utf-8"))
    if not isinstance(anchor, dict) or anchor.get("record_count") != len(lines) \
            or anchor.get("head_hash") != previous:
        raise ValueError("audit head anchor does not match the log")
    return previous


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
    target = tool_input.get("file_path") or tool_input.get("command", "")[:120] or "-"

    try:
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
        AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
        with AUDIT_PATH.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")
        lines = [line for line in AUDIT_PATH.read_text(encoding="utf-8").splitlines() if line.strip()]
        AUDIT_HEAD_PATH.write_text(
            json.dumps({"record_count": len(lines), "head_hash": record["hash"]}, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except Exception as exc:
        print(f"ERROR: failed to write audit record: {exc}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
