"""Audit logging and provenance for transparent, attributable automation.

Every action the agent takes (scan, report, proposed remediation) is appended to
an immutable, hash-chained JSONL audit log. Each record embeds the SHA-256 of the
previous record, so any tampering breaks the chain. This satisfies the
CMP-AUDIT-033 control and NIST AU-2/AU-3/AU-12 expectations.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS_HASH = "0" * 64


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class AuditEvent:
    ts: str
    actor: str                 # e.g. "copilot-agent", "claude-agent", "ci"
    action: str                # scan | report | propose_remediation | approve | block
    target: str                # repo / control id / file
    outcome: str               # success | blocked | error
    details: dict[str, Any] = field(default_factory=dict)
    prev_hash: str = GENESIS_HASH
    hash: str = ""

    def compute_hash(self) -> str:
        payload = {k: v for k, v in asdict(self).items() if k != "hash"}
        blob = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()


class AuditLogger:
    def __init__(self, path: str | Path, actor: str = "sre-governance-agent"):
        self.path = Path(path)
        self.anchor_path = self.path.with_suffix(self.path.suffix + ".head")
        self.actor = actor
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _last_hash(self) -> str:
        if not self.path.exists():
            return GENESIS_HASH
        last = GENESIS_HASH
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                last = json.loads(line).get("hash", GENESIS_HASH)
        return last

    def record(self, action: str, target: str, outcome: str = "success", **details: Any) -> AuditEvent:
        event = AuditEvent(
            ts=_now(), actor=self.actor, action=action, target=target,
            outcome=outcome, details=details, prev_hash=self._last_hash(),
        )
        event.hash = event.compute_hash()
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(asdict(event), sort_keys=True) + "\n")
        self._write_anchor()
        return event

    def _write_anchor(self) -> None:
        lines = [line.strip() for line in self.path.read_text(encoding="utf-8").splitlines() if line.strip()]
        head_hash = json.loads(lines[-1])["hash"]
        anchor = {"record_count": len(lines), "head_hash": head_hash}
        self.anchor_path.write_text(json.dumps(anchor, sort_keys=True) + "\n", encoding="utf-8")

    def verify(self) -> tuple[bool, str]:
        """Verify the hash chain. Returns (ok, message)."""
        if not self.path.exists():
            return False, "audit log is missing"
        try:
            log_text = self.path.read_text(encoding="utf-8")
        except OSError:
            return False, "audit log is unreadable"
        anchor_text = None
        if self.anchor_path.exists():
            try:
                anchor_text = self.anchor_path.read_text(encoding="utf-8")
            except OSError:
                return False, "audit head anchor is invalid"
        return verify_audit_contents(log_text, anchor_text)


def verify_audit_contents(log_text: str | None, anchor_text: str | None) -> tuple[bool, str]:
    if log_text is None:
        return False, "audit log is missing"
    lines = [line.strip() for line in log_text.splitlines() if line.strip()]
    if not lines:
        return False, "audit log is empty"
    prev = GENESIS_HASH
    for i, line in enumerate(lines, 1):
        try:
            rec = json.loads(line)
            if not isinstance(rec, dict):
                return False, f"malformed audit record {i}"
            stored = rec.get("hash", "")
            event = AuditEvent(**{k: v for k, v in rec.items() if k != "hash"})
            if rec.get("prev_hash") != prev:
                return False, f"broken chain at record {i}: prev_hash mismatch"
            if event.compute_hash() != stored:
                return False, f"tampered record {i}: hash mismatch"
            prev = stored
        except (json.JSONDecodeError, TypeError, ValueError, AttributeError, KeyError):
            return False, f"malformed audit record {i}"
    if anchor_text is None:
        return False, "audit head anchor is missing"
    try:
        anchor = json.loads(anchor_text)
    except (OSError, json.JSONDecodeError):
        return False, "audit head anchor is invalid"
    if not isinstance(anchor, dict):
        return False, "audit head anchor is invalid"
    if anchor.get("record_count") != len(lines) or anchor.get("head_hash") != prev:
        return False, "audit log does not match its anchored head"
    return True, "audit chain intact"


def provenance(profile: str, catalog_version: str, score: float) -> dict[str, Any]:
    """Lightweight attestation describing how a report was produced."""
    return {
        "generator": "sre-governance-agent",
        "generated_at": _now(),
        "profile": profile,
        "catalog_version": catalog_version,
        "compliance_score": score,
        "runtime": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "ci": bool(os.environ.get("CI")),
        },
    }
