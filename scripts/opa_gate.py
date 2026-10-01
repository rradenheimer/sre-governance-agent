#!/usr/bin/env python3
"""Local policy-as-code gate runner for the SRE Governance Agent.

Evaluates a governance JSON report against policies/opa/repo_governance.rego.

It prefers real OPA tooling and gracefully falls back to a pure-Python evaluator
so the gate ALWAYS runs, even on machines without `conftest`/`opa` installed:

  1. `conftest test <report> --policy policies/opa --namespace sre.governance`
  2. `opa eval` against the rego + report
  3. Built-in Python evaluator that mirrors the Rego deny/warn rules

Exit code: 1 if any deny triggers (gate fails), else 0. `warn` never fails.

Usage:
  python scripts/opa_gate.py --report sre-reports/sre-governance-report.json
  python scripts/opa_gate.py --report r.json --engine python   # force fallback
  python scripts/opa_gate.py --report r.json --warn-as-error    # strict mode
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POLICY_DIR = ROOT / "policies" / "opa"
NAMESPACE = "sre.governance"


# --------------------------------------------------------------------------
# Pure-Python mirror of repo_governance.rego (deny/warn). Keep in lock-step
# with the Rego; policies/opa/tests and tests/test_opa_gate.py guard this.
# --------------------------------------------------------------------------
def evaluate_python(report: dict) -> tuple[list[str], list[str]]:
    deny: list[str] = []
    warn: list[str] = []
    gate = report.get("gate", {})
    results = report.get("results", [])

    # deny: honor the engine's blocking decision
    if gate.get("should_fail_pipeline") is True:
        for reason in gate.get("reasons", []):
            deny.append(f"policy gate failed: {reason}")

    # deny: no mandatory CRITICAL control may fail
    for r in results:
        if r.get("status") == "FAIL" and r.get("applicability") == "mandatory" and r.get("severity") == "critical":
            deny.append(f"mandatory CRITICAL control failed: {r.get('control_id')} â€” {r.get('reason')}")

    # deny: audit integrity control must pass everywhere
    for r in results:
        if r.get("control_id") == "CMP-AUDIT-033" and r.get("status") == "FAIL":
            deny.append("audit logging control CMP-AUDIT-033 must pass: enable governance.audit_logging")

    # warn: mandatory HIGH failures
    for r in results:
        if r.get("status") == "FAIL" and r.get("applicability") == "mandatory" and r.get("severity") == "high":
            warn.append(f"mandatory HIGH control failed: {r.get('control_id')} â€” {r.get('remediation')}")

    return deny, warn


def _find_binary(name: str) -> str | None:
    """Locate a real executable, ignoring same-named scripts in the cwd.

    On Windows, PATHEXT can include .PY, so shutil.which("conftest") may match a
    local conftest.py. Only accept binary extensions / extension-less matches.
    """
    found = shutil.which(name)
    if not found:
        return None
    suffix = Path(found).suffix.lower()
    if suffix in (".py", ".pyc", ".pyw"):
        return None
    return found


def run_conftest(report_path: Path) -> tuple[list[str], list[str]] | None:
    binary = _find_binary("conftest")
    if not binary:
        return None
    try:
        proc = subprocess.run(
            [binary, "test", str(report_path), "--policy", str(POLICY_DIR),
             "--namespace", NAMESPACE, "--output", "json"],
            capture_output=True, text=True,
        )
    except (FileNotFoundError, OSError):
        return None
    try:
        data = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError:
        print(proc.stdout, proc.stderr, file=sys.stderr)
        return None
    deny, warn = [], []
    for block in data:
        for f in block.get("failures", []):
            deny.append(f.get("msg", "deny"))
        for w in block.get("warnings", []):
            warn.append(w.get("msg", "warn"))
    return deny, warn


def run_opa(report_path: Path) -> tuple[list[str], list[str]] | None:
    binary = _find_binary("opa")
    if not binary:
        return None
    out = {}
    for rule in ("deny", "warn"):
        try:
            proc = subprocess.run(
                [binary, "eval", "--format", "raw", "--data", str(POLICY_DIR),
                 "--input", str(report_path), f"data.{NAMESPACE}.{rule}"],
                capture_output=True, text=True,
            )
        except (FileNotFoundError, OSError):
            return None
        if proc.returncode != 0:
            print(proc.stderr, file=sys.stderr)
            return None
        try:
            out[rule] = json.loads(proc.stdout or "[]")
        except json.JSONDecodeError:
            out[rule] = []
    return list(out.get("deny", [])), list(out.get("warn", []))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="SRE Governance OPA/Rego gate runner")
    ap.add_argument("--report", required=True, help="Path to the governance JSON report")
    ap.add_argument("--engine", choices=["auto", "conftest", "opa", "python"], default="auto")
    ap.add_argument("--warn-as-error", action="store_true", help="Treat warnings as gate failures")
    args = ap.parse_args(argv)

    report_path = Path(args.report)
    if not report_path.is_file():
        print(f"ERROR: report not found: {report_path}", file=sys.stderr)
        return 2
    report = json.loads(report_path.read_text(encoding="utf-8"))

    result = None
    used = "python"
    if args.engine in ("auto", "conftest"):
        result = run_conftest(report_path)
        if result is not None:
            used = "conftest"
    if result is None and args.engine in ("auto", "opa"):
        result = run_opa(report_path)
        if result is not None:
            used = "opa"
    if result is None:
        result = evaluate_python(report)
        used = "python (fallback)"

    deny, warn = result
    print(f"OPA gate engine: {used}")
    print(f"Report:          {report_path}  (profile={report.get('profile')}, score={report.get('score')})")
    print("-" * 68)
    if deny:
        print("DENY:")
        for m in deny:
            print(f"  [X] {m}")
    if warn:
        print("WARN:")
        for m in warn:
            print(f"  [!] {m}")
    if not deny and not warn:
        print("[OK] No policy violations.")

    failed = bool(deny) or (args.warn_as_error and bool(warn))
    print("-" * 68)
    print("RESULT:", "FAIL" if failed else "PASS")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())

