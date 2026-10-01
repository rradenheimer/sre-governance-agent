"""Deterministic evaluation engine.

Given a RepoScan, a Catalog, and a Profile, produce per-control Results and an
overall Assessment (score + policy gate). No AI, no network, no randomness.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable

from sre_governance.catalog import Catalog, Control, Profile
from sre_governance.scanner import RepoScan, keyword_in_workflows

PASS = "PASS"
FAIL = "FAIL"
NA = "NOT_APPLICABLE"

SEVERITY_WEIGHT = {"critical": 10, "high": 6, "medium": 3, "low": 1}


@dataclass(frozen=True)
class Result:
    control_id: str
    title: str
    category: str
    severity: str
    status: str                  # PASS | FAIL | NOT_APPLICABLE
    applicability: str           # mandatory | recommended | not_applicable
    reason: str
    remediation: str
    mappings: dict[str, list[str]] = field(default_factory=dict)

    @property
    def is_failure(self) -> bool:
        return self.status == FAIL

    @property
    def is_blocking_failure(self) -> bool:
        return self.status == FAIL and self.applicability == "mandatory"


@dataclass(frozen=True)
class Gate:
    compliant: bool
    enforcement: str             # blocking | warning
    reasons: list[str]
    has_critical_blocking_failure: bool = False

    @property
    def should_fail_pipeline(self) -> bool:
        return ((self.enforcement == "blocking" and not self.compliant)
                or self.has_critical_blocking_failure)


@dataclass(frozen=True)
class Assessment:
    profile: str
    repo: str
    results: list[Result]
    score: float
    gate: Gate
    summary: dict[str, Any]


# --------------------------------------------------------------------------
# Check evaluators. Each returns (passed: bool, reason: str).
# --------------------------------------------------------------------------
CheckFn = Callable[[RepoScan, dict[str, Any]], tuple[bool, str]]


def _check_file_exists(scan: RepoScan, params: dict[str, Any]) -> tuple[bool, str]:
    candidates = params.get("any_of", [])
    found = [c for c in candidates if scan.has_path(c)]
    if found:
        return True, f"found {found[0]}"
    return False, f"none of {candidates} present"


def _check_file_absent(scan: RepoScan, params: dict[str, Any]) -> tuple[bool, str]:
    candidates = params.get("any_of", [])
    present = [c for c in candidates if scan.has_path(c)]
    if present:
        return False, f"forbidden path present: {present[0]}"
    return True, "no forbidden paths present"


def _check_workflow_present(scan: RepoScan, params: dict[str, Any]) -> tuple[bool, str]:
    keywords = params.get("keywords", [])
    if params.get("semantic") == "sast_analyzer":
        if scan.sast_analyzer_present:
            return True, "workflow invokes a recognized SAST analyzer"
        return False, "no workflow invokes a recognized SAST analyzer"
    if keyword_in_workflows(scan, keywords):
        return True, f"workflow references one of {keywords}"
    return False, f"no workflow references any of {keywords}"


def _check_content_match(scan: RepoScan, params: dict[str, Any]) -> tuple[bool, str]:
    path = params["path"]
    pattern = params["pattern"]
    text = scan.read_text(path)
    if text and re.search(pattern, text, re.MULTILINE):
        return True, f"{path} matches /{pattern}/"
    return False, f"{path} missing or no match for /{pattern}/"


def _check_metadata_true(scan: RepoScan, params: dict[str, Any]) -> tuple[bool, str]:
    key = params["key"]
    val = scan.metadata_value(key)
    if val is True:
        return True, f"{key} is true"
    return False, f"{key} is not true (got {val!r})"


def _check_metadata_gte(scan: RepoScan, params: dict[str, Any]) -> tuple[bool, str]:
    key = params["key"]
    threshold = params["value"]
    val = scan.metadata_value(key)
    try:
        if val is not None and float(val) >= float(threshold):
            return True, f"{key}={val} >= {threshold}"
    except (TypeError, ValueError):
        pass
    return False, f"{key}={val!r} < {threshold}"


def _check_metadata_in(scan: RepoScan, params: dict[str, Any]) -> tuple[bool, str]:
    key = params["key"]
    allowed = params.get("values", [])
    val = scan.metadata_value(key)
    if val in allowed:
        return True, f"{key}={val!r} in allowed set"
    return False, f"{key}={val!r} not in {allowed}"


CHECKS: dict[str, CheckFn] = {
    "file_exists": _check_file_exists,
    "file_absent": _check_file_absent,
    "workflow_present": _check_workflow_present,
    "content_match": _check_content_match,
    "metadata_true": _check_metadata_true,
    "metadata_gte": _check_metadata_gte,
    "metadata_in": _check_metadata_in,
}


def evaluate_control(scan: RepoScan, control: Control, profile: Profile) -> Result:
    applicability = profile.status_for(control.id)
    if applicability == "not_applicable":
        return Result(
            control_id=control.id, title=control.title, category=control.category,
            severity=control.severity, status=NA, applicability=applicability,
            reason="marked not applicable by profile", remediation=control.remediation,
            mappings=control.mappings,
        )

    check_type = control.check.get("type")
    fn = CHECKS.get(check_type)
    if fn is None:
        raise ValueError(f"Unknown check type '{check_type}' for control {control.id}")

    # Profile threshold injection: GOV-REV-011 uses the profile's required_reviewers.
    params = dict(control.check)
    if control.id == "GOV-REV-011":
        params["value"] = profile.thresholds.get("required_reviewers", params.get("value", 1))

    passed, reason = fn(scan, params)
    return Result(
        control_id=control.id, title=control.title, category=control.category,
        severity=control.severity, status=PASS if passed else FAIL,
        applicability=applicability, reason=reason, remediation=control.remediation,
        mappings=control.mappings,
    )


def evaluate(scan: RepoScan, catalog: Catalog, profile: Profile) -> Assessment:
    results = [evaluate_control(scan, c, profile) for c in catalog]
    score = _compliance_score(results)
    gate = _gate(results, score, profile)
    summary = _summarize(results, score)
    return Assessment(
        profile=profile.profile,
        repo=str(scan.root),
        results=results,
        score=score,
        gate=gate,
        summary=summary,
    )


def _compliance_score(results: list[Result]) -> float:
    possible = 0
    earned = 0
    for r in results:
        if r.status == NA:
            continue
        w = SEVERITY_WEIGHT[r.severity]
        possible += w
        if r.status == PASS:
            earned += w
    if possible == 0:
        return 100.0
    return round(earned / possible * 100, 1)


def _gate(results: list[Result], score: float, profile: Profile) -> Gate:
    t = profile.thresholds
    reasons: list[str] = []

    crit_fail = sum(1 for r in results if r.is_blocking_failure and r.severity == "critical")
    high_fail = sum(1 for r in results if r.is_blocking_failure and r.severity == "high")

    max_crit = t.get("max_critical_failures", 0)
    max_high = t.get("max_high_failures", 9999)
    min_score = t.get("min_compliance_score", 0)

    if crit_fail > max_crit:
        reasons.append(f"{crit_fail} mandatory CRITICAL failure(s) exceed limit {max_crit}")
    if high_fail > max_high:
        reasons.append(f"{high_fail} mandatory HIGH failure(s) exceed limit {max_high}")
    if score < min_score:
        reasons.append(f"compliance score {score} below minimum {min_score}")

    return Gate(
        compliant=not reasons,
        enforcement=profile.enforcement,
        reasons=reasons,
        has_critical_blocking_failure=crit_fail > 0,
    )


def _summarize(results: list[Result], score: float) -> dict[str, Any]:
    by_status: dict[str, int] = {PASS: 0, FAIL: 0, NA: 0}
    by_severity_fail: dict[str, int] = {s: 0 for s in SEVERITY_WEIGHT}
    for r in results:
        by_status[r.status] += 1
        if r.is_failure:
            by_severity_fail[r.severity] += 1
    return {
        "total_controls": len(results),
        "passed": by_status[PASS],
        "failed": by_status[FAIL],
        "not_applicable": by_status[NA],
        "failures_by_severity": by_severity_fail,
        "blocking_failures": sum(1 for r in results if r.is_blocking_failure),
        "compliance_score": score,
    }
