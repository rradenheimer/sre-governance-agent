"""Deterministic evaluation engine.

Given a RepoScan, a Catalog, and a Profile, produce per-control Results and an
overall Assessment (score + policy gate). No AI, no network, no randomness.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable

import yaml

from sre_governance.audit import verify_audit_contents
from sre_governance.catalog import Catalog, Control, Profile
from sre_governance.scanner import (
    RepoScan,
    has_iac_workflow,
    has_safe_change_workflow,
    has_sca_configuration,
    has_sbom_workflow,
    has_sast_workflow,
    has_slo_linked_observability,
)

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
    critical_failure: bool = False

    @property
    def should_fail_pipeline(self) -> bool:
        return self.critical_failure or (self.enforcement == "blocking" and not self.compliant)


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
    checkers = {
        "safe_change_workflow": has_safe_change_workflow,
        "sbom_workflow": has_sbom_workflow,
        "iac_workflow": has_iac_workflow,
        "sca_configured": has_sca_configuration,
    }
    requirement = params["requirement"]
    checker = checkers[requirement]
    if checker(scan):
        return True, f"workflow satisfies {requirement} evidence requirements"
    return False, f"no workflow satisfies {requirement} evidence requirements"


def _check_workflow_security_scan(scan: RepoScan, params: dict[str, Any]) -> tuple[bool, str]:
    if has_sast_workflow(scan):
        return True, "workflow runs a SAST tool for pull requests and pushes"
    return False, "no SAST analysis step runs for both pull requests and pushes"


def _check_observability_configured(scan: RepoScan, params: dict[str, Any]) -> tuple[bool, str]:
    if has_slo_linked_observability(scan):
        return True, "observability alert references a declared SLI"
    return False, "no non-empty observability alert is linked to a declared SLI"


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
        if val is not None and not isinstance(val, bool) and float(val) >= float(threshold):
            return True, f"{key}={val} >= {threshold}"
    except (TypeError, ValueError):
        pass
    return False, f"{key}={val!r} < {threshold}"


def _check_slo_configured(scan: RepoScan, params: dict[str, Any]) -> tuple[bool, str]:
    candidates = params.get("any_of", [])
    paths = [
        path for path in sorted(scan.files)
        if path in candidates or any(
            candidate.endswith("/") and path.startswith(candidate)
            for candidate in candidates
        )
    ]
    for path in paths:
        try:
            document = yaml.safe_load(scan.read_text(path))
        except yaml.YAMLError:
            continue
        if not isinstance(document, dict) or not isinstance(document.get("service"), str):
            continue
        if not document["service"].strip() or not isinstance(document.get("slos"), list):
            continue
        for slo in document["slos"]:
            if not isinstance(slo, dict):
                continue
            if not all(isinstance(slo.get(key), str) and slo[key].strip()
                       for key in ("name", "sli", "window")):
                continue
            objective = slo.get("objective")
            if (isinstance(objective, (int, float)) and not isinstance(objective, bool)
                    and 0 < objective <= 100):
                return True, f"{path} declares a valid SLO for {document['service']}"
    return False, "no valid SLO entry with a service, SLI, objective, and window"


def _check_audit_log_verified(scan: RepoScan, params: dict[str, Any]) -> tuple[bool, str]:
    if scan.metadata_value("governance.audit_logging") is not True:
        return False, "governance.audit_logging is not true"
    log_path = params["log_path"]
    anchor_path = params["anchor_path"]
    if log_path not in scan.files or anchor_path not in scan.files:
        return False, "audit log and head anchor must both be tracked"
    valid, message = verify_audit_contents(
        scan.read_text(log_path), scan.read_text(anchor_path),
    )
    if valid:
        return True, "tracked audit log and head anchor verify"
    return False, message


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
    "workflow_security_scan": _check_workflow_security_scan,
    "observability_configured": _check_observability_configured,
    "content_match": _check_content_match,
    "metadata_true": _check_metadata_true,
    "metadata_gte": _check_metadata_gte,
    "metadata_in": _check_metadata_in,
    "slo_configured": _check_slo_configured,
    "audit_log_verified": _check_audit_log_verified,
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
        compliant=not reasons, enforcement=profile.enforcement, reasons=reasons,
        critical_failure=crit_fail > max_crit,
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
