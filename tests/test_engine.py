from dataclasses import replace
from pathlib import Path

from sre_governance.catalog import Catalog, Control, load_catalog, load_profiles
from sre_governance.engine import FAIL, NA, PASS, evaluate, evaluate_control
from sre_governance.scanner import merge_api_metadata, scan_repo

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "config" / "control-catalog.yaml"
PROFILES = ROOT / "config" / "industry-profiles"
GOOD = ROOT / "tests" / "fixtures" / "good-repo"
BAD = ROOT / "tests" / "fixtures" / "bad-repo"


def _ctx():
    return load_catalog(CATALOG), load_profiles(PROFILES)


def test_good_repo_is_compliant_commercial():
    catalog, profiles = _ctx()
    assessment = evaluate(scan_repo(GOOD), catalog, profiles["commercial"])
    assert assessment.gate.compliant, assessment.gate.reasons
    assert assessment.score >= 90


def test_good_repo_is_compliant_federal():
    catalog, profiles = _ctx()
    assessment = evaluate(scan_repo(GOOD), catalog, profiles["federal-defense"])
    # good-repo attests to everything federal requires
    assert assessment.score >= 95
    assert assessment.gate.compliant, assessment.gate.reasons


def test_bad_repo_fails_everywhere():
    catalog, profiles = _ctx()
    for name in ("commercial", "regulated", "federal-defense"):
        assessment = evaluate(scan_repo(BAD), catalog, profiles[name])
        assert not assessment.gate.compliant, f"{name} unexpectedly passed"
        assert assessment.summary["failed"] > 0


def test_bad_repo_blocking_under_blocking_enforcement():
    catalog, profiles = _ctx()
    assessment = evaluate(scan_repo(BAD), catalog, profiles["federal-defense"])
    assert assessment.gate.should_fail_pipeline is True


def test_commercial_warning_enforcement_still_blocks_critical_failures():
    catalog, profiles = _ctx()
    assessment = evaluate(scan_repo(BAD), catalog, profiles["commercial"])
    assert assessment.gate.enforcement == "warning"
    assert assessment.gate.should_fail_pipeline is True


def test_warning_gate_does_not_fail_for_noncritical_shortfalls():
    catalog, profiles = _ctx()
    profile = replace(
        profiles["commercial"],
        control_overrides={
            control.id: "recommended"
            for control in catalog
            if control.severity == "critical"
        },
    )
    assessment = evaluate(scan_repo(BAD), catalog, profile)
    assert not assessment.gate.has_critical_blocking_failure
    assert assessment.gate.enforcement == "warning"
    assert assessment.gate.should_fail_pipeline is False


def test_required_reviewers_threshold_from_profile():
    # good-repo declares 2 reviewers -> passes federal (needs 2). Override to 1
    # reviewer and federal GOV-REV-011 should FAIL.
    catalog, profiles = _ctx()
    scan = scan_repo(GOOD)
    scan = merge_api_metadata(scan, {"governance": {"branch_protection": {"required_reviewers": 1}}})
    assessment = evaluate(scan, catalog, profiles["federal-defense"])
    rev = next(r for r in assessment.results if r.control_id == "GOV-REV-011")
    assert rev.status == FAIL


def test_na_controls_excluded_from_score():
    catalog, profiles = _ctx()
    controls = {
        "NA-CRITICAL": Control(
            id="NA-CRITICAL", title="Not applicable critical control",
            category="security", severity="critical", automatable=True,
            description="", rationale="",
            check={"type": "file_exists", "any_of": ["missing-critical-file"]},
            remediation="",
        ),
        "PASS-HIGH": Control(
            id="PASS-HIGH", title="Passing high control", category="governance",
            severity="high", automatable=True, description="", rationale="",
            check={"type": "file_exists", "any_of": ["README.md"]}, remediation="",
        ),
        "FAIL-MEDIUM": Control(
            id="FAIL-MEDIUM", title="Failing medium control", category="security",
            severity="medium", automatable=True, description="", rationale="",
            check={"type": "file_exists", "any_of": ["missing-medium-file"]},
            remediation="",
        ),
    }
    profile = replace(
        profiles["commercial"],
        control_overrides={"NA-CRITICAL": "not_applicable"},
    )
    assessment = evaluate(scan_repo(BAD), Catalog("1", controls), profile)
    na = next(result for result in assessment.results if result.control_id == "NA-CRITICAL")
    assert na.status == NA
    assert assessment.score == 66.7  # 6 earned / (6 high + 3 medium) possible


def test_metadata_true_rejects_string_false():
    catalog, profiles = _ctx()
    scan = scan_repo(GOOD)
    scan.metadata["security"]["secret_scanning"] = "false"
    result = evaluate_control(
        scan, catalog.get("SEC-SECRETS-020"), profiles["commercial"]
    )
    assert result.status == FAIL


def test_sast_control_requires_analyzer_invocation(tmp_path):
    catalog, profiles = _ctx()
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    workflow = workflows / "sast.yml"
    workflow.write_text(
        "name: Scan\non: [pull_request]\njobs:\n  scan:\n    steps:\n"
        "      - uses: github/codeql-action/upload-sarif@v3\n",
        encoding="utf-8",
    )
    result = evaluate_control(
        scan_repo(tmp_path), catalog.get("SEC-SAST-021"), profiles["commercial"]
    )
    assert result.status == FAIL

    workflow.write_text(
        "name: Scan\non: [pull_request]\njobs:\n  scan:\n    steps:\n"
        "      - uses: github/codeql-action/analyze@v3\n",
        encoding="utf-8",
    )
    result = evaluate_control(
        scan_repo(tmp_path), catalog.get("SEC-SAST-021"), profiles["commercial"]
    )
    assert result.status == PASS
