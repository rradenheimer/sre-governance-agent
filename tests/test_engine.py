from dataclasses import replace
from datetime import date, timedelta
from pathlib import Path

from sre_governance.catalog import load_catalog, load_profiles
from sre_governance.engine import FAIL, PASS, evaluate
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


def test_commercial_warning_enforcement_does_not_fail_pipeline_on_low_only():
    catalog, profiles = _ctx()
    scan = scan_repo(GOOD)
    scan.files.remove("LICENSE")
    assessment = evaluate(scan, catalog, profiles["commercial"])
    assert assessment.gate.enforcement == "warning"
    assert assessment.gate.compliant
    assert assessment.gate.should_fail_pipeline is False


def test_commercial_critical_failures_block_in_warning_mode():
    catalog, profiles = _ctx()
    assessment = evaluate(scan_repo(BAD), catalog, profiles["commercial"])
    assert assessment.gate.enforcement == "warning"
    assert assessment.gate.critical_failure
    assert assessment.gate.should_fail_pipeline is True


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
    profile = profiles["commercial"]
    baseline = evaluate(scan_repo(BAD), catalog, profile)
    profile = replace(
        profile,
        control_overrides={**profile.control_overrides, "SRE-SLO-001": "not_applicable"},
    )
    assessment = evaluate(scan_repo(BAD), catalog, profile)
    assert next(r for r in assessment.results if r.control_id == "SRE-SLO-001").status == "NOT_APPLICABLE"

    weights = {"critical": 10, "high": 6, "medium": 3, "low": 1}
    denominator = sum(weights[r.severity] for r in assessment.results if r.status != "NOT_APPLICABLE")
    numerator = sum(
        weights[r.severity] for r in assessment.results if r.status == PASS
    )
    assert assessment.score == round(numerator / denominator * 100, 1)
    assert assessment.score > baseline.score


def test_audit_control_requires_verified_files_and_metadata():
    catalog, profiles = _ctx()
    scan = merge_api_metadata(scan_repo(GOOD), {"governance": {"audit_logging": "false"}})
    assessment = evaluate(scan, catalog, profiles["commercial"])
    audit = next(r for r in assessment.results if r.control_id == "CMP-AUDIT-033")
    assert audit.status == FAIL


def test_boolean_metadata_does_not_pass_numeric_checks():
    catalog, profiles = _ctx()
    scan = merge_api_metadata(
        scan_repo(GOOD),
        {"governance": {
            "branch_protection": {"required_reviewers": True},
        }, "sre": {"toil_budget_pct": True}},
    )
    assessment = evaluate(scan, catalog, profiles["commercial"])
    statuses = {result.control_id: result.status for result in assessment.results}
    assert statuses["GOV-REV-011"] == FAIL
    assert statuses["SRE-TOIL-007"] == FAIL


def test_disaster_recovery_requires_structured_evidence():
    catalog, profiles = _ctx()
    scan = merge_api_metadata(
        scan_repo(GOOD), {"sre": {"dr_tested": True, "disaster_recovery": None}},
    )
    assessment = evaluate(scan, catalog, profiles["commercial"])
    dr = next(result for result in assessment.results if result.control_id == "SRE-DR-006")
    assert dr.status == FAIL

    scan = merge_api_metadata(scan_repo(GOOD), {
        "sre": {
            "disaster_recovery": {
                "rpo": "4h",
                "rto": "8h",
                "test_cadence": "quarterly",
                "last_tested": date.today().isoformat(),
            },
        },
    })
    assessment = evaluate(scan, catalog, profiles["commercial"])
    dr = next(result for result in assessment.results if result.control_id == "SRE-DR-006")
    assert dr.status == PASS

    scan = merge_api_metadata(scan, {
        "sre": {
            "disaster_recovery": {
                "last_tested": (date.today() + timedelta(days=1)).isoformat(),
            },
        },
    })
    assessment = evaluate(scan, catalog, profiles["commercial"])
    dr = next(result for result in assessment.results if result.control_id == "SRE-DR-006")
    assert dr.status == FAIL
    assert "future" in dr.reason

    scan = merge_api_metadata(scan, {
        "sre": {
            "disaster_recovery": {
                "last_tested": (date.today() - timedelta(days=93)).isoformat(),
            },
        },
    })
    assessment = evaluate(scan, catalog, profiles["commercial"])
    dr = next(result for result in assessment.results if result.control_id == "SRE-DR-006")
    assert dr.status == FAIL
    assert "quarterly test cadence" in dr.reason

    scan = merge_api_metadata(scan, {
        "sre": {"disaster_recovery": {"rpo": "0h"}},
    })
    assessment = evaluate(scan, catalog, profiles["commercial"])
    dr = next(result for result in assessment.results if result.control_id == "SRE-DR-006")
    assert dr.status == FAIL


def test_slo_control_requires_a_valid_entry(tmp_path):
    catalog, profiles = _ctx()
    slo_file = tmp_path / ".sre" / "slo.yaml"
    slo_file.parent.mkdir()

    for text in ("", "service: api\nslos: []\n",
                 "service: api\nslos:\n  - name: availability\n    sli: requests_ok\n"):
        slo_file.write_text(text, encoding="utf-8")
        assessment = evaluate(scan_repo(tmp_path), catalog, profiles["commercial"])
        slo = next(result for result in assessment.results if result.control_id == "SRE-SLO-001")
        assert slo.status == FAIL

    slo_file.write_text(
        "service: api\nslos:\n"
        "  - name: availability\n    sli: requests_ok / requests_total\n"
        "    objective: 99.9\n    window: 30d\n",
        encoding="utf-8",
    )
    assessment = evaluate(scan_repo(tmp_path), catalog, profiles["commercial"])
    slo = next(result for result in assessment.results if result.control_id == "SRE-SLO-001")
    assert slo.status == PASS


def test_audit_control_requires_tracked_verified_log_and_anchor(tmp_path):
    import subprocess

    from sre_governance.audit import AuditLogger

    catalog, profiles = _ctx()
    (tmp_path / ".sre").mkdir()
    (tmp_path / ".sre" / "governance.yaml").write_text(
        "governance:\n  audit_logging: true\n", encoding="utf-8",
    )
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(
        ["git", "-C", str(tmp_path), "add", ".sre/governance.yaml"], check=True,
    )
    assessment = evaluate(scan_repo(tmp_path), catalog, profiles["commercial"])
    audit = next(result for result in assessment.results if result.control_id == "CMP-AUDIT-033")
    assert audit.status == FAIL

    audit_path = tmp_path / ".sre" / "audit.jsonl"
    AuditLogger(audit_path).record("scan", target="fixture")
    subprocess.run(["git", "-C", str(tmp_path), "add", ".sre"], check=True)

    assessment = evaluate(scan_repo(tmp_path), catalog, profiles["commercial"])
    audit = next(result for result in assessment.results if result.control_id == "CMP-AUDIT-033")
    assert audit.status == PASS

    (tmp_path / ".sre" / "audit.jsonl.head").unlink()
    subprocess.run(["git", "-C", str(tmp_path), "rm", "-q", ".sre/audit.jsonl.head"], check=True)
    assessment = evaluate(scan_repo(tmp_path), catalog, profiles["commercial"])
    audit = next(result for result in assessment.results if result.control_id == "CMP-AUDIT-033")
    assert audit.status == FAIL
