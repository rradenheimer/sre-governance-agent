from pathlib import Path

from sre_governance.catalog import load_catalog, load_profiles
from sre_governance.engine import PASS, evaluate
from sre_governance.scanner import scan_repo

ROOT = Path(__file__).resolve().parents[1]


def test_commercial_self_scan_reaches_client_target():
    catalog = load_catalog(ROOT / "config" / "control-catalog.yaml")
    profile = load_profiles(ROOT / "config" / "industry-profiles")["commercial"]
    assessment = evaluate(scan_repo(ROOT), catalog, profile)

    assert assessment.score >= 80, assessment.gate.reasons
    assert assessment.gate.compliant, assessment.gate.reasons
    results = {result.control_id: result for result in assessment.results}
    for control_id in ("GOV-BP-010", "GOV-REV-011", "SEC-SECRETS-020"):
        assert results[control_id].status == PASS, results[control_id].reason
