from pathlib import Path

import yaml

from sre_governance.catalog import load_catalog, load_profiles
from sre_governance.engine import PASS, evaluate
from sre_governance.scanner import scan_repo

ROOT = Path(__file__).resolve().parents[1]


def test_commercial_self_scan_reaches_client_target():
    catalog = load_catalog(ROOT / "config" / "control-catalog.yaml")
    profile = load_profiles(ROOT / "config" / "industry-profiles")["commercial"]
    assessment = evaluate(scan_repo(ROOT), catalog, profile)

    assert assessment.score == 100, [
        (result.control_id, result.reason) for result in assessment.results
        if result.status != PASS
    ]
    assert assessment.gate.compliant, assessment.gate.reasons
    results = {result.control_id: result for result in assessment.results}
    for control_id in (
        "GOV-BP-010", "GOV-REV-011", "GOV-SIGN-013", "SEC-SECRETS-020",
        "SRE-CHG-005", "SEC-SBOM-023", "SEC-IAC-024",
    ):
        assert results[control_id].status == PASS, results[control_id].reason


def test_release_and_iac_workflows_have_real_gates():
    workflows = ROOT / ".github" / "workflows"
    release = yaml.load(
        (workflows / "release.yml").read_text(encoding="utf-8"),
        Loader=yaml.BaseLoader,
    )
    candidate = release["jobs"]["candidate"]["steps"]
    promote = release["jobs"]["promote"]["steps"]
    assert any("python -m pytest -q" in step.get("run", "") for step in candidate)
    assert any("git archive" in step.get("run", "") for step in candidate)
    assert any(step.get("uses", "").startswith("anchore/sbom-action@")
               and step.get("with", {}).get("output-file")
               for step in candidate)
    assert any("gh release create" in step.get("run", "")
               and "--prerelease" in step["run"] for step in candidate)
    assert any("git merge-base --is-ancestor" in step.get("run", "")
               and "gh release edit" in step["run"] for step in promote)

    iac = yaml.load(
        (workflows / "iac-scan.yml").read_text(encoding="utf-8"),
        Loader=yaml.BaseLoader,
    )
    steps = iac["jobs"]["iac-scan"]["steps"]
    assert any(step.get("uses", "").startswith("bridgecrewio/checkov-action@")
               and step.get("with", {}).get("framework") == "github_actions"
               and step["with"].get("soft_fail") == "false"
               for step in steps)
