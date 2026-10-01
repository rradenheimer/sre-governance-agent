from pathlib import Path

import yaml

from sre_governance.catalog import load_catalog, load_profiles
from sre_governance.engine import PASS, evaluate
from sre_governance.scanner import scan_repo

ROOT = Path(__file__).resolve().parents[1]


def test_commercial_self_scan_does_not_overstate_missing_evidence():
    catalog = load_catalog(ROOT / "config" / "control-catalog.yaml")
    profile = load_profiles(ROOT / "config" / "industry-profiles")["commercial"]
    assessment = evaluate(scan_repo(ROOT), catalog, profile)

    assert assessment.gate.compliant, assessment.gate.reasons
    results = {result.control_id: result for result in assessment.results}
    assert {
        result.control_id for result in assessment.results if result.status != PASS
    } == {"SEC-SAST-021", "SRE-OBS-004"}
    for control_id in (
        "GOV-BP-010", "GOV-REV-011", "GOV-SIGN-013", "SEC-SECRETS-020",
        "SRE-CHG-005", "SEC-SBOM-023", "SEC-IAC-024", "CMP-AUDIT-033",
    ):
        assert results[control_id].status == PASS, results[control_id].reason


def test_release_and_iac_workflows_have_real_gates():
    workflows = ROOT / ".github" / "workflows"
    release = yaml.load(
        (workflows / "release.yml").read_text(encoding="utf-8"),
        Loader=yaml.BaseLoader,
    )
    candidate = release["jobs"]["candidate"]["steps"]
    promotion = yaml.load(
        (workflows / "promote-release.yml").read_text(encoding="utf-8"),
        Loader=yaml.BaseLoader,
    )
    promote = promotion["jobs"]["promote"]["steps"]
    assert any("python -m pytest -q" in step.get("run", "") for step in candidate)
    assert any(".verification.verified" in step.get("run", "")
               and "git rev-parse" in step["run"] for step in candidate)
    assert any("git archive" in step.get("run", "") for step in candidate)
    assert any(step.get("uses", "").startswith("anchore/sbom-action@")
               and step.get("with", {}).get("output-file")
               for step in candidate)
    assert any("gh release create" in step.get("run", "")
               and "--prerelease" in step["run"] for step in candidate)
    assert any("git merge-base --is-ancestor" in step.get("run", "")
               and "gh release edit" in step["run"] for step in promote)

    validation = yaml.load(
        (workflows / "policy-validation.yml").read_text(encoding="utf-8"),
        Loader=yaml.BaseLoader,
    )
    validation_steps = validation["jobs"]["validate"]["steps"]
    assert any(step.get("uses", "").startswith("anchore/sbom-action@")
               for step in validation_steps)
    assert any("spdxVersion" in step.get("run", "")
               for step in validation_steps)

    for path in (
        ROOT / ".github" / "workflows" / "policy-validation.yml",
        ROOT / "agents" / "copilot" / ".github" / "workflows" / "policy-validation.yml",
    ):
        policy_validation = yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
        steps = policy_validation["jobs"]["validate"]["steps"]
        install = next(step for step in steps if step.get("name") == "Install Conftest")
        verify = next(step for step in steps if step.get("name") == "Verify OPA policies")
        assert "version=0.56.0" in install["run"]
        assert verify["run"] == "conftest verify --policy policies/opa"
        assert "continue-on-error" not in verify

    for path in (
        ROOT / ".github" / "workflows" / "sre-governance.yml",
        ROOT / "agents" / "copilot" / ".github" / "workflows" / "sre-governance.yml",
    ):
        governance = yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
        comment = next(
            step for step in governance["jobs"]["governance-scan"]["steps"]
            if step.get("name") == "Comment report on PR"
        )
        assert comment.get("continue-on-error") == "true"

    iac = yaml.load(
        (workflows / "iac-scan.yml").read_text(encoding="utf-8"),
        Loader=yaml.BaseLoader,
    )
    assert set(iac["jobs"]["iac-scan"]["strategy"]["matrix"]["workflow"]) == {
        path.name for path in workflows.glob("*.yml")
    }
    steps = iac["jobs"]["iac-scan"]["steps"]
    assert any(step.get("uses", "").startswith("bridgecrewio/checkov-action@")
               and step.get("with", {}).get("framework") == "github_actions"
               and step["with"].get("soft_fail") == "false"
               for step in steps)
