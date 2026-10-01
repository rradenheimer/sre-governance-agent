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
    assert all(result.status == PASS for result in assessment.results), {
        result.control_id: result.reason for result in assessment.results if result.status != PASS
    }
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
    candidate_run = next(
        step["run"] for step in candidate
        if step.get("name") == "Verify signed release tag targets this commit"
    )
    promotion = yaml.load(
        (workflows / "promote-release.yml").read_text(encoding="utf-8"),
        Loader=yaml.BaseLoader,
    )
    promote = promotion["jobs"]["promote"]["steps"]
    promote_run = next(
        step["run"] for step in promote
        if step.get("name") == "Check candidate and promote without rebuilding"
    )
    assert any("python -m pytest -q" in step.get("run", "") for step in candidate)
    assert "verification.verified" in promote_run
    assert "git/tags/$TAG_OBJECT" in promote_run
    assert 'test "$TAG_COMMIT" = "$CANDIDATE_COMMIT"' in promote_run
    assert 'test "$(git rev-parse "$TAG^{tag}")" = "$TAG_OBJECT"' in promote_run
    assert any(".verification.verified" in step.get("run", "")
               and "git rev-parse" in step["run"] for step in candidate)
    assert any("git archive" in step.get("run", "") for step in candidate)
    assert any(step.get("uses", "").startswith("anchore/sbom-action@")
               and step.get("with", {}).get("output-file")
               for step in candidate)
    assert any("gh release create" in step.get("run", "")
               and "--prerelease" in step["run"] for step in candidate)
    assert any(".immutable" in step.get("run", "")
               and "grep -qx true" in step["run"] for step in candidate)
    assert ".immutable" in promote_run
    assert ".digest" in promote_run and "sha256sum --check" in promote_run
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
        assert any(step.get("name") == "Restore prior audit chain"
                   for step in governance["jobs"]["governance-scan"]["steps"])
        restore = next(step for step in governance["jobs"]["governance-scan"]["steps"]
                       if step.get("name") == "Restore prior audit chain")
        assert "sre-governance-reports" in restore["run"]
        assert "No prior audit artifact found" in restore["run"]
        assert any(step.get("name") == "Persist audit chain for the next run"
                   for step in governance["jobs"]["governance-scan"]["steps"])

    dependency_review = yaml.load(
        (ROOT / ".github" / "workflows" / "dependency-review.yml").read_text(encoding="utf-8"),
        Loader=yaml.BaseLoader,
    )
    review_step = dependency_review["jobs"]["dependency-review"]["steps"][0]
    assert review_step["uses"] == "actions/dependency-review-action@v5"
    assert review_step["with"]["fail-on-severity"] == "critical"

    template_workflow = yaml.load(
        (ROOT / "agents" / "copilot" / ".github" / "workflows" / "sre-governance.yml")
        .read_text(encoding="utf-8"),
        Loader=yaml.BaseLoader,
    )
    template_steps = template_workflow["jobs"]["governance-scan"]["steps"]
    engine_checkout = next(step for step in template_steps
                           if step.get("with", {}).get("repository") == "rradenheimer/sre-governance-agent")
    assert engine_checkout["with"]["ref"] == "v1.0.0"
    template_scan = next(step for step in template_steps if step.get("name") == "Run governance scan")
    assert "sre-governance-engine/src" in template_scan["run"]
    assert "sre-governance-engine/config/control-catalog.yaml" in template_scan["run"]

    iac = yaml.load(
        (workflows / "iac-scan.yml").read_text(encoding="utf-8"),
        Loader=yaml.BaseLoader,
    )
    assert set(iac["jobs"]["iac-scan"]["strategy"]["matrix"]["workflow"]) == {
        "sre-governance.yml", "policy-validation.yml", "iac-scan.yml",
        "release.yml", "promote-release.yml",
    }
    steps = iac["jobs"]["iac-scan"]["steps"]
    assert any(step.get("uses", "").startswith("bridgecrewio/checkov-action@")
               and step.get("with", {}).get("framework") == "github_actions"
               and step["with"].get("soft_fail") == "false"
               for step in steps)
    for workflow in ("codeql.yml", "scan-observability.yml"):
        step = next(step for step in steps if step.get("with", {}).get("file")
                    == f".github/workflows/{workflow}")
        assert step.get("if") == "matrix.workflow == 'iac-scan.yml'"
        assert step.get("with", {}).get("soft_fail") == "false"
