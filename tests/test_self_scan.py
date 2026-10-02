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
    codeql = yaml.load(
        (workflows / "codeql.yml").read_text(encoding="utf-8"),
        Loader=yaml.BaseLoader,
    )
    assert {"pull_request", "push"} <= set(codeql["on"])
    analyze_steps = codeql["jobs"]["analyze"]["steps"]
    assert any(step.get("uses", "").startswith("github/codeql-action/init@")
               for step in analyze_steps)
    assert any(step.get("uses", "").startswith("github/codeql-action/analyze@")
               and not step.get("continue-on-error") for step in analyze_steps)
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
    assert set(iac["jobs"]["iac-scan"]["strategy"]["matrix"]["workflow"]) == {
        path.name for path in workflows.glob("*.yml")
    }
    steps = iac["jobs"]["iac-scan"]["steps"]
    assert any(step.get("uses", "").startswith("bridgecrewio/checkov-action@")
               and step.get("with", {}).get("framework") == "github_actions"
               and step["with"].get("soft_fail") == "false"
               for step in steps)


def test_workflow_security_and_validation_gates():
    workflows = ROOT / ".github" / "workflows"
    validation = yaml.load(
        (workflows / "policy-validation.yml").read_text(encoding="utf-8"),
        Loader=yaml.BaseLoader,
    )
    paths = validation["on"]["pull_request"]["paths"]
    assert {"requirements.txt", "pytest.ini", "conftest.py"} <= set(paths)
    install = next(
        step["run"] for step in validation["jobs"]["validate"]["steps"]
        if step.get("name") == "Install Conftest"
    )
    assert "sha256sum --check -" in install

    scan = yaml.load(
        (workflows / "sre-governance.yml").read_text(encoding="utf-8"),
        Loader=yaml.BaseLoader,
    )
    assert scan["permissions"] == {"contents": "read"}
    assert not any(
        step.get("uses", "").startswith("actions/github-script@")
        or step.get("uses", "").startswith("github/codeql-action/upload-sarif@")
        for step in scan["jobs"]["governance-scan"]["steps"]
    )

    report = yaml.load(
        (workflows / "sre-governance-report.yml").read_text(encoding="utf-8"),
        Loader=yaml.BaseLoader,
    )
    assert report["on"]["workflow_run"]["workflows"] == ["SRE Governance"]
    assert report["jobs"]["publish"]["permissions"]["pull-requests"] == "write"
    download = next(
        step for step in report["jobs"]["publish"]["steps"]
        if step.get("uses", "").startswith("actions/download-artifact@")
    )
    assert download["uses"] == "actions/download-artifact@v4.1.3"
    assert not any(
        step.get("uses", "").startswith("actions/checkout@")
        for step in report["jobs"]["publish"]["steps"]
    )
    vendored_report = yaml.load(
        (ROOT / "agents" / "copilot" / ".github" / "workflows"
         / "sre-governance-report.yml").read_text(encoding="utf-8"),
        Loader=yaml.BaseLoader,
    )
    vendored_download = next(
        step for step in vendored_report["jobs"]["publish"]["steps"]
        if step.get("uses", "").startswith("actions/download-artifact@")
    )
    assert vendored_download["uses"] == download["uses"]
