import subprocess

from sre_governance.scanner import (
    has_iac_workflow,
    has_safe_change_workflow,
    has_sast_workflow,
    has_sca_configuration,
    has_sbom_workflow,
    scan_repo,
)


def test_sast_detection_ignores_sarif_upload_action(tmp_path):
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    workflow = workflow_dir / "security.yml"
    workflow.write_text(
        """name: Security
on:
  pull_request:
  push:
jobs:
  upload:
    steps:
      - uses: github/codeql-action/upload-sarif@v3
      - run: echo "bandit is not being run"
""",
        encoding="utf-8",
    )
    assert not has_sast_workflow(scan_repo(tmp_path))

    workflow.write_text(
        workflow.read_text(encoding="utf-8").replace(
            "upload-sarif", "analyze"
        ),
        encoding="utf-8",
    )
    assert has_sast_workflow(scan_repo(tmp_path))


def test_git_scans_ignore_untracked_evidence(tmp_path):
    (tmp_path / "README.md").write_text("tracked", encoding="utf-8")
    subprocess.run(["git", "init", str(tmp_path)], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(tmp_path), "add", "README.md"],
        check=True, capture_output=True,
    )
    (tmp_path / "SECURITY.md").write_text("untracked", encoding="utf-8")

    scan = scan_repo(tmp_path)
    assert scan.has_path("README.md")
    assert not scan.has_path("SECURITY.md")
    assert scan.read_text("SECURITY.md") == ""


def test_git_scanner_does_not_read_symlink_outside_repository(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside.yaml"
    outside.write_text("sensitive: data", encoding="utf-8")
    link = repo / "evidence.yaml"
    link.symlink_to(outside)
    subprocess.run(["git", "init", str(repo)], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(repo), "add", "evidence.yaml"],
        check=True, capture_output=True,
    )

    scan = scan_repo(repo)
    assert scan.has_path("evidence.yaml")
    assert scan.read_text("evidence.yaml") == ""


def test_git_scanner_ignores_symlink_to_untracked_repository_file(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    target = repo / "local.yaml"
    target.write_text("evidence: true", encoding="utf-8")
    link = repo / "evidence.yaml"
    link.symlink_to(target.name)
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "add", "evidence.yaml"], check=True)

    scan = scan_repo(repo)

    assert scan.has_path("evidence.yaml")
    assert scan.read_text("evidence.yaml") == ""


def test_control_specific_workflow_checks_ignore_labels_and_echoes(tmp_path):
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    workflow = workflow_dir / "checks.yml"
    workflow.write_text(
        """name: checkov deploy sbom
on: [push, pull_request]
jobs:
  scan:
    name: IaC scan and SBOM release
    steps:
      - name: deploy canary
        run: echo "checkov syft deploy.sh --canary"
""",
        encoding="utf-8",
    )
    scan = scan_repo(tmp_path)
    assert not has_iac_workflow(scan)
    assert not has_safe_change_workflow(scan)
    assert not has_sbom_workflow(scan)

    workflow.write_text(
        """name: checks
on: [push, pull_request, workflow_dispatch]
jobs:
  scan:
    steps:
      - uses: bridgecrewio/checkov-action@v12
      - run: ./deploy.sh --canary
      - run: syft dir:. -o cyclonedx-json > sbom.json
      - run: gh release create v1 release.tar.gz sbom.json
""",
        encoding="utf-8",
    )
    scan = scan_repo(tmp_path)
    assert has_iac_workflow(scan)
    assert has_safe_change_workflow(scan)
    assert has_sbom_workflow(scan)


def test_sca_requires_enabled_updates_and_critical_ci_gate(tmp_path):
    dependabot = tmp_path / ".github" / "dependabot.yml"
    dependabot.parent.mkdir(parents=True)
    dependabot.write_text("version: 2\nupdates: []\n", encoding="utf-8")
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir()
    workflow = workflow_dir / "ci.yml"
    workflow.write_text(
        """on: [pull_request]
jobs:
  test:
    steps:
      - uses: actions/dependency-review-action@v4
        with:
          fail-on-severity: critical
""",
        encoding="utf-8",
    )
    assert not has_sca_configuration(scan_repo(tmp_path))

    dependabot.write_text(
        "version: 2\nupdates:\n"
        "  - package-ecosystem: pip\n"
        "    directory: /\n"
        "    schedule:\n"
        "      interval: weekly\n",
        encoding="utf-8",
    )
    assert has_sca_configuration(scan_repo(tmp_path))

    workflow.write_text(
        workflow.read_text(encoding="utf-8").replace("critical", "high"),
        encoding="utf-8",
    )
    assert not has_sca_configuration(scan_repo(tmp_path))
