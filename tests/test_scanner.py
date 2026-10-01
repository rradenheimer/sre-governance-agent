import subprocess

from sre_governance.scanner import has_sast_workflow, scan_repo


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
