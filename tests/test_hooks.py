import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOOKS = ROOT / "agents" / "claude" / ".claude" / "hooks"
SECRET_GUARD = HOOKS / "secret_guard.py"
AUDIT_LOGGER = HOOKS / "audit_logger.py"


def _run(script: Path, payload: dict, cwd: Path | None = None):
    return subprocess.run(
        [sys.executable, str(script)],
        input=json.dumps(payload),
        capture_output=True, text=True, cwd=str(cwd) if cwd else None,
    )


def test_secret_guard_allows_benign():
    r = _run(SECRET_GUARD, {"tool_name": "Write",
                            "tool_input": {"file_path": "a.txt", "content": "hello"}})
    assert r.returncode == 0


def test_secret_guard_blocks_edits_in_suggest_only_profile(tmp_path):
    profile = tmp_path / ".sre" / "profile"
    profile.parent.mkdir()
    profile.write_text("federal-defense\n", encoding="utf-8")

    result = _run(
        SECRET_GUARD,
        {"tool_name": "Write", "tool_input": {"file_path": "report.md", "content": "proposal"}},
        cwd=tmp_path,
    )

    assert result.returncode == 2
    assert "suggest_only" in result.stderr


def test_read_only_mode_does_not_grant_editing():
    settings = json.loads(
        (ROOT / "agents" / "claude" / ".claude" / "settings.json").read_text(encoding="utf-8")
    )
    chatmode = (
        ROOT / "agents" / "copilot" / ".github" / "chatmodes" / "sre-governance.chatmode.md"
    ).read_text(encoding="utf-8")

    assert settings["permissions"]["defaultMode"] != "acceptEdits"
    assert "editFiles" not in chatmode.split("---", 2)[1]


def test_secret_guard_blocks_aws_key():
    r = _run(SECRET_GUARD, {"tool_name": "Write",
                            "tool_input": {"file_path": "a.txt", "content": "AKIAIOSFODNN7EXAMPLE"}})
    assert r.returncode == 2
    assert "secret" in r.stderr.lower()


def test_secret_guard_blocks_nested_multiedit_replacement():
    r = _run(SECRET_GUARD, {
        "tool_name": "MultiEdit",
        "tool_input": {"edits": [{"old_string": "safe", "new_string": "AKIAIOSFODNN7EXAMPLE"}]},
    })
    assert r.returncode == 2


def test_secret_guard_ignores_secret_only_in_multiedit_old_text():
    r = _run(SECRET_GUARD, {
        "tool_name": "MultiEdit",
        "tool_input": {"edits": [{"old_string": "AKIAIOSFODNN7EXAMPLE", "new_string": "removed"}]},
    })
    assert r.returncode == 0


def test_secret_guard_blocks_audit_edit():
    r = _run(SECRET_GUARD, {"tool_name": "Edit",
                            "tool_input": {"file_path": ".sre/audit.jsonl", "new_string": "x"}})
    assert r.returncode == 2


def test_secret_guard_blocks_audit_anchor_edit():
    r = _run(SECRET_GUARD, {"tool_name": "Edit",
                            "tool_input": {"file_path": ".sre/audit.jsonl.head", "new_string": "x"}})
    assert r.returncode == 2


def test_secret_guard_blocks_force_push():
    for command in (
        "git push --force origin main",
        "git push origin main --force",
        "git push origin main --force-with-lease",
        "git push origin main -f",
    ):
        r = _run(SECRET_GUARD, {"tool_name": "Bash", "tool_input": {"command": command}})
        assert r.returncode == 2, command


def test_secret_guard_blocks_self_approval_with_flags_after_arguments():
    r = _run(SECRET_GUARD, {
        "tool_name": "Bash",
        "tool_input": {"command": "gh pr review 123 --approve"},
    })
    assert r.returncode == 2


def test_secret_guard_blocks_bash_sensitive_path_reads():
    for command in (
        "cat .env",
        "python -c 'print(open(\".aws/credentials\").read())'",
        "head -n 1 ~/.ssh/id_rsa",
    ):
        r = _run(SECRET_GUARD, {"tool_name": "Bash", "tool_input": {"command": command}})
        assert r.returncode == 2, command


def test_audit_logger_writes_verifiable_chain(tmp_path):
    _run(AUDIT_LOGGER, {"tool_name": "Edit", "tool_input": {"file_path": "a.py"}}, cwd=tmp_path)
    _run(AUDIT_LOGGER, {"tool_name": "Bash", "tool_input": {"command": "ls"}}, cwd=tmp_path)
    audit = tmp_path / ".sre" / "audit.jsonl"
    anchor = tmp_path / ".sre" / "audit.jsonl.head"
    assert audit.exists()
    assert anchor.exists()

    # Verify with the engine's own verifier for cross-compatibility.
    sys.path.insert(0, str(ROOT / "src"))
    from sre_governance.audit import AuditLogger
    ok, msg = AuditLogger(audit).verify()
    assert ok, msg


def test_audit_logger_reports_persistence_failure(tmp_path):
    (tmp_path / ".sre").mkdir()
    (tmp_path / ".sre" / "audit.jsonl.head").mkdir()
    result = _run(AUDIT_LOGGER, {"tool_name": "Edit", "tool_input": {}}, cwd=tmp_path)
    assert result.returncode == 2
    assert "failed to write audit record" in result.stderr


def test_audit_logger_rejects_truncated_history(tmp_path):
    first = _run(AUDIT_LOGGER, {"tool_name": "Edit", "tool_input": {}}, cwd=tmp_path)
    assert first.returncode == 0
    second = _run(AUDIT_LOGGER, {"tool_name": "Edit", "tool_input": {}}, cwd=tmp_path)
    assert second.returncode == 0

    audit = tmp_path / ".sre" / "audit.jsonl"
    anchor = tmp_path / ".sre" / "audit.jsonl.head"
    retained_record = audit.read_text(encoding="utf-8").splitlines()[0]
    original_anchor = anchor.read_text(encoding="utf-8")
    audit.write_text(retained_record + "\n", encoding="utf-8")

    result = _run(AUDIT_LOGGER, {"tool_name": "Edit", "tool_input": {}}, cwd=tmp_path)
    assert result.returncode == 2
    assert "failed to write audit record" in result.stderr
    assert anchor.read_text(encoding="utf-8") == original_anchor
