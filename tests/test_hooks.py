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


def test_secret_guard_blocks_aws_key():
    r = _run(SECRET_GUARD, {"tool_name": "Write",
                            "tool_input": {"file_path": "a.txt", "content": "AKIAIOSFODNN7EXAMPLE"}})
    assert r.returncode == 2
    assert "secret" in r.stderr.lower()


def test_secret_guard_blocks_audit_edit():
    r = _run(SECRET_GUARD, {"tool_name": "Edit",
                            "tool_input": {"file_path": ".sre/audit.jsonl", "new_string": "x"}})
    assert r.returncode == 2


def test_secret_guard_blocks_audit_anchor_edit():
    r = _run(SECRET_GUARD, {"tool_name": "Edit",
                            "tool_input": {"file_path": ".sre/audit.jsonl.head", "new_string": "x"}})
    assert r.returncode == 2


def test_secret_guard_blocks_force_push():
    r = _run(SECRET_GUARD, {"tool_name": "Bash",
                            "tool_input": {"command": "git push --force origin main"}})
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
