import pytest

from sre_governance.audit import AuditLogger


@pytest.mark.parametrize("record", ("{", "[]", '{"unexpected": true}'))
def test_verify_reports_malformed_records_without_raising(tmp_path, record):
    audit_path = tmp_path / "audit.jsonl"
    audit_path.write_text(record + "\n", encoding="utf-8")

    ok, message = AuditLogger(audit_path).verify()

    assert not ok
    assert message == "malformed audit record 1"
