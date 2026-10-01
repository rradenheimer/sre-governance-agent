import pytest

from sre_governance.audit import AuditLogger


@pytest.mark.parametrize("record", ("{", "[]", '{"unexpected": true}'))
def test_verify_reports_malformed_records_without_raising(tmp_path, record):
    audit_path = tmp_path / "audit.jsonl"
    audit_path.write_text(record + "\n", encoding="utf-8")

    ok, message = AuditLogger(audit_path).verify()

    assert not ok
    assert message == "malformed audit record 1"


def test_record_rejects_truncated_history_without_replacing_anchor(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    logger = AuditLogger(audit_path)
    logger.record("scan", target="one")
    logger.record("scan", target="two")
    original_anchor = logger.anchor_path.read_text(encoding="utf-8")
    first_record = audit_path.read_text(encoding="utf-8").splitlines()[0]
    audit_path.write_text(first_record + "\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="refusing to append"):
        logger.record("scan", target="three")

    assert logger.anchor_path.read_text(encoding="utf-8") == original_anchor
