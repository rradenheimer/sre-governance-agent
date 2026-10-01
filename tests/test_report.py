import json
from pathlib import Path

from sre_governance.audit import AuditLogger
from sre_governance.catalog import load_catalog, load_profiles
from sre_governance.engine import evaluate
from sre_governance.report import render_json, render_markdown, render_sarif
from sre_governance.scanner import scan_repo

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "config" / "control-catalog.yaml"
PROFILES = ROOT / "config" / "industry-profiles"
GOOD = ROOT / "tests" / "fixtures" / "good-repo"


def _assessment():
    catalog = load_catalog(CATALOG)
    profiles = load_profiles(PROFILES)
    return evaluate(scan_repo(GOOD), catalog, profiles["regulated"]), catalog


def test_markdown_report_contains_key_sections():
    assessment, catalog = _assessment()
    md = render_markdown(assessment, "Regulated", catalog.version)
    assert "SRE Governance Report" in md
    assert "Compliance score" in md
    assert "All controls" in md


def test_json_report_is_valid_and_has_provenance():
    assessment, catalog = _assessment()
    payload = json.loads(render_json(assessment, catalog.version))
    assert payload["provenance"]["generator"] == "sre-governance-agent"
    assert "results" in payload and len(payload["results"]) >= 20
    assert "gate" in payload


def test_sarif_is_valid_schema_shape():
    assessment, catalog = _assessment()
    sarif = json.loads(render_sarif(assessment))
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "SRE-Governance-Agent"


def test_audit_chain_detects_tampering(tmp_path):
    log = tmp_path / "audit.jsonl"
    logger = AuditLogger(log, actor="test")
    logger.record("scan", target="repo-a")
    logger.record("report", target="repo-a")
    ok, msg = logger.verify()
    assert ok, msg

    # Tamper with the first record.
    lines = log.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[0])
    rec["details"] = {"evil": True}
    lines[0] = json.dumps(rec, sort_keys=True)
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok, msg = AuditLogger(log).verify()
    assert not ok
    assert "tampered" in msg or "broken" in msg
