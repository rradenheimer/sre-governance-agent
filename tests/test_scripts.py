import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(ROOT / "src"))


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


opa_gate = _load("opa_gate")
fleet = _load("fleet_aggregate")


# --------------------------- opa_gate (python fallback) ---------------------------
def test_opa_gate_compliant_report_no_deny():
    report = {"gate": {"should_fail_pipeline": False, "reasons": []},
              "results": [{"control_id": "CMP-AUDIT-033", "status": "PASS",
                           "applicability": "mandatory", "severity": "high",
                           "reason": "ok", "remediation": "-"}]}
    deny, warn = opa_gate.evaluate_python(report)
    assert deny == []


def test_opa_gate_denies_on_gate_failure():
    report = {"gate": {"should_fail_pipeline": True, "reasons": ["score too low"]},
              "results": []}
    deny, _ = opa_gate.evaluate_python(report)
    assert any("score too low" in d for d in deny)


def test_opa_gate_denies_mandatory_critical():
    report = {"gate": {"should_fail_pipeline": False, "reasons": []},
              "results": [{"control_id": "SEC-SECRETS-020", "status": "FAIL",
                           "applicability": "mandatory", "severity": "critical",
                           "reason": "no scanning", "remediation": "enable"}]}
    deny, _ = opa_gate.evaluate_python(report)
    assert any("SEC-SECRETS-020" in d for d in deny)


def test_opa_gate_denies_audit_control_failure():
    report = {"gate": {"should_fail_pipeline": False, "reasons": []},
              "results": [{"control_id": "CMP-AUDIT-033", "status": "FAIL",
                           "applicability": "mandatory", "severity": "high",
                           "reason": "off", "remediation": "enable"}]}
    deny, _ = opa_gate.evaluate_python(report)
    assert any("CMP-AUDIT-033" in d for d in deny)


def test_opa_gate_high_failure_warns_not_denies():
    report = {"gate": {"should_fail_pipeline": False, "reasons": []},
              "results": [{"control_id": "SEC-SAST-021", "status": "FAIL",
                           "applicability": "mandatory", "severity": "high",
                           "reason": "no sast", "remediation": "add codeql"}]}
    deny, warn = opa_gate.evaluate_python(report)
    assert deny == []
    assert any("SEC-SAST-021" in w for w in warn)


def test_opa_gate_main_exit_codes(tmp_path):
    good = tmp_path / "good.json"
    good.write_text(json.dumps({"profile": "commercial", "score": 100,
                                "gate": {"should_fail_pipeline": False, "reasons": []},
                                "results": []}), encoding="utf-8")
    assert opa_gate.main(["--report", str(good), "--engine", "python"]) == 0

    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"profile": "regulated", "score": 10,
                               "gate": {"should_fail_pipeline": True, "reasons": ["low"]},
                               "results": []}), encoding="utf-8")
    assert opa_gate.main(["--report", str(bad), "--engine", "python"]) == 1


def test_find_binary_ignores_python_scripts(monkeypatch):
    # Simulate shutil.which matching a local conftest.py (the Windows pitfall).
    monkeypatch.setattr(opa_gate.shutil, "which", lambda n: "/repo/conftest.py")
    assert opa_gate._find_binary("conftest") is None


# --------------------------- fleet_aggregate ---------------------------
def _report(name, profile, score, results, compliant, blocking=0):
    return {
        "_repo_name": name, "repo": name, "profile": profile, "score": score,
        "gate": {"compliant": compliant},
        "summary": {"blocking_failures": blocking, "failed": len([r for r in results if r["status"] == "FAIL"]),
                    "passed": len([r for r in results if r["status"] == "PASS"])},
        "results": results,
    }


def test_fleet_aggregate_metrics():
    reports = [
        _report("a", "commercial", 100.0, [{"control_id": "X", "status": "PASS",
                 "severity": "high", "title": "x"}], True),
        _report("b", "regulated", 20.0, [{"control_id": "SEC-SAST-021", "status": "FAIL",
                 "severity": "high", "title": "SAST"}], False, blocking=1),
    ]
    out = fleet.aggregate(reports)
    assert out["repo_count"] == 2
    assert out["compliant_count"] == 1
    assert out["compliant_pct"] == 50.0
    assert out["mean_score"] == 60.0
    top = {c["control_id"] for c in out["top_failing_controls"]}
    assert "SEC-SAST-021" in top
    # regulated minimum is 90 -> b is below minimum
    assert "b" in out["below_minimum_repos"]


def test_fleet_writes_all_outputs(tmp_path):
    reports = [_report("a", "commercial", 80.0,
                       [{"control_id": "X", "status": "PASS", "severity": "low", "title": "x"}], True)]
    out = fleet.aggregate(reports)
    fleet.write_outputs(out, tmp_path)
    assert (tmp_path / "fleet-summary.json").is_file()
    assert (tmp_path / "fleet-summary.csv").is_file()
    assert (tmp_path / "fleet-dashboard.md").is_file()
    dash = (tmp_path / "fleet-dashboard.md").read_text(encoding="utf-8")
    assert "Fleet Dashboard" in dash


def test_fleet_load_reports_filters_non_reports(tmp_path):
    (tmp_path / "not-a-report.json").write_text(json.dumps({"hello": "world"}), encoding="utf-8")
    repo = tmp_path / "repoX"
    repo.mkdir()
    # A realistic report has no _repo_name; load_reports derives it from the path.
    realistic = {"profile": "commercial", "score": 50.0,
                 "gate": {"compliant": True}, "summary": {}, "results": []}
    (repo / "sre-governance-report.json").write_text(json.dumps(realistic), encoding="utf-8")
    loaded = fleet.load_reports(tmp_path)
    assert len(loaded) == 1
    assert loaded[0]["_repo_name"] == "repoX"
