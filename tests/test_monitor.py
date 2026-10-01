from pathlib import Path

import pytest
import yaml

from sre_governance.monitor import evaluate_availability, load_alert

ROOT = Path(__file__).resolve().parents[1]


def test_alert_links_to_slo_and_runs_on_schedule():
    assert load_alert(ROOT)["threshold"] == 99.9
    workflow = yaml.load(
        (ROOT / ".github/workflows/scan-observability.yml").read_text(encoding="utf-8"),
        Loader=yaml.BaseLoader,
    )
    assert "schedule" in workflow["on"]
    assert "workflow_dispatch" in workflow["on"]
    assert any("python -m sre_governance.monitor" in step.get("run", "")
               for step in workflow["jobs"]["availability"]["steps"])


def test_mismatched_alert_fails_closed(tmp_path):
    (tmp_path / ".sre").mkdir()
    (tmp_path / "observability").mkdir()
    (tmp_path / ".sre/slo.yaml").write_text(
        "slos:\n  - name: scan-availability\n    sli: successful_scans / total_scans\n"
        "    objective: 99.9\n    window: 30d\n", encoding="utf-8"
    )
    (tmp_path / "observability/alerts.yaml").write_text(
        "alerts:\n  - name: broken\n    sli: scan-availability\n"
        "    query: successful_scans / total_scans\n    threshold: 50\n    window: 30d\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="must match"):
        load_alert(tmp_path)


def test_codeql_analyzes_on_push_and_pull_requests():
    workflow = yaml.load(
        (ROOT / ".github/workflows/codeql.yml").read_text(encoding="utf-8"),
        Loader=yaml.BaseLoader,
    )
    assert {"push", "pull_request"} <= set(workflow["on"])
    steps = workflow["jobs"]["analyze"]["steps"]
    assert any(step.get("uses", "").startswith("github/codeql-action/init@") for step in steps)
    assert any(step.get("uses", "").startswith("github/codeql-action/analyze@") and
               not step.get("continue-on-error") for step in steps)


@pytest.mark.parametrize(
    ("runs", "counts", "healthy"),
    [
        ([], (0, 0), False),
        ([{"status": "completed", "event": "push", "conclusion": "success"}], (1, 1), True),
        ([{"status": "completed", "event": "push", "conclusion": "failure"}], (0, 1), False),
        ([{"status": "completed", "event": "push", "conclusion": "cancelled"}], (0, 1), False),
        ([{"status": "in_progress", "event": "push", "conclusion": None},
          {"status": "completed", "event": "pull_request", "conclusion": "success"}], (1, 1), True),
    ],
)
def test_availability_evaluation(runs, counts, healthy):
    metrics, is_healthy = evaluate_availability(runs, 99.9)
    assert (metrics["successful_scans"], metrics["total_scans"]) == counts
    assert is_healthy is healthy
