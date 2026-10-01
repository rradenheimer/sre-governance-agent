"""Evaluate the declared scan-availability alert against GitHub Actions history."""

from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import yaml


def load_alert(root: Path) -> dict:
    slo = yaml.safe_load((root / ".sre/slo.yaml").read_text(encoding="utf-8"))
    alerts = yaml.safe_load((root / "observability/alerts.yaml").read_text(encoding="utf-8"))
    alert = next((item for item in alerts["alerts"] if item.get("sli") == "scan-availability"), None)
    declaration = next((item for item in slo["slos"] if item.get("name") == "scan-availability"), None)
    if (not alert or not declaration or alert.get("window") != declaration.get("window")
            or alert.get("query") != declaration.get("sli")
            or alert.get("threshold") != declaration.get("objective")):
        raise ValueError("scan-availability alert must match its SLO declaration")
    if (alert["window"] != "30d" or alert["query"] != "successful_scans / total_scans"
            or not isinstance(alert["threshold"], (int, float))
            or not 0 < alert["threshold"] <= 100):
        raise ValueError("unsupported scan-availability alert definition")
    return alert


def fetch_runs(repo: str, token: str, since: datetime) -> list[dict]:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo) or not token:
        raise ValueError("GITHUB_REPOSITORY and GH_TOKEN are required")
    runs: list[dict] = []
    for page in range(1, 101):
        params = urlencode({"created": f">={since:%Y-%m-%dT%H:%M:%SZ}", "per_page": 100, "page": page})
        url = f"https://api.github.com/repos/{repo}/actions/workflows/sre-governance.yml/runs?{params}"
        request = Request(url, headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        })
        with urlopen(request, timeout=30) as response:
            batch = json.load(response)["workflow_runs"]
        runs.extend(batch)
        if len(batch) < 100:
            return runs
    raise RuntimeError("scan history exceeds 10,000 runs; cannot evaluate the full 30d window")


def evaluate_availability(runs: list[dict], threshold: float) -> tuple[dict, bool]:
    completed = [run for run in runs if run["status"] == "completed" and run["event"] in {"push", "pull_request", "schedule", "workflow_dispatch"}]
    successful = sum(run["conclusion"] == "success" for run in completed)
    total = len(completed)
    percentage = successful / total * 100 if total else None
    metrics = {"successful_scans": successful, "total_scans": total, "availability_percent": percentage}
    return metrics, percentage is not None and percentage >= threshold


def main() -> int:
    root = Path(__file__).resolve().parents[2]
    alert = load_alert(root)
    since = datetime.now(timezone.utc) - timedelta(days=30)
    runs = fetch_runs(os.environ.get("GITHUB_REPOSITORY", ""), os.environ.get("GH_TOKEN", ""), since)
    metrics, healthy = evaluate_availability(runs, alert["threshold"])
    print(json.dumps({"alert": alert["name"], "window": alert["window"], "metrics": metrics}, sort_keys=True))
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as output:
            output.write(f"## {alert['name']}\n\n{metrics['successful_scans']} / {metrics['total_scans']} "
                         f"successful scans (target: {alert['threshold']}%).\n\n"
                         f"{alert['action']}\n")
    if not healthy:
        print(f"::error::{alert['name']}: {alert['action']}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
