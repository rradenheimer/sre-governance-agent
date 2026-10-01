#!/usr/bin/env python3
"""Fleet aggregation for the SRE Governance Agent.

Rolls up governance results across many repositories into org-wide reporting:
a JSON summary (for dashboards/warehouses), a CSV (one row per repo), and a
Markdown dashboard (for humans / wiki).

Two input modes:

  1. Scan a directory of repos (runs the deterministic engine on each):
       python scripts/fleet_aggregate.py scan --repos-root /path/to/org \
           --out fleet-reports [--default-profile commercial]

  2. Aggregate pre-generated JSON reports (e.g., downloaded CI artifacts):
       python scripts/fleet_aggregate.py aggregate --reports-dir ./artifacts \
           --out fleet-reports

Reported metrics: repo count, mean/median compliance score, compliant count &
percentage, repos below their profile minimum, breakdown by profile, and the top
failing controls across the fleet (for targeted remediation campaigns).
"""
from __future__ import annotations

import argparse
import csv
import json
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

DEFAULT_CATALOG = ROOT / "config" / "control-catalog.yaml"
DEFAULT_PROFILES = ROOT / "config" / "industry-profiles"


# --------------------------------------------------------------------------
# Input collection
# --------------------------------------------------------------------------
def _looks_like_repo(path: Path) -> bool:
    return path.is_dir() and (
        (path / ".git").exists()
        or (path / ".sre" / "profile").is_file()
        or (path / ".sre" / "governance.yaml").is_file()
    )


def scan_fleet(repos_root: Path, default_profile: str) -> list[dict[str, Any]]:
    from sre_governance.catalog import load_catalog, load_profiles
    from sre_governance.engine import evaluate
    from sre_governance.report import render_json
    from sre_governance.scanner import scan_repo

    catalog = load_catalog(DEFAULT_CATALOG)
    profiles = load_profiles(DEFAULT_PROFILES)

    reports: list[dict[str, Any]] = []
    for child in sorted(repos_root.iterdir()):
        if not _looks_like_repo(child):
            continue
        profile_name = default_profile
        pf = child / ".sre" / "profile"
        if pf.is_file():
            profile_name = pf.read_text(encoding="utf-8").strip() or default_profile
        if profile_name not in profiles:
            print(f"  ! {child.name}: unknown profile '{profile_name}', skipping", file=sys.stderr)
            continue
        assessment = evaluate(scan_repo(child), catalog, profiles[profile_name])
        report = json.loads(render_json(assessment, catalog.version))
        report["_repo_name"] = child.name
        reports.append(report)
        print(f"  - {child.name}: {report['score']}% "
              f"({'COMPLIANT' if report['gate']['compliant'] else 'NON-COMPLIANT'})")
    return reports


def load_reports(reports_dir: Path) -> list[dict[str, Any]]:
    reports: list[dict[str, Any]] = []
    for jf in sorted(reports_dir.rglob("*.json")):
        try:
            data = json.loads(jf.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        if not ({"results", "gate", "score"} <= set(data)):
            continue  # not a governance report
        data.setdefault("_repo_name", _repo_name_from_path(jf))
        reports.append(data)
    return reports


def _repo_name_from_path(path: Path) -> str:
    # artifacts are often <repo>/sre-governance-report.json or <repo>.json
    if path.stem not in ("sre-governance-report",):
        return path.stem
    return path.parent.name


# --------------------------------------------------------------------------
# Aggregation
# --------------------------------------------------------------------------
def _profile_minimums() -> dict[str, float]:
    try:
        from sre_governance.catalog import load_profiles
        return {name: p.thresholds.get("min_compliance_score", 0)
                for name, p in load_profiles(DEFAULT_PROFILES).items()}
    except Exception:
        return {}


def aggregate(reports: list[dict[str, Any]]) -> dict[str, Any]:
    minimums = _profile_minimums()
    rows: list[dict[str, Any]] = []
    scores: list[float] = []
    by_profile: dict[str, list[float]] = defaultdict(list)
    control_failures: Counter = Counter()
    control_meta: dict[str, dict[str, str]] = {}
    below_minimum: list[str] = []

    for rep in reports:
        name = rep.get("_repo_name", rep.get("repo", "unknown"))
        profile = rep.get("profile", "unknown")
        score = float(rep.get("score", 0))
        gate = rep.get("gate", {})
        summary = rep.get("summary", {})
        scores.append(score)
        by_profile[profile].append(score)

        minimum = minimums.get(profile)
        is_below = minimum is not None and score < minimum
        if is_below:
            below_minimum.append(name)

        for r in rep.get("results", []):
            if r.get("status") == "FAIL":
                cid = r.get("control_id", "?")
                control_failures[cid] += 1
                control_meta[cid] = {
                    "title": r.get("title", ""),
                    "severity": r.get("severity", ""),
                }

        rows.append({
            "repo": name,
            "profile": profile,
            "score": score,
            "compliant": bool(gate.get("compliant")),
            "below_minimum": is_below,
            "blocking_failures": summary.get("blocking_failures", 0),
            "failed": summary.get("failed", 0),
            "passed": summary.get("passed", 0),
        })

    rows.sort(key=lambda r: r["score"])
    total = len(rows)
    compliant = sum(1 for r in rows if r["compliant"])

    fleet = {
        "generated_by": "fleet_aggregate.py",
        "repo_count": total,
        "compliant_count": compliant,
        "compliant_pct": round(compliant / total * 100, 1) if total else 0.0,
        "below_minimum_count": len(below_minimum),
        "below_minimum_repos": below_minimum,
        "mean_score": round(statistics.mean(scores), 1) if scores else 0.0,
        "median_score": round(statistics.median(scores), 1) if scores else 0.0,
        "min_score": min(scores) if scores else 0.0,
        "max_score": max(scores) if scores else 0.0,
        "by_profile": {
            p: {
                "repos": len(v),
                "mean_score": round(statistics.mean(v), 1) if v else 0.0,
            }
            for p, v in sorted(by_profile.items())
        },
        "top_failing_controls": [
            {
                "control_id": cid,
                "title": control_meta[cid]["title"],
                "severity": control_meta[cid]["severity"],
                "failing_repos": count,
                "failing_pct": round(count / total * 100, 1) if total else 0.0,
            }
            for cid, count in control_failures.most_common(15)
        ],
        "repos": rows,
    }
    return fleet


# --------------------------------------------------------------------------
# Output rendering
# --------------------------------------------------------------------------
def write_outputs(fleet: dict[str, Any], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "fleet-summary.json").write_text(json.dumps(fleet, indent=2), encoding="utf-8")

    with (out_dir / "fleet-summary.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=[
            "repo", "profile", "score", "compliant", "below_minimum",
            "blocking_failures", "failed", "passed"])
        writer.writeheader()
        for row in fleet["repos"]:
            writer.writerow(row)

    (out_dir / "fleet-dashboard.md").write_text(render_dashboard(fleet), encoding="utf-8")


def render_dashboard(fleet: dict[str, Any]) -> str:
    L: list[str] = []
    L.append("# SRE Governance — Fleet Dashboard")
    L.append("")
    L.append(f"**Repositories:** {fleet['repo_count']}  ")
    L.append(f"**Compliant:** {fleet['compliant_count']} "
             f"({fleet['compliant_pct']}%)  ")
    L.append(f"**Below profile minimum:** {fleet['below_minimum_count']}  ")
    L.append(f"**Mean score:** {fleet['mean_score']}%  ·  "
             f"**Median:** {fleet['median_score']}%  ·  "
             f"**Range:** {fleet['min_score']}–{fleet['max_score']}%")
    L.append("")

    L.append("## By profile")
    L.append("")
    L.append("| Profile | Repos | Mean score |")
    L.append("|---|---|---|")
    for p, v in fleet["by_profile"].items():
        L.append(f"| `{p}` | {v['repos']} | {v['mean_score']}% |")
    L.append("")

    L.append("## Top failing controls (fleet-wide remediation targets)")
    L.append("")
    L.append("| Control | Severity | Failing repos | % of fleet |")
    L.append("|---|---|---|---|")
    for c in fleet["top_failing_controls"]:
        L.append(f"| `{c['control_id']}` {c['title']} | {c['severity']} "
                 f"| {c['failing_repos']} | {c['failing_pct']}% |")
    L.append("")

    L.append("## Repositories (lowest score first)")
    L.append("")
    L.append("| Repo | Profile | Score | Compliant | Below min | Blocking fails |")
    L.append("|---|---|---|---|---|---|")
    for r in fleet["repos"]:
        L.append(f"| {r['repo']} | `{r['profile']}` | {r['score']}% "
                 f"| {'✅' if r['compliant'] else '❌'} "
                 f"| {'⚠️' if r['below_minimum'] else '—'} | {r['blocking_failures']} |")
    L.append("")
    L.append("---")
    L.append("")
    L.append("_Generated by `scripts/fleet_aggregate.py`. Scores come from the "
             "deterministic policy engine; aggregation adds no judgment._")
    L.append("")
    return "\n".join(L)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Aggregate SRE governance results across a fleet")
    sub = ap.add_subparsers(dest="mode", required=True)

    sp = sub.add_parser("scan", help="Scan every repo under a root directory")
    sp.add_argument("--repos-root", required=True)
    sp.add_argument("--default-profile", default="commercial")
    sp.add_argument("--out", default="fleet-reports")

    sp = sub.add_parser("aggregate", help="Aggregate pre-generated JSON reports")
    sp.add_argument("--reports-dir", required=True)
    sp.add_argument("--out", default="fleet-reports")

    args = ap.parse_args(argv)

    if args.mode == "scan":
        root = Path(args.repos_root)
        if not root.is_dir():
            print(f"ERROR: repos-root not found: {root}", file=sys.stderr)
            return 2
        print(f">> Scanning repositories under {root}")
        reports = scan_fleet(root, args.default_profile)
    else:
        rdir = Path(args.reports_dir)
        if not rdir.is_dir():
            print(f"ERROR: reports-dir not found: {rdir}", file=sys.stderr)
            return 2
        print(f">> Loading reports from {rdir}")
        reports = load_reports(rdir)

    if not reports:
        print("No governance reports found.", file=sys.stderr)
        return 1

    fleet = aggregate(reports)
    out_dir = Path(args.out)
    write_outputs(fleet, out_dir)

    print("-" * 68)
    print(f"Repos: {fleet['repo_count']}  |  Compliant: {fleet['compliant_count']} "
          f"({fleet['compliant_pct']}%)  |  Mean: {fleet['mean_score']}%  |  "
          f"Below min: {fleet['below_minimum_count']}")
    print(f"Outputs written to: {out_dir}/ (fleet-summary.json, fleet-summary.csv, fleet-dashboard.md)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
