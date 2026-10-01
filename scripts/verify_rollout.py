#!/usr/bin/env python3
"""Verify the health of a rollout ring from its repositories' SRE Governance runs.

For every repository in the ring, the latest `SRE Governance` workflow run on
the commit recorded by `scripts/deploy.sh` must complete successfully. The ring
is healthy when the success rate meets `health.min_scan_success_rate` from
`config/rollout-rings.yaml`. Scans still pending at the end of the soak period,
repositories without a recorded deployment, and repositories without a run all
count as failures (fail closed). Exits non-zero when the threshold is breached.

Also used by the shell scripts to read the validated ring configuration
(`--list-repos`, `--previous-ring`).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Callable
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import yaml

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = ROOT / "config" / "rollout-rings.yaml"
DEFAULT_STATE = Path("rollout-state") / "rollout-state.jsonl"
WORKFLOW_PATH = ".github/workflows/sre-governance.yml"
_REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
_RING = re.compile(r"[a-z][a-z0-9-]*")
_PROFILES = {"commercial", "regulated", "federal-defense"}


def load_config(path: Path) -> dict:
    config = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(config, dict):
        raise ValueError("rollout config must be a mapping")
    health = config.get("health")
    if not isinstance(health, dict):
        raise ValueError("rollout config requires a health section")
    rate = health.get("min_scan_success_rate")
    if isinstance(rate, bool) or not isinstance(rate, (int, float)) or not 0 < rate <= 100:
        raise ValueError("health.min_scan_success_rate must be in (0, 100]")
    for key in ("soak_minutes", "poll_seconds"):
        value = health.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ValueError(f"health.{key} must be a positive integer")
    if config.get("default_profile") not in _PROFILES:
        raise ValueError(f"default_profile must be one of {sorted(_PROFILES)}")
    rings = config.get("rings")
    if not isinstance(rings, list) or not rings:
        raise ValueError("rollout config requires at least one ring")
    seen_rings: set[str] = set()
    seen_repos: set[str] = set()
    for ring in rings:
        name = ring.get("name") if isinstance(ring, dict) else None
        if not isinstance(name, str) or not _RING.fullmatch(name) or name in seen_rings:
            raise ValueError(f"invalid or duplicate ring name: {name!r}")
        seen_rings.add(name)
        repos = ring.get("repos")
        if not isinstance(repos, list) or not repos:
            raise ValueError(f"ring {name} must list at least one repository")
        for repo in repos:
            if not isinstance(repo, str) or not _REPO.fullmatch(repo) or ".." in repo:
                raise ValueError(f"ring {name}: invalid repository {repo!r}")
            if repo in seen_repos:
                raise ValueError(f"repository {repo} is listed in more than one ring")
            seen_repos.add(repo)
    return config


def ring_names(config: dict) -> list[str]:
    return [ring["name"] for ring in config["rings"]]


def ring_repos(config: dict, ring: str) -> list[str]:
    for item in config["rings"]:
        if item["name"] == ring:
            return list(item["repos"])
    raise ValueError(f"unknown ring: {ring}")


def previous_ring(config: dict, ring: str) -> str:
    names = ring_names(config)
    if ring not in names:
        raise ValueError(f"unknown ring: {ring}")
    index = names.index(ring)
    if index == 0:
        raise ValueError(f"ring {ring} is the first ring; deploy it with deploy.sh")
    return names[index - 1]


def deployed_commits(state_path: Path, ring: str) -> dict[str, str]:
    """Map repo -> commit SHA whose scan proves the ring's deployment."""
    commits: dict[str, str] = {}
    if not Path(state_path).is_file():
        return commits
    for line in Path(state_path).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        entry = json.loads(line)
        if entry.get("ring") == ring and entry.get("phase") == "deployed" and entry.get("head_sha"):
            commits[entry["repo"]] = entry["head_sha"]
    return commits


def fetch_runs(repo: str, head_sha: str, token: str) -> list[dict]:
    if not _REPO.fullmatch(repo) or not re.fullmatch(r"[0-9a-f]{40}", head_sha) or not token:
        raise ValueError("a valid repository, commit SHA, and GH_TOKEN are required")
    params = urlencode({"head_sha": head_sha, "per_page": 100})
    request = Request(f"https://api.github.com/repos/{repo}/actions/runs?{params}", headers={
        "Authorization": "Bearer " + token,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    with urlopen(request, timeout=30) as response:
        return json.load(response)["workflow_runs"]


def scan_status(runs: list[dict]) -> str:
    """Return success | failure | pending for the latest SRE Governance run."""
    scans = [run for run in runs if str(run.get("path", "")).split("@")[0] == WORKFLOW_PATH]
    if not scans:
        return "pending"
    latest = max(scans, key=lambda run: (run.get("created_at", ""), run.get("id", 0)))
    if latest.get("status") != "completed":
        return "pending"
    return "success" if latest.get("conclusion") == "success" else "failure"


def evaluate(statuses: dict[str, str], threshold: float) -> tuple[dict, bool]:
    total = len(statuses)
    successful = sum(status == "success" for status in statuses.values())
    rate = successful / total * 100 if total else None
    metrics = {"successful_scans": successful, "total_repos": total, "success_rate_percent": rate,
               "threshold_percent": threshold, "statuses": dict(sorted(statuses.items()))}
    return metrics, rate is not None and rate >= threshold


def observe(repos: list[str], commits: dict[str, str], threshold: float,
            fetch: Callable[[str, str], list[dict]], soak_seconds: float, poll_seconds: float,
            sleep: Callable[[float], None] = time.sleep,
            clock: Callable[[], float] = time.monotonic) -> tuple[dict, bool]:
    """Poll until every scan completes, the threshold becomes unreachable, or soak ends."""
    statuses = {repo: ("pending" if repo in commits else "not_deployed") for repo in repos}
    deadline = clock() + soak_seconds
    while True:
        for repo, status in statuses.items():
            if status == "pending":
                try:
                    statuses[repo] = scan_status(fetch(repo, commits[repo]))
                except (OSError, ValueError, KeyError) as exc:
                    print(f"::warning::{repo}: scan status unavailable ({type(exc).__name__}); "
                          "retrying until the soak period ends", file=sys.stderr)
        pending = sum(status == "pending" for status in statuses.values())
        best_case = sum(status in {"success", "pending"} for status in statuses.values())
        unreachable = not repos or best_case / len(repos) * 100 < threshold
        if not pending or unreachable or clock() >= deadline:
            break
        sleep(min(poll_seconds, max(deadline - clock(), 0)))
    final = {repo: ("failure_timeout" if status == "pending" else status)
             for repo, status in statuses.items()}
    return evaluate(final, threshold)


def _is_dry_run(flag: bool) -> bool:
    return flag or os.environ.get("ROLLOUT_DRY_RUN", "").lower() == "true"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--ring", required=True)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--state", type=Path,
                        default=Path(os.environ.get("ROLLOUT_STATE", DEFAULT_STATE)))
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--list-repos", action="store_true", help="print the ring's repositories")
    parser.add_argument("--previous-ring", action="store_true", help="print the preceding ring")
    parser.add_argument("--default-profile", action="store_true",
                        help="print the profile scaffolded into repos without one")
    args = parser.parse_args(argv)

    try:
        config = load_config(args.config)
        repos = ring_repos(config, args.ring)
        if args.list_repos:
            print("\n".join(repos))
            return 0
        if args.previous_ring:
            print(previous_ring(config, args.ring))
            return 0
        if args.default_profile:
            print(config["default_profile"])
            return 0
    except (OSError, ValueError, yaml.YAMLError) as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 2

    health = config["health"]
    threshold = health["min_scan_success_rate"]
    if _is_dry_run(args.dry_run):
        print(f"DRY RUN: would verify ring {args.ring} ({len(repos)} repos) against "
              f"{threshold}% scan success within {health['soak_minutes']}m")
        return 0

    token = os.environ.get("GH_TOKEN", "")
    commits = deployed_commits(args.state, args.ring)
    metrics, healthy = observe(
        repos, commits, threshold, lambda repo, sha: fetch_runs(repo, sha, token),
        soak_seconds=health["soak_minutes"] * 60, poll_seconds=health["poll_seconds"],
    )
    print(json.dumps({"ring": args.ring, "healthy": healthy, "metrics": metrics}, sort_keys=True))
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as output:
            output.write(f"## Rollout ring `{args.ring}`\n\n{metrics['successful_scans']} / "
                         f"{metrics['total_repos']} repos passed SRE Governance "
                         f"(threshold: {threshold}%): {'healthy' if healthy else 'BREACHED'}\n")
    if not healthy:
        print(f"::error::ring {args.ring} breached the health threshold ({threshold}%)",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
