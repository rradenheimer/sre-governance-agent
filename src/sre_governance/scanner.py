"""Repository scanner — collects deterministic signals from a repo on disk.

The scanner is read-only. It gathers:
  * the set of tracked file and directory paths (repo-relative, POSIX style),
  * parsed CI workflow definitions, and
  * declared governance metadata from `.sre/governance.yaml`.

Declared metadata lets teams attest to settings the agent cannot read offline
(e.g., server-side branch protection). In CI the same fields can be populated
from the GitHub API by the pipeline before invoking the engine.
"""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

_IGNORE_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".mypy_cache"}
_WORKFLOW_GLOBS = (".github/workflows/*.yml", ".github/workflows/*.yaml")
_METADATA_PATHS = (".sre/governance.yaml", ".sre/governance.yml")


@dataclass
class RepoScan:
    root: Path
    files: set[str] = field(default_factory=set)
    dirs: set[str] = field(default_factory=set)
    workflows: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def has_path(self, candidate: str) -> bool:
        """True if a file or directory matching `candidate` exists.

        A trailing '/' means directory. A bare name matches a file OR a dir.
        """
        candidate = candidate.strip()
        if candidate.endswith("/"):
            return candidate.rstrip("/") in self.dirs
        return candidate in self.files or candidate in self.dirs

    def read_text(self, relpath: str) -> str:
        if relpath not in self.files:
            return ""
        p = self.root / relpath
        if p.is_file():
            return p.read_text(encoding="utf-8", errors="replace")
        return ""

    def metadata_value(self, dotted_key: str) -> Any:
        node: Any = self.metadata
        for part in dotted_key.split("."):
            if isinstance(node, dict) and part in node:
                node = node[part]
            else:
                return None
        return node


def scan_repo(root: str | Path) -> RepoScan:
    root = Path(root).resolve()
    if not root.is_dir():
        raise NotADirectoryError(f"Repo path is not a directory: {root}")

    scan = RepoScan(root=root)
    tracked_paths = _tracked_paths(root)
    if tracked_paths is None:
        paths = _walk(root)
        for path in paths:
            rel = path.relative_to(root).as_posix()
            if path.is_dir():
                scan.dirs.add(rel)
            else:
                scan.files.add(rel)
    else:
        for rel in tracked_paths:
            path = root / rel
            if not path.exists() or any(part in _IGNORE_DIRS for part in Path(rel).parts):
                continue
            if path.is_file():
                scan.files.add(rel)
            parent = path.parent
            while parent != root:
                if parent.is_dir():
                    scan.dirs.add(parent.relative_to(root).as_posix())
                parent = parent.parent

    for rel in sorted(scan.files):
        if Path(rel).parent.as_posix() != ".github/workflows" or not rel.endswith((".yml", ".yaml")):
            continue
        try:
            workflow = yaml.load(scan.read_text(rel), Loader=yaml.BaseLoader)
        except yaml.YAMLError:
            continue
        if isinstance(workflow, dict):
            scan.workflows.append(workflow)

    # Declared governance metadata.
    for mp in _METADATA_PATHS:
        if mp in scan.files:
            scan.metadata = yaml.safe_load(scan.read_text(mp)) or {}
            break

    return scan


def merge_api_metadata(scan: RepoScan, api_metadata: dict[str, Any]) -> RepoScan:
    """Overlay authoritative metadata (e.g., from the GitHub API) onto declared.

    API-sourced values win over declared values so pipelines reflect reality.
    """
    scan.metadata = _deep_merge(scan.metadata, api_metadata)
    return scan


def _walk(root: Path):
    for path in root.rglob("*"):
        if any(part in _IGNORE_DIRS for part in path.relative_to(root).parts):
            continue
        yield path


def _tracked_paths(root: Path) -> list[str] | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"],
            check=True, capture_output=True, text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return [path for path in result.stdout.split("\0") if path]


def _deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for k, v in overlay.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def keyword_in_workflows(scan: RepoScan, keywords: list[str]) -> bool:
    terms = [re.compile(re.escape(keyword), re.IGNORECASE) for keyword in keywords]
    for workflow in scan.workflows:
        values: list[str] = []
        triggers = workflow.get("on", {})
        if isinstance(triggers, dict):
            values.extend(str(value) for value in triggers)
        elif isinstance(triggers, list):
            values.extend(str(value) for value in triggers)
        elif triggers:
            values.append(str(triggers))

        jobs = workflow.get("jobs", {})
        if not isinstance(jobs, dict):
            continue
        for job_id, job in jobs.items():
            values.append(str(job_id))
            if not isinstance(job, dict):
                continue
            values.append(str(job.get("name", "")))
            steps = job.get("steps", [])
            if not isinstance(steps, list):
                continue
            for step in steps:
                if not isinstance(step, dict):
                    continue
                values.extend(str(step.get(key, "")) for key in ("name", "run"))
                uses = str(step.get("uses", ""))
                if not uses.lower().endswith("/upload-sarif@v3") and "upload-sarif" not in uses.lower():
                    values.append(uses)
        if any(term.search(value) for term in terms for value in values):
            return True
    return False


def has_sast_workflow(scan: RepoScan) -> bool:
    for workflow in scan.workflows:
        triggers = workflow.get("on", {})
        if isinstance(triggers, dict):
            trigger_names = set(triggers)
        elif isinstance(triggers, list):
            trigger_names = set(triggers)
        else:
            trigger_names = {triggers} if triggers else set()
        if not {"pull_request", "push"}.issubset(trigger_names):
            continue

        jobs = workflow.get("jobs", {})
        if not isinstance(jobs, dict):
            continue
        for job in jobs.values():
            if not isinstance(job, dict):
                continue
            steps = job.get("steps", [])
            if not isinstance(steps, list):
                continue
            for step in steps:
                if not isinstance(step, dict):
                    continue
                uses = str(step.get("uses", "")).lower()
                if re.search(r"github/codeql-action/analyze@", uses):
                    return True
                if re.search(r"(?:semgrep/semgrep|returntocorp/semgrep-action)@", uses):
                    return True
                run = str(step.get("run", "")).lower()
                command = (
                    r"(?m)^\s*(?:(?:[a-z_][a-z0-9_]*=\S+)\s+)*"
                    r"(?:python(?:\d+(?:\.\d+)?)?\s+-m\s+)?"
                    r"(?:bandit|semgrep|snyk\s+code\s+test|codeql\s+database\s+analyze)(?:\s|$)"
                )
                if re.search(command, run):
                    return True
    return False


def has_slo_linked_observability(scan: RepoScan) -> bool:
    slo_data = None
    for path in (".sre/slo.yaml", ".sre/slo.yml"):
        text = scan.read_text(path)
        if text:
            try:
                slo_data = yaml.safe_load(text)
            except yaml.YAMLError:
                return False
            break
    if not isinstance(slo_data, dict):
        return False

    sli_names: set[str] = set()
    for slo in slo_data.get("slos", []) or []:
        if isinstance(slo, dict):
            sli_names.update(
                str(slo[key]).strip().lower()
                for key in ("name", "sli")
                if slo.get(key)
            )
    if not sli_names:
        return False

    def valid_alerts(value: Any) -> bool:
        if isinstance(value, dict):
            for key, child in value.items():
                if isinstance(key, str) and key.lower() in {"alerts", "rules"} and isinstance(child, list):
                    for alert in child:
                        if not isinstance(alert, dict):
                            continue
                        sli = str(alert.get("sli", "")).strip().lower()
                        has_query = any(alert.get(key) for key in ("query", "expr", "expression", "condition"))
                        if alert.get("name") and sli in sli_names and has_query:
                            return True
                if valid_alerts(child):
                    return True
        elif isinstance(value, list):
            return any(valid_alerts(child) for child in value)
        return False

    for rel in scan.files:
        if not rel.endswith((".yaml", ".yml")):
            continue
        if not (rel.startswith(("observability/", "monitoring/")) or rel in {".sre/alerts.yaml", ".sre/alerts.yml"}):
            continue
        try:
            data = yaml.safe_load(scan.read_text(rel))
        except yaml.YAMLError:
            continue
        if valid_alerts(data):
            return True
    return False
