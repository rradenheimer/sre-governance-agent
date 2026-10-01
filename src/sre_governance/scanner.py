"""Repository scanner — collects deterministic signals from a repo on disk.

The scanner is read-only. It gathers:
  * the set of tracked file and directory paths (repo-relative, POSIX style),
  * the concatenated text of CI workflow files, and
  * declared governance metadata from `.sre/governance.yaml`.

Declared metadata lets teams attest to settings the agent cannot read offline
(e.g., server-side branch protection). In CI the same fields can be populated
from the GitHub API by the pipeline before invoking the engine.
"""
from __future__ import annotations

import re
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
    workflow_text: str = ""
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
    for path in _walk(root):
        rel = path.relative_to(root).as_posix()
        if path.is_dir():
            scan.dirs.add(rel)
        else:
            scan.files.add(rel)

    # Workflow text (lowercased for case-insensitive keyword checks).
    parts: list[str] = []
    for pattern in _WORKFLOW_GLOBS:
        for wf in sorted(root.glob(pattern)):
            parts.append(wf.read_text(encoding="utf-8", errors="replace"))
    scan.workflow_text = "\n".join(parts).lower()

    # Declared governance metadata.
    for mp in _METADATA_PATHS:
        meta_path = root / mp
        if meta_path.is_file():
            scan.metadata = yaml.safe_load(meta_path.read_text(encoding="utf-8")) or {}
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


def _deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for k, v in overlay.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def keyword_in_workflows(scan: RepoScan, keywords: list[str]) -> bool:
    return any(re.search(re.escape(k.lower()), scan.workflow_text) for k in keywords)
