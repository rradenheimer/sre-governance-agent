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
import shlex
import subprocess
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

import yaml

_IGNORE_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".mypy_cache"}
_WORKFLOW_GLOBS = (".github/workflows/*.yml", ".github/workflows/*.yaml")
_METADATA_PATHS = (".sre/governance.yaml", ".sre/governance.yml")
_RENOVATE_MANAGERS = {
    "ansible", "argocd", "asdf", "azure-pipelines", "bazel", "bitbucket-pipelines",
    "buildkite", "cargo", "circleci", "cloudbuild", "cocoapods", "composer",
    "devcontainer", "docker-compose", "dockerfile", "drone", "flux", "github-actions",
    "gitlabci", "gomod", "gradle", "gradle-wrapper", "helm-values", "helmv3",
    "kubernetes", "maven", "npm", "nuget", "pep621", "pip_requirements", "pip_setup",
    "pipenv", "poetry", "pre-commit", "regex", "repology", "sbt", "swift",
    "terraform", "terragrunt", "vscode", "woodpecker",
}


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
        try:
            p = (self.root / relpath).resolve()
            p.relative_to(self.root)
        except (OSError, RuntimeError, ValueError):
            return ""
        resolved_relpath = p.relative_to(self.root).as_posix()
        if resolved_relpath != relpath and resolved_relpath not in self.files:
            return ""
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


def _workflow_triggers(workflow: dict[str, Any]) -> set[str]:
    triggers = workflow.get("on", {})
    if isinstance(triggers, dict):
        return set(triggers)
    if isinstance(triggers, list):
        return set(triggers)
    return {triggers} if triggers else set()


def _workflow_steps(workflow: dict[str, Any]):
    jobs = workflow.get("jobs", {})
    if not isinstance(jobs, dict):
        return
    for job in jobs.values():
        if not isinstance(job, dict):
            continue
        steps = job.get("steps", [])
        if not isinstance(steps, list):
            continue
        for step in steps:
            if isinstance(step, dict):
                yield step


def _commands(run: str, pattern: str, required: str | None = None) -> bool:
    lines = run.splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        index += 1
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        command = line
        while command.rstrip().endswith("\\") and index < len(lines):
            command = command.rstrip()[:-1] + " " + lines[index].strip()
            index += 1
        if re.search(pattern, line, re.IGNORECASE) and (
            required is None or re.search(required, command, re.IGNORECASE)
        ):
            return True
    return False


def has_safe_change_workflow(scan: RepoScan) -> bool:
    deploy_actions = (
        "azure/webapps-deploy@",
        "aws-actions/amazon-ecs-deploy-task-definition@",
        "google-github-actions/deploy-cloudrun@",
        "deliverybot/helm@",
    )
    deploy_command = r"^\s*(?:sudo\s+)?(?:kubectl\s+apply|helm\s+upgrade|terraform\s+apply|ansible-playbook|\.?/[\w./-]*deploy[\w./-]*)(?:\s|$)"
    rollout = re.compile(r"(?:--canary\b|--blue-green\b|--strategy(?:=|\s+)(?:rolling|canary|blue-green)|kubectl\s+rollout\b)", re.I)
    for workflow in scan.workflows:
        if not _workflow_triggers(workflow).intersection({"push", "workflow_dispatch", "release"}):
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
            deployment = staged = tested = promoted = rolled_back = False
            for step in steps:
                if not isinstance(step, dict):
                    continue
                uses = str(step.get("uses", "")).lower()
                run = str(step.get("run", ""))
                config = step.get("with", {})
                if any(uses.startswith(action) for action in deploy_actions):
                    deployment = True
                    if isinstance(config, dict) and any(
                        rollout.search(f"{key} {value}") for key, value in config.items()
                    ):
                        staged = True
                if _commands(run, deploy_command):
                    deployment = True
                    staged |= bool(rollout.search(run))
                tested |= _commands(
                    run, r"^\s*(?:pytest|tox|npm\s+test|yarn\s+test|pnpm\s+test|go\s+test|cargo\s+test)\b"
                )
                promoted |= _commands(
                    run, r"^\s*(?:kubectl\s+rollout\s+resume|helm\s+upgrade|[\w./-]*promote[\w./-]*)\b"
                )
                rolled_back |= _commands(
                    run, r"^\s*(?:kubectl\s+rollout\s+undo|helm\s+rollback|[\w./-]*rollback[\w./-]*)\b"
                )
            if (
                deployment and staged and tested and promoted and rolled_back
                and job.get("environment")
            ):
                return True
    return False


def has_sbom_workflow(scan: RepoScan) -> bool:
    for workflow in scan.workflows:
        triggers = _workflow_triggers(workflow)
        push = workflow.get("on", {}).get("push", {}) if isinstance(workflow.get("on"), dict) else {}
        tagged_release = isinstance(push, dict) and bool(push.get("tags"))
        if not triggers.intersection({"release", "workflow_dispatch"}) and not tagged_release:
            continue
        steps = list(_workflow_steps(workflow))
        generated_paths: set[str] = set()
        published_patterns: set[str] = set()
        for step in steps:
            uses = str(step.get("uses", "")).lower()
            run = str(step.get("run", ""))
            config = step.get("with", {})
            if uses.startswith("anchore/sbom-action@") and isinstance(config, dict) \
                    and config.get("output-file"):
                generated_paths.add(str(config["output-file"]).strip())
            for command in _command_lines(run):
                if re.match(r"^\s*(?:syft|cyclonedx|trivy\s+fs)\b", command, re.IGNORECASE):
                    output = re.search(
                        r"(?:>\s*|--output(?:=|\s+))([^\s;&|]+)", command, re.IGNORECASE,
                    )
                    if output:
                        generated_paths.add(output.group(1).strip("'\""))
                if re.match(r"^\s*gh\s+release\s+(?:create|upload)\b", command, re.IGNORECASE):
                    try:
                        tokens = shlex.split(command)
                    except ValueError:
                        continue
                    command_index = next(
                        (i for i, token in enumerate(tokens)
                         if token == "release" and i > 0 and tokens[i - 1] == "gh"),
                        -1,
                    )
                    if command_index >= 0:
                        for token in tokens[command_index + 2:]:
                            if not token.startswith("-"):
                                published_patterns.add(token)
            if uses.startswith(("softprops/action-gh-release@", "ncipollo/release-action@")) \
                    and isinstance(config, dict) and config.get("files"):
                files = config["files"]
                if isinstance(files, str):
                    published_patterns.update(
                        line.strip() for line in files.splitlines() if line.strip()
                    )
                elif isinstance(files, list):
                    published_patterns.update(
                        str(path).strip() for path in files if str(path).strip()
                    )
        if any(
            fnmatchcase(generated, published)
            for generated in generated_paths for published in published_patterns
        ):
            return True
    return False


def _command_lines(run: str):
    lines = run.splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        index += 1
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        command = line
        while command.rstrip().endswith("\\") and index < len(lines):
            command = command.rstrip()[:-1] + " " + lines[index].strip()
            index += 1
        yield command


def has_iac_workflow(scan: RepoScan) -> bool:
    scanner_actions = (
        "bridgecrewio/checkov-action@",
        "aquasecurity/tfsec-action@",
        "tenable/terrascan-action@",
    )
    scanner_command = r"^\s*(?:python(?:\d+(?:\.\d+)?)?\s+-m\s+)?(?:checkov|tfsec|terrascan|kics)(?:\s|$)"
    for workflow in scan.workflows:
        if not {"push", "pull_request"}.issubset(_workflow_triggers(workflow)):
            continue
        for step in _workflow_steps(workflow):
            uses = str(step.get("uses", "")).lower()
            if any(uses.startswith(action) for action in scanner_actions):
                return True
            if _commands(str(step.get("run", "")), scanner_command):
                return True
    return False


def has_sca_configuration(scan: RepoScan) -> bool:
    configs = (
        ".github/dependabot.yml", ".github/dependabot.yaml",
        "renovate.json", ".renovaterc",
    )
    enabled = False
    for path in configs:
        if path not in scan.files:
            continue
        try:
            data = yaml.safe_load(scan.read_text(path))
        except yaml.YAMLError:
            continue
        if path.endswith(("dependabot.yml", "dependabot.yaml")):
            updates = data.get("updates") if isinstance(data, dict) else None
            configured = isinstance(data, dict) and data.get("version") == 2 \
                and isinstance(updates, list) \
                and any(_dependabot_update_enabled(item) for item in updates)
        else:
            configured = _renovate_enabled(data)
        if configured:
            enabled = True
            break
    if not enabled:
        return False


    for workflow in scan.workflows:
        if "pull_request" not in _workflow_triggers(workflow):
            continue
        jobs = workflow.get("jobs", {})
        if not isinstance(jobs, dict):
            continue
        for job in jobs.values():
            if not isinstance(job, dict) or _continues_on_error(job):
                continue
            steps = job.get("steps", [])
            if not isinstance(steps, list):
                continue
            for step in steps:
                if not isinstance(step, dict) or _continues_on_error(step):
                    continue
                uses = str(step.get("uses", "")).lower()
                config = step.get("with", {})
                if uses.startswith("actions/dependency-review-action@") \
                        and isinstance(config, dict) \
                        and str(config.get("fail-on-severity", "")).lower() == "critical":
                    return True
                if uses.startswith("aquasecurity/trivy-action@") and isinstance(config, dict) \
                        and "CRITICAL" in str(config.get("severity", "")).upper() \
                        and str(config.get("exit-code", "")) == "1":
                    return True
                run = str(step.get("run", ""))
                if _commands(
                    run,
                    r"^\s*(?:npm\s+audit\s+--audit-level=critical|pip-audit|"
                    r"snyk\s+test\s+--severity-threshold=critical|osv-scanner)\b",
                ):
                    return True
    return False


def _dependabot_update_enabled(item: Any) -> bool:
    ecosystems = {
        "bazel", "bun", "bundler", "cargo", "composer", "conda", "deno",
        "devcontainers", "docker", "docker-compose", "dotnet-sdk", "elm",
        "gitsubmodule", "github-actions", "gomod", "gradle", "helm", "julia",
        "maven", "mix", "nix", "npm", "nuget", "opentofu", "pip", "pre-commit",
        "pub", "rust-toolchain", "sbt", "swift", "terraform", "uv", "vcpkg",
    }
    if not isinstance(item, dict) or item.get("package-ecosystem") not in ecosystems:
        return False
    if "directory" in item and "directories" not in item:
        directories = [item["directory"]]
    elif "directories" in item and "directory" not in item \
            and isinstance(item["directories"], list):
        directories = item["directories"]
    else:
        return False
    if not directories or any(
        not isinstance(directory, str) or not directory.startswith("/")
        for directory in directories
    ):
        return False
    schedule = item.get("schedule")
    if not isinstance(schedule, dict):
        return False
    interval = schedule.get("interval")
    if interval in {"daily", "weekly", "monthly", "quarterly", "semiannually", "yearly"}:
        return True
    return interval == "cron" and isinstance(schedule.get("cronjob"), str) \
        and _valid_cronjob(schedule["cronjob"])


def _valid_cronjob(expression: str) -> bool:
    limits = ((0, 59), (0, 23), (1, 31), (1, 12), (0, 7))
    fields = expression.split()
    return len(fields) == len(limits) and all(
        _valid_cron_field(field, minimum, maximum)
        for field, (minimum, maximum) in zip(fields, limits)
    )


def _valid_cron_field(field: str, minimum: int, maximum: int) -> bool:
    for item in field.split(","):
        base, separator, step = item.partition("/")
        if separator and (not step.isdigit() or int(step) == 0):
            return False
        if base == "*":
            continue
        if "-" in base:
            start, end = base.split("-", 1)
            if not start.isdigit() or not end.isdigit() \
                    or int(start) > int(end) \
                    or not minimum <= int(start) <= maximum \
                    or not minimum <= int(end) <= maximum:
                return False
        elif not base.isdigit() or not minimum <= int(base) <= maximum:
            return False
    return True


def _continues_on_error(config: dict[str, Any]) -> bool:
    return "continue-on-error" in config \
        and str(config["continue-on-error"]).strip().lower() != "false"


def _renovate_enabled(data: Any) -> bool:
    if not isinstance(data, dict) or (
        "enabled" in data and not isinstance(data["enabled"], bool)
    ) or data.get("enabled") is False:
        return False
    managers = data.get("enabledManagers")
    if isinstance(managers, list) and any(
        isinstance(manager, str) and manager in _RENOVATE_MANAGERS
        for manager in managers
    ):
        return True
    extends = data.get("extends")
    if isinstance(extends, list) and any(
        preset in {"config:recommended", "config:best-practices"}
        for preset in extends if isinstance(preset, str)
    ):
        return True
    rules = data.get("packageRules")
    if isinstance(rules, list) and any(
        isinstance(rule, dict)
        and rule.get("enabled") is not False
        and any(rule.get(key) for key in ("matchManagers", "matchPackageNames", "matchDatasources"))
        for rule in rules
    ):
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
