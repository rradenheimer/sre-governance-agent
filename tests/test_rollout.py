"""Tests for the staged governance rollout (SRE-CHG-005 evidence)."""
import base64
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from sre_governance.scanner import has_safe_change_workflow, scan_repo

ROOT = Path(__file__).resolve().parents[1]
DEPLOY_WORKFLOW = ROOT / ".github" / "workflows" / "deploy.yml"
TEMPLATE = ROOT / "agents" / "copilot" / ".github" / "workflows" / "sre-governance.yml"
SHA_A = "a" * 40
SHA_B = "b" * 40

_spec = importlib.util.spec_from_file_location("verify_rollout", ROOT / "scripts" / "verify_rollout.py")
verify_rollout = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(verify_rollout)

requires_tools = pytest.mark.skipif(
    not (shutil.which("bash") and shutil.which("jq")), reason="bash and jq are required",
)


# --- SRE-CHG-005 evidence ---------------------------------------------------

def _scan_workflow(tmp_path, text):
    workflow = tmp_path / ".github" / "workflows" / "deploy.yml"
    workflow.parent.mkdir(parents=True, exist_ok=True)
    workflow.write_text(text, encoding="utf-8")
    return has_safe_change_workflow(scan_repo(tmp_path))


def test_real_deploy_workflow_satisfies_safe_change(tmp_path):
    assert _scan_workflow(tmp_path, DEPLOY_WORKFLOW.read_text(encoding="utf-8"))


@pytest.mark.parametrize("element, old, new", [
    ("environment", "    environment: production-rollout\n", ""),
    ("staging flag", "--strategy canary --ring canary", "--ring canary"),
    ("tests", "          pytest -q\n", ""),
    ("promote", "./scripts/promote.sh", "echo skipped"),
    ("rollback", "run: ./scripts/rollback.sh", "run: echo skipped"),
])
def test_removing_a_safe_change_element_fails(tmp_path, element, old, new):
    text = DEPLOY_WORKFLOW.read_text(encoding="utf-8")
    assert old in text, element
    assert not _scan_workflow(tmp_path, text.replace(old, new)), element


def test_deploy_workflow_is_gated_least_privilege_and_rolls_back():
    workflow = yaml.load(DEPLOY_WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    assert set(workflow["on"]) == {"workflow_dispatch"}
    assert workflow["permissions"] == {"contents": "read"}
    job = workflow["jobs"]["staged-rollout"]
    assert job["environment"] == "production-rollout"
    assert job["permissions"] == {"contents": "read"}
    assert job["env"]["ROLLOUT_DRY_RUN"] == "${{ vars.FLEET_ROLLOUT_LIVE != 'true' }}"
    runs = [step.get("run", "") for step in job["steps"]]
    joined = "\n".join(runs)
    assert "verification.verified" in joined and ".immutable" in joined
    assert "grep -qx false" in joined  # non-prerelease
    assert "git merge-base --is-ancestor" in joined
    order = [
        './scripts/deploy.sh --strategy canary --ring canary --version "$VERSION"',
        "python scripts/verify_rollout.py --ring canary",
        './scripts/promote.sh --ring early --version "$VERSION"',
        "python scripts/verify_rollout.py --ring early",
        './scripts/promote.sh --ring broad --version "$VERSION"',
        "python scripts/verify_rollout.py --ring broad",
    ]
    positions = [joined.index(command) for command in order]
    assert positions == sorted(positions)
    rollback = next(step for step in job["steps"] if "rollback.sh" in step.get("run", ""))
    assert rollback["if"] == "failure()"
    for step in job["steps"]:
        token = step.get("env", {}).get("GH_TOKEN", "")
        if "FLEET_ROLLOUT_TOKEN" in token:
            assert token == "${{ secrets.FLEET_ROLLOUT_TOKEN }}"
        assert "secrets." not in step.get("run", "")
        assert "set -x" not in step.get("run", "")


# --- gh stub ----------------------------------------------------------------

GH_STUB = r'''#!/usr/bin/env python3
import json, os, re, sys
args = " ".join(sys.argv[1:])
with open(os.environ["GH_STUB_LOG"], "a", encoding="utf-8") as log:
    log.write(args + "\n")
for pattern, out, code, err in json.load(open(os.environ["GH_STUB_RESPONSES"])):
    if re.search(pattern, args):
        sys.stdout.write(out)
        sys.stderr.write(err)
        sys.exit(code)
sys.exit(0)
'''
NOT_FOUND = ("", 1, "gh: Not Found (HTTP 404)\n")


def _stub_env(tmp_path, responses):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    stub = bin_dir / "gh"
    stub.write_text(GH_STUB, encoding="utf-8")
    stub.chmod(0o755)
    (tmp_path / "responses.json").write_text(
        json.dumps([[pattern, *response] for pattern, response in responses]), encoding="utf-8")
    log = tmp_path / "gh.log"
    log.write_text("", encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if not k.startswith(("ROLLOUT_", "GITHUB_"))}
    env.update(PATH=f"{bin_dir}{os.pathsep}{env['PATH']}", GH_STUB_LOG=str(log),
               GH_STUB_RESPONSES=str(tmp_path / "responses.json"), PYTHON=sys.executable,
               GH_TOKEN="test-token-never-printed")
    return env, log


def _write_config(tmp_path, canary, early=("acme/early",)):
    config = tmp_path / "rings.yaml"
    config.write_text(yaml.safe_dump({
        "default_profile": "commercial",
        "health": {"min_scan_success_rate": 95, "soak_minutes": 1, "poll_seconds": 1},
        "rings": [{"name": "canary", "repos": list(canary)},
                  {"name": "early", "repos": list(early)}],
    }), encoding="utf-8")
    return config


def _pinned(version):
    return base64.b64encode(
        TEMPLATE.read_text(encoding="utf-8").replace("ref: v1.0.0", f"ref: {version}").encode()
    ).decode()


def _state(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


@requires_tools
def test_deploy_dry_run_records_previous_versions_without_writes(tmp_path):
    config = _write_config(tmp_path, ["acme/old", "acme/new", "acme/current"])
    state = tmp_path / "state" / "rollout.jsonl"
    env, log = _stub_env(tmp_path, [
        (r"^api repos/acme/\w+ --jq \.default_branch$", ("main\n", 0, "")),
        (r"^api repos/acme/\w+/git/ref/heads/main ", (SHA_A + "\n", 0, "")),
        (r"^api repos/acme/old/contents/\.github/workflows/sre-governance\.yml\?ref=main",
         (f"oldblob\t{_pinned('v0.9.0')}\n", 0, "")),
        (r"^api repos/acme/current/contents/\.github/workflows/sre-governance\.yml\?ref=main",
         (f"curblob\t{_pinned('v1.1.0')}\n", 0, "")),
        (r"^api repos/acme/new/contents/", NOT_FOUND),
        (r"^api repos/acme/\w+/contents/\.sre/profile", ("profblob\tY29tbWVyY2lhbAo=\n", 0, "")),
    ])
    result = subprocess.run(
        [str(ROOT / "scripts" / "deploy.sh"), "--strategy", "canary", "--ring", "canary",
         "--version", "v1.1.0", "--dry-run", "--config", str(config), "--state", str(state),
         "--template", str(TEMPLATE)],
        env=env, capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "DRY RUN: acme/old (canary): v0.9.0 -> v1.1.0" in result.stdout
    assert "DRY RUN: acme/new (canary): none -> v1.1.0" in result.stdout
    assert "acme/current: already on v1.1.0" in result.stdout
    assert "test-token-never-printed" not in result.stdout + result.stderr
    calls = log.read_text(encoding="utf-8").splitlines()
    assert calls and not any(" -X " in f" {call}" or call.startswith("pr ") for call in calls)
    touched = {entry["repo"]: entry for entry in _state(state) if entry["phase"] == "touched"}
    assert set(touched) == {"acme/old", "acme/new"}
    assert touched["acme/old"]["previous_version"] == "v0.9.0"
    assert touched["acme/old"]["previous_blob_sha"] == "oldblob"
    assert touched["acme/new"]["previous_version"] == "none"
    assert touched["acme/new"]["previous_blob_sha"] == "none"
    assert all(entry["dry_run"] is True for entry in touched.values())
    assert all(entry["branch"] == "sre-governance/rollout-v1.1.0" for entry in touched.values())


@requires_tools
def test_deploy_live_opens_pull_request_and_records_head(tmp_path):
    config = _write_config(tmp_path, ["acme/new"])
    state = tmp_path / "state.jsonl"
    env, log = _stub_env(tmp_path, [
        (r"--jq \.default_branch$", ("main\n", 0, "")),
        (r"^api repos/acme/new/git/ref/heads/main ", (SHA_A + "\n", 0, "")),
        (r"^api repos/acme/new/git/ref/heads/sre-governance/rollout-v1\.1\.0 --jq",
         (SHA_B + "\n", 0, "")),
        (r"^api repos/acme/new/git/ref/heads/sre-governance/rollout-v1\.1\.0$", NOT_FOUND),
        (r"^api repos/acme/new/contents/", NOT_FOUND),
        (r"^pr list ", ("", 0, "")),
        (r"^pr create ", ("https://github.com/acme/new/pull/7\n", 0, "")),
    ])
    result = subprocess.run(
        [str(ROOT / "scripts" / "deploy.sh"), "--strategy", "canary", "--ring", "canary",
         "--version", "v1.1.0", "--config", str(config), "--state", str(state),
         "--template", str(TEMPLATE)],
        env=env, capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    calls = log.read_text(encoding="utf-8")
    assert "api -X POST repos/acme/new/git/refs -f ref=refs/heads/sre-governance/rollout-v1.1.0" in calls
    put = next(line for line in calls.splitlines()
               if line.startswith("api -X PUT repos/acme/new/contents/.github/workflows/"))
    content = base64.b64decode(put.split("content=")[1].split(" ")[0]).decode()
    assert "ref: v1.1.0" in content and "ref: v1.0.0" not in content
    assert "api -X PUT repos/acme/new/contents/.sre/profile" in calls
    assert "pr create -R acme/new --base main --head sre-governance/rollout-v1.1.0" in calls
    deployed = [entry for entry in _state(state) if entry["phase"] == "deployed"]
    assert deployed[0]["head_sha"] == SHA_B
    assert deployed[0]["pr_url"] == "https://github.com/acme/new/pull/7"


def test_deploy_rejects_unsupported_strategy_and_version(tmp_path):
    script = str(ROOT / "scripts" / "deploy.sh")
    for args in (["--strategy", "big-bang", "--ring", "canary", "--version", "v1.0.0"],
                 ["--strategy", "canary", "--ring", "canary", "--version", "main"]):
        result = subprocess.run([script, *args, "--dry-run"], capture_output=True, text=True,
                                check=False)
        assert result.returncode == 2


def _rollback_state(path):
    base = {"ring": "early", "version": "v1.1.0", "default_branch": "main",
            "branch": "sre-governance/rollout-v1.1.0", "created_profile": False,
            "previous_blob_sha": "none", "dry_run": False, "phase": "touched"}
    entries = [
        {**base, "repo": "acme/canary", "ring": "canary", "previous_version": "v1.0.0"},
        {**base, "repo": "acme/open", "previous_version": "v1.0.0", "previous_blob_sha": "b1"},
        {**base, "repo": "acme/partial", "previous_version": "none"},
        {**base, "repo": "acme/merged", "previous_version": "v1.0.0",
         "previous_blob_sha": "oldblob", "created_profile": True},
        {**base, "repo": "acme/same", "previous_version": "v1.1.0", "phase": "unchanged"},
        {**base, "repo": "acme/open", "phase": "deployed", "previous_version": "v1.0.0"},
    ]
    path.write_text("".join(json.dumps(entry) + "\n" for entry in entries), encoding="utf-8")


@requires_tools
def test_rollback_restores_previous_version_for_every_repo_in_failed_ring(tmp_path):
    state = tmp_path / "state.jsonl"
    _rollback_state(state)
    env, log = _stub_env(tmp_path, [
        (r"^pr list -R acme/open --head sre-governance/rollout-v1\.1\.0 --state all",
         ("OPEN\thttps://github.com/acme/open/pull/1\n", 0, "")),
        (r"^pr list -R acme/merged --head sre-governance/rollout-v1\.1\.0 --state all",
         ("MERGED\thttps://github.com/acme/merged/pull/2\n", 0, "")),
        (r"^pr list ", ("", 0, "")),
        (r"^api repos/acme/partial/git/ref/heads/sre-governance/rollout-v1\.1\.0$", ("{}", 0, "")),
        (r"^api repos/acme/merged/git/ref/heads/main --jq", (SHA_A + "\n", 0, "")),
        (r"^api repos/acme/merged/git/ref/heads/sre-governance/rollback-v1\.1\.0$", NOT_FOUND),
        (r"^api repos/acme/merged/contents/\.github/workflows/sre-governance\.yml\?ref=",
         ("newblob\n", 0, "")),
        (r"^api repos/acme/merged/contents/\.sre/profile\?ref=", ("profblob\n", 0, "")),
        (r"^api repos/acme/merged/git/blobs/oldblob ", ("T0xECg==\n", 0, "")),
        (r"^pr create ", ("https://github.com/acme/merged/pull/3\n", 0, "")),
    ])
    result = subprocess.run([str(ROOT / "scripts" / "rollback.sh"), "--state", str(state)],
                            env=env, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    calls = log.read_text(encoding="utf-8")
    assert ("pr close https://github.com/acme/open/pull/1 -R acme/open --delete-branch"
            in calls)
    assert "api -X DELETE repos/acme/partial/git/refs/heads/sre-governance/rollout-v1.1.0" in calls
    assert ("api -X PUT repos/acme/merged/contents/.github/workflows/sre-governance.yml "
            "-f branch=sre-governance/rollback-v1.1.0") in calls
    assert "-f content=T0xECg== -f sha=newblob" in calls
    assert "api -X DELETE repos/acme/merged/contents/.sre/profile" in calls
    assert "pr create -R acme/merged --base main --head sre-governance/rollback-v1.1.0" in calls
    assert "acme/same" not in calls and "acme/canary" not in calls
    assert "Rollback of ring 'early' complete." in result.stdout


@requires_tools
def test_rollback_dry_run_and_dry_run_entries_make_no_calls(tmp_path):
    state = tmp_path / "state.jsonl"
    _rollback_state(state)
    env, log = _stub_env(tmp_path, [])
    result = subprocess.run([str(ROOT / "scripts" / "rollback.sh"), "--state", str(state),
                             "--dry-run"], env=env, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    assert "would roll back acme/merged (early) from v1.1.0 to v1.0.0" in result.stdout
    assert log.read_text(encoding="utf-8") == ""

    state.write_text(json.dumps({
        "ring": "canary", "repo": "acme/x", "version": "v1.1.0", "previous_version": "v1.0.0",
        "previous_blob_sha": "b", "created_profile": False, "default_branch": "main",
        "branch": "sre-governance/rollout-v1.1.0", "dry_run": True, "phase": "touched",
    }) + "\n", encoding="utf-8")
    result = subprocess.run([str(ROOT / "scripts" / "rollback.sh"), "--state", str(state)],
                            env=env, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    assert log.read_text(encoding="utf-8") == ""

    missing = subprocess.run([str(ROOT / "scripts" / "rollback.sh"), "--state",
                              str(tmp_path / "absent.jsonl")],
                             env=env, capture_output=True, text=True, check=False)
    assert missing.returncode == 0
    assert "nothing to roll back" in missing.stdout


@requires_tools
def test_rollback_reports_failure_but_continues_other_repos(tmp_path):
    state = tmp_path / "state.jsonl"
    _rollback_state(state)
    env, log = _stub_env(tmp_path, [
        (r"^pr list -R acme/open ", ("OPEN\thttps://github.com/acme/open/pull/1\n", 0, "")),
        (r"^pr close ", ("", 1, "HTTP 500\n")),
        (r"^pr list ", ("", 0, "")),
        (r"^api repos/acme/\w+/git/ref/heads/sre-governance/rollout", NOT_FOUND),
    ])
    result = subprocess.run([str(ROOT / "scripts" / "rollback.sh"), "--state", str(state)],
                            env=env, capture_output=True, text=True, check=False)
    assert result.returncode == 1
    assert "rollback failed for acme/open" in result.stderr
    assert "pr list -R acme/partial" in log.read_text(encoding="utf-8")


@requires_tools
def test_promote_requires_previous_ring_health(tmp_path):
    config = _write_config(tmp_path, ["acme/canary"])
    env, log = _stub_env(tmp_path, [])
    result = subprocess.run(
        [str(ROOT / "scripts" / "promote.sh"), "--ring", "early", "--version", "v1.1.0",
         "--config", str(config), "--state", str(tmp_path / "empty.jsonl")],
        env={**env, "GH_TOKEN": ""}, capture_output=True, text=True, check=False, timeout=120,
    )
    assert result.returncode == 1
    assert "ring canary breached the health threshold" in result.stderr
    assert log.read_text(encoding="utf-8") == ""  # early ring was never deployed

    first = subprocess.run(
        [str(ROOT / "scripts" / "promote.sh"), "--ring", "canary", "--version", "v1.1.0",
         "--config", str(config), "--dry-run"],
        env=env, capture_output=True, text=True, check=False,
    )
    assert first.returncode == 2
    assert "first ring" in first.stderr


# --- verify_rollout.py ------------------------------------------------------

def run(status="completed", conclusion="success", created="2026-10-01T00:00:00Z",
        path=".github/workflows/sre-governance.yml", run_id=1):
    return {"id": run_id, "path": path, "status": status, "conclusion": conclusion,
            "created_at": created}


def test_real_rollout_config_is_valid_and_ordered():
    config = verify_rollout.load_config(ROOT / "config" / "rollout-rings.yaml")
    assert verify_rollout.ring_names(config) == ["canary", "early", "broad"]
    assert verify_rollout.previous_ring(config, "broad") == "early"
    assert 0 < config["health"]["min_scan_success_rate"] <= 100
    assert config["health"]["soak_minutes"] > 0


@pytest.mark.parametrize("mutate, message", [
    (lambda c: c["health"].update(min_scan_success_rate=0), "min_scan_success_rate"),
    (lambda c: c["health"].update(soak_minutes=True), "soak_minutes"),
    (lambda c: c["rings"][1]["repos"].append("acme/canary"), "more than one ring"),
    (lambda c: c["rings"][0].update(repos=["not a repo"]), "invalid repository"),
    (lambda c: c["rings"][1].update(name="canary"), "duplicate ring"),
    (lambda c: c.update(default_profile="lenient"), "default_profile"),
])
def test_invalid_rollout_config_is_rejected(tmp_path, mutate, message):
    config = yaml.safe_load(_write_config(tmp_path, ["acme/canary"]).read_text(encoding="utf-8"))
    mutate(config)
    path = tmp_path / "bad.yaml"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")
    with pytest.raises(ValueError, match=message):
        verify_rollout.load_config(path)


def test_scan_status_uses_latest_sre_governance_run():
    assert verify_rollout.scan_status([]) == "pending"
    assert verify_rollout.scan_status([run(path=".github/workflows/other.yml")]) == "pending"
    assert verify_rollout.scan_status([run(status="in_progress", conclusion=None)]) == "pending"
    assert verify_rollout.scan_status([run(conclusion="failure")]) == "failure"
    assert verify_rollout.scan_status([
        run(conclusion="failure", created="2026-10-01T00:00:00Z", run_id=1),
        run(conclusion="success", created="2026-10-01T00:05:00Z", run_id=2),
    ]) == "success"


@pytest.mark.parametrize("statuses, threshold, healthy", [
    ({"a/a": "success", "b/b": "success"}, 95, True),
    ({"a/a": "success", "b/b": "failure"}, 95, False),
    ({"a/a": "success", "b/b": "failure"}, 50, True),
    ({"a/a": "success", "b/b": "not_deployed"}, 95, False),
    ({}, 95, False),
])
def test_threshold_evaluation(statuses, threshold, healthy):
    metrics, ok = verify_rollout.evaluate(statuses, threshold)
    assert ok is healthy
    assert metrics["total_repos"] == len(statuses)


class FakeClock:
    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


def test_observe_waits_for_pending_scans_then_passes():
    clock = FakeClock()
    responses = {"a/a": [[run(status="queued", conclusion=None)], [run()]], "b/b": [[run()]]}
    metrics, healthy = verify_rollout.observe(
        ["a/a", "b/b"], {"a/a": SHA_A, "b/b": SHA_B}, 95,
        lambda repo, sha: responses[repo].pop(0), soak_seconds=600, poll_seconds=60,
        sleep=clock.sleep, clock=clock,
    )
    assert healthy and clock.sleeps == [60]
    assert metrics["statuses"] == {"a/a": "success", "b/b": "success"}


def test_observe_fails_fast_when_threshold_unreachable():
    clock = FakeClock()
    _, healthy = verify_rollout.observe(
        ["a/a", "b/b"], {"a/a": SHA_A, "b/b": SHA_B}, 95,
        lambda repo, sha: [run(conclusion="failure")] if repo == "a/a" else [],
        soak_seconds=600, poll_seconds=60, sleep=clock.sleep, clock=clock,
    )
    assert not healthy and clock.sleeps == []


def test_observe_times_out_pending_and_tolerates_transient_errors():
    clock = FakeClock()

    def fetch(repo, sha):
        if clock.now == 0:
            raise OSError("transient")
        return [run(status="in_progress", conclusion=None)]

    metrics, healthy = verify_rollout.observe(
        ["a/a"], {"a/a": SHA_A}, 95, fetch, soak_seconds=120, poll_seconds=60,
        sleep=clock.sleep, clock=clock,
    )
    assert not healthy
    assert metrics["statuses"] == {"a/a": "failure_timeout"}
    assert clock.now == 120


def test_observe_counts_missing_deployments_as_failures():
    metrics, healthy = verify_rollout.observe(
        ["a/a", "b/b"], {"a/a": SHA_A}, 50, lambda repo, sha: [run()],
        soak_seconds=1, poll_seconds=1, sleep=lambda s: None,
    )
    assert healthy  # 1/2 meets 50%
    assert metrics["statuses"]["b/b"] == "not_deployed"


class _Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@pytest.mark.parametrize("conclusion, expected_exit", [("success", 0), ("failure", 1)])
def test_main_queries_github_api_and_enforces_threshold(tmp_path, monkeypatch, capsys,
                                                       conclusion, expected_exit):
    config = _write_config(tmp_path, ["acme/canary"])
    state = tmp_path / "state.jsonl"
    state.write_text(json.dumps({"ring": "canary", "repo": "acme/canary", "phase": "deployed",
                                 "head_sha": SHA_A}) + "\n", encoding="utf-8")
    requests = []

    def fake_urlopen(request, timeout):
        requests.append(request)
        return _Response(json.dumps({"workflow_runs": [run(conclusion=conclusion)]}).encode())

    monkeypatch.setattr(verify_rollout, "urlopen", fake_urlopen)
    monkeypatch.setenv("GH_TOKEN", "secret-token")
    monkeypatch.delenv("ROLLOUT_DRY_RUN", raising=False)
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    code = verify_rollout.main(["--ring", "canary", "--config", str(config), "--state", str(state)])
    assert code == expected_exit
    assert requests[0].full_url == (
        f"https://api.github.com/repos/acme/canary/actions/runs?head_sha={SHA_A}&per_page=100")
    assert requests[0].get_header("Authorization") == "Bearer " + "secret-token"
    output = capsys.readouterr()
    assert "secret-token" not in output.out + output.err
    assert json.loads(output.out)["healthy"] is (expected_exit == 0)


def test_main_dry_run_skips_api(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(verify_rollout, "urlopen", lambda *a, **k: pytest.fail("API called"))
    monkeypatch.setenv("ROLLOUT_DRY_RUN", "true")
    assert verify_rollout.main(["--ring", "canary"]) == 0
    assert "DRY RUN" in capsys.readouterr().out
