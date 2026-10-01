# Deployment Playbook — governing 2,000+ repositories

## Distribution models

1. **Org `.github` template repo** — place `agents/copilot/.github/*` into your
   organization's `.github` repository so every repo inherits the Copilot
   instructions, chat mode, prompts, and the `SRE Governance` + `Policy
   Validation` workflows automatically.
2. **Reusable workflow** — publish `sre-governance.yml` as a reusable workflow
   and have each repo call it with its profile. Centralizes upgrades.
3. **Vendored agent folder** — teams copy `agents/claude/.claude/` and
   `CLAUDE.md` into repos that use Claude Code.
4. **Pre-commit / local** — developers run `python -m sre_governance.cli scan`
   before pushing.

The engine itself can be published as an internal package (`pip install
sre-governance`) so repos don't vendor `src/`.

## Per-repo onboarding

Each repo adds:

```
.sre/profile            # one line: federal-defense | regulated | commercial
.sre/governance.yaml    # declared posture (attestations, not verified API evidence)
```

Run `/sre-onboard` (Copilot prompt or Claude command) to scaffold these honestly
and produce a baseline.

## Phased enforcement (avoid a wall of red)

1. **Observe (weeks 1–2):** `enforcement: warning` everywhere. Collect fleet
   baseline scores; publish a leaderboard. No builds blocked.
2. **Ratchet (weeks 3–8):** switch critical controls to blocking per profile;
   give teams error-budget-style remediation windows.
3. **Enforce (week 9+):** full profile enforcement. Federal/Defense and Regulated
   run `blocking`; Commercial blocks on criticals.

Because profiles are data, you roll out stricter posture by changing one file,
not code.

## Fleet reporting

Each repo emits `sre-governance-report.json`. Aggregate the fleet with the
bundled script (no extra services required):

```bash
# Aggregate downloaded CI artifacts (one JSON per repo)
python scripts/fleet_aggregate.py aggregate --reports-dir ./artifacts --out fleet-reports

# Or scan a directory that contains many repos
python scripts/fleet_aggregate.py scan --repos-root /path/to/org --out fleet-reports
```

It produces `fleet-summary.json`, `fleet-summary.csv`, and `fleet-dashboard.md`.
The `SRE Governance Fleet Report` workflow (`sre-governance-fleet.yml`) runs this
weekly and publishes the dashboard to the job summary.

- Upload the JSON artifact to a data lake / warehouse (one row per control per
  repo per run) for org-wide dashboards and trend lines.
- SARIF flows to each repo's **Security** tab automatically.
- Track: mean compliance score by business unit, # repos below profile minimum,
  top failing controls, time-to-remediate.

The governance workflow restores the latest completed audit-chain artifact for
the same branch before scanning, serializes runs for that branch, and uploads the
updated chain for the next run. Configure Actions artifact retention to match the
audit policy; export artifacts to an approved durable archive when platform
retention limits do not cover the required period.

## Enforcing the gate (defense in depth)

Enforcement happens at multiple layers that read the same deterministic report:

1. The engine's exit code (`enforcement: blocking` fails CI).
2. The OPA/Rego gate — run locally or in CI with
   `python scripts/opa_gate.py --report <json>` (uses `conftest`/`opa` if
   installed, else a Python fallback), or `conftest test ... --policy policies/opa`.
3. Branch protection requiring the governance check.

`opa test policies/opa` unit-tests the Rego itself.

## Verify remote settings separately

The scanner reads declared `.sre/governance.yaml` values; the bundled CI workflow
does not query GitHub branch protection, reviewer requirements, or secret scanning.
An attested PASS is not proof that a server-side setting is enabled. Verify these
settings in GitHub before declaring them true, and periodically recheck for drift.

## Upgrades & change control

- The control catalog is versioned (`config/control-catalog.yaml: version`) and
  stamped into every report's provenance.
- `Policy Validation` CI runs `validate-config` + `pytest` on any change to
  `config/`, `src/`, `policies/`, or `tests/` — the policies are tested like code.
- Roll catalog changes out behind the phased model above.

## Rollback

All changes are PRs in version control and fully revertible. Disabling the agent
is removing a workflow — the deterministic engine has no side effects beyond
reports and the append-only audit log. Fleet rollouts roll back automatically;
see [Staged fleet rollout](#staged-fleet-rollout).

## Staged GitHub Releases

The agent is distributed as a source archive, not published to PyPI. After
review and merge to `main`, sign an annotated `v<VERSION>` tag on the
current `main` commit with a GitHub-registered signing key and push it:

```bash
git tag -s v1.0.0 -m "SRE Governance Agent v1.0.0"
git push origin v1.0.0
```

Use the current value of `VERSION`, not necessarily `1.0.0`. Dispatch
**Staged GitHub Release** from `main` to build a candidate for that version.
The workflow rejects unsigned tags and tags pointing to another commit. It
validates the catalog, runs tests and a commercial scan, builds a source
archive, generates an SPDX SBOM from that archive, and publishes both as
assets of a prerelease. It refuses to overwrite an existing release.

Inspect and test the candidate assets before manually dispatching **Promote
GitHub Release** from `main`. Promotion requires the
candidate to be a prerelease, requires both archive and SBOM assets, and
checks that the tag is an ancestor of the current `main` before publishing
the already-built artifacts. The repository must have immutable releases enabled;
promotion also checks each downloaded asset against its GitHub SHA-256 digest.
Promotion does not rebuild. If a release must be
withdrawn, mark it as a prerelease in GitHub, stop distributing the affected
version, and ship a reviewed fix under a new version; do not rewrite release
tags.

The GitHub Actions workflows in `.github/workflows/` are this repository's
CI/CD configuration as code. **IaC Scan** runs Checkov against them on PRs and
pushes to `main`, failing on detected misconfigurations. The protected `main`
branch requires all six matrix scan jobs (including `iac-scan (deploy.yml)`)
and the governance scan to pass. The
`iac-scan.yml` matrix context also scans `codeql.yml` and
`scan-observability.yml`, keeping all eight workflows covered without adding
unprotected status-check contexts.
**Policy Validation** also builds the source archive and validates a real
SPDX SBOM in CI before a release can be proposed. This is not a claim
that Terraform or Kubernetes infrastructure exists in this repository.

## Staged fleet rollout

**Staged Governance Rollout** (`.github/workflows/deploy.yml`) deploys a
promoted release to governed repositories. The deployed unit is the
`sre-governance.yml` workflow from the release tag
(`agents/copilot/.github/workflows/sre-governance.yml`), with its engine
checkout pinned to that tag. It also adds `.sre/profile` (the
`default_profile`) to repos that don't have one. It never writes
`.sre/governance.yaml` attestations; teams must make those themselves.

### Rings and health threshold

`config/rollout-rings.yaml` lists ordered rings (`canary`, `early`, `broad`)
of `owner/repo` targets. A repository may appear in only one ring. The `health`
section sets:

- `min_scan_success_rate` — the minimum percentage of ring repositories whose
  latest `SRE Governance` run on the deployed commit completed successfully;
- `soak_minutes` — how long verification observes the ring for scans to
  complete. Scans still pending at the end, repositories that were not
  deployed, and API failures that persist through the window count as failures;
- `poll_seconds` — the GitHub API polling interval.

Change ring membership or thresholds through a reviewed PR, like any other
policy change.

### Procedure

1. Release and promote `v<VERSION>` (see above). The rollout deploys only the
   version in `VERSION` on `main`.
2. Dispatch **Staged Governance Rollout** from `main`. The job waits for a
   required reviewer to approve the `production-rollout` environment.
3. The job runs `validate-config` and the test suite. It then verifies that the
   release is not a prerelease, is immutable, and has a verified-signed tag
   that is an ancestor of `main`.
4. `scripts/deploy.sh --strategy canary --ring canary --version v<VERSION>`
   opens or updates a `sre-governance/rollout-v<VERSION>` PR in each canary
   repository. Default branches are never pushed to directly. Before changing
   a repository, it records that repository's previous pinned version and
   workflow blob in `rollout-state/rollout-state.jsonl`, which is uploaded as
   the `rollout-state` artifact. Repositories already on the target version
   are left unchanged.
5. `scripts/verify_rollout.py --ring canary` reads each repository's
   `SRE Governance` runs for the deployed commit from the GitHub Actions API.
   It fails when the threshold is breached.
6. `scripts/promote.sh --ring early` re-verifies the preceding ring and
   deploys `early` only if that ring is healthy. The job then verifies `early`
   and repeats both steps for `broad`.
7. Rollout PRs are merged by each repository's owners under their own branch
   protection.

### Automated rollback

If any step fails, `scripts/rollback.sh` runs (`if: failure()`) against the
last ring in the rollout state. For each repository that ring touched:

- **Open rollout PR:** the PR is closed and its branch deleted. The default
  branch still runs the recorded previous version.
- **Already-merged PR:** a `sre-governance/rollback-v<VERSION>` PR restores the
  recorded previous workflow blob. If the rollout added the workflow or
  `.sre/profile`, the rollback PR removes them instead.
- **No PR:** a partially written rollout branch is deleted.

Repositories that were already on the target version are never modified.
Rollback continues past per-repository errors, then fails the job and names
each repository that must be restored manually. To roll back a ring by hand,
download the `rollout-state` artifact and run
`GH_TOKEN=... ./scripts/rollback.sh --state rollout-state.jsonl --ring <ring>`.
Add `--dry-run` to preview the changes first.

### Environment and credentials (one-time setup)

1. Create the `production-rollout` environment (**Settings → Environments**).
   Add a **Required reviewers** protection rule with at least one reviewer, and
   enable **Prevent self-review**. Restrict deployment branches to `main`.
2. Add the `FLEET_ROLLOUT_TOKEN` environment secret. Use a GitHub App
   installation token or a fine-grained token scoped to the ring repositories,
   with **Contents**, **Pull requests**, and **Workflows** write permissions and
   **Actions** read permission. The workflow passes it to `gh` only through
   `GH_TOKEN` and never prints it. Even dry runs need this secret for their
   read-only API calls.
3. Runs are read-only dry runs by default. They report each ring's planned
   `previous -> target` versions, make no changes, and skip health
   verification. Set the environment variable `FLEET_ROLLOUT_LIVE=true` to
   allow changes, and remove it when the rollout ends. This is an environment
   setting instead of a `workflow_dispatch` input because Checkov
   (`CKV_GHA_7`) forbids dispatch inputs that affect build output.
4. Add `iac-scan (deploy.yml)` to the required status checks on `main`.
