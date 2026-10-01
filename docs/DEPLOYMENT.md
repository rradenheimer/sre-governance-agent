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

Each repo emits `sre-governance-report.json`. Aggregate them:

- Upload the JSON artifact to a data lake / warehouse (one row per control per
  repo per run) for org-wide dashboards and trend lines.
- SARIF flows to each repo's **Security** tab automatically.
- Track: mean compliance score by business unit, # repos below profile minimum,
  top failing controls, time-to-remediate.

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
reports and the append-only audit log.
