# Scripts

Local tooling for the SRE Governance Agent. All scripts are dependency-light
(the engine needs only PyYAML) and run on Windows, macOS, and Linux.

## `opa_gate.py` — policy-as-code gate (local)

Evaluates a governance JSON report against `policies/opa/repo_governance.rego`.
It prefers real OPA tooling and **falls back to a pure-Python evaluator** that
mirrors the Rego, so the gate always runs even without `opa`/`conftest`.

```bash
# Generate a report, then gate it
export PYTHONPATH=src
python -m sre_governance.cli scan --repo . --profile commercial --format json
python scripts/opa_gate.py --report sre-reports/sre-governance-report.json

# Force an engine, or treat warnings as failures
python scripts/opa_gate.py --report r.json --engine python
python scripts/opa_gate.py --report r.json --warn-as-error
```

Exit code `1` when any `deny` rule fires (gate fails), else `0`. Engine
precedence: `conftest` → `opa` → Python fallback.

### Convenience wrappers (scan + gate in one step)

```bash
scripts/run-opa.sh [REPO_PATH] [PROFILE]          # macOS/Linux
```
```powershell
scripts/run-opa.ps1 -Repo . -Profile commercial   # Windows
```

If `opa` is installed, the wrappers also run the native Rego unit tests
(`opa test policies/opa -v`).

## `fleet_aggregate.py` — org-wide rollup

Aggregates governance results across many repositories into a JSON summary, a
CSV (one row per repo), and a Markdown dashboard.

```bash
# Mode 1: scan every repo under a root directory
python scripts/fleet_aggregate.py scan --repos-root /path/to/org --out fleet-reports

# Mode 2: aggregate pre-generated JSON reports (e.g., downloaded CI artifacts)
python scripts/fleet_aggregate.py aggregate --reports-dir ./artifacts --out fleet-reports
```

Outputs in `--out`:

| File | Audience |
|---|---|
| `fleet-summary.json` | Dashboards / data warehouse |
| `fleet-summary.csv` | Spreadsheets / BI |
| `fleet-dashboard.md` | Humans / wiki / job summary |

Metrics: repo count, compliant count/percentage, repos below their profile
minimum, mean/median/range of scores, per-profile breakdown, and the **top
failing controls** across the fleet (for targeted remediation campaigns). In
`scan` mode each repo's profile comes from its `.sre/profile`
(fallback `--default-profile`).

Both scripts are covered by `tests/test_scripts.py`, and the Rego by
`policies/opa/tests/` + `opa test`.
