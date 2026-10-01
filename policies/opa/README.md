# OPA / Rego policies

These policies let platform teams enforce the **same** governance decision the
engine makes, inside OPA/Conftest/Gatekeeper pipelines.

## Input

`repo_governance.rego` evaluates the JSON report produced by:

```bash
python -m sre_governance.cli scan --repo . --profile <profile> --format json
```

## Run with conftest

```bash
conftest test sre-reports/sre-governance-report.json --policy policies/opa --namespace sre.governance
```

- `deny` rules block the pipeline (gate failure, mandatory CRITICAL failure,
  audit-control failure).
- `warn` rules surface mandatory HIGH failures without blocking.

## Why both engine gate and OPA?

Defense in depth and portability: the engine gate runs anywhere Python runs; the
Rego gate plugs into existing OPA-based admission/CD controls without changing
them. Both read the same deterministic report, so decisions are consistent.
