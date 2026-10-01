# Policy: Service Level Objectives (SLOs)

**Policy ID:** POL-SRE-SLO · **Controls:** `SRE-SLO-001`, `SRE-EB-002`
**Applies to:** all production services · **Enforcement:** per industry profile

## Statement

Every production service MUST declare its Service Level Indicators (SLIs) and
Service Level Objectives (SLOs) as version-controlled code, and MUST have a
documented error-budget policy.

## Requirements

1. SLOs are declared in `.sre/slo.yaml` (or `slo/`), covering at minimum
   **availability** and **latency** for each user-facing journey.
2. Each SLO specifies an SLI expressed as *good events / valid events*, an
   objective (e.g., 99.9%), and a rolling measurement window (e.g., 30 days).
3. An error-budget policy is declared (`sre.error_budget_policy_defined: true`)
   with an explicit consequence when the budget is exhausted (e.g., change
   freeze) and a named owner.
4. Alerting is based on **burn rate**, not static thresholds.

## Rationale

SLOs make reliability an explicit, testable engineering target and are the
prerequisite for error budgets — the mechanism that balances velocity and
reliability. Maps to NIST 800-53 CP-2/SA-4 and SOC 2 Availability.

## Verification

`python -m sre_governance.cli scan` evaluates `SRE-SLO-001` and `SRE-EB-002`
deterministically. Evidence is the generated report plus `.sre/audit.jsonl`.
