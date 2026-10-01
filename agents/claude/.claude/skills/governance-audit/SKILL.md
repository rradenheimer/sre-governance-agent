---
name: governance-audit
description: Run and interpret a full repository governance audit against the control catalog and an industry profile. Use when the user asks for a compliance scan, audit evidence, control mapping, or gate status for Federal/Defense, Regulated, or Commercial.
---

# Governance Audit Skill

Produce transparent, framework-mapped governance assessments using the
deterministic engine. The engine computes pass/fail; you explain and prioritize.

## Steps

1. Resolve the profile (`.sre/profile`, else ask; default `commercial`).
2. Validate config, then scan:
   ```bash
   PYTHONPATH=src python -m sre_governance.cli validate-config
   PYTHONPATH=src python -m sre_governance.cli scan --repo . --profile <profile> --format all
   PYTHONPATH=src python -m sre_governance.cli verify-audit --audit .sre/audit.jsonl
   ```
3. Read `sre-reports/sre-governance-report.json` and present:
   - Gate decision, score, and CI impact.
   - Mandatory failures first (ID, severity, reason, remediation, frameworks).
   - A prioritized remediation backlog (critical → high → medium → low).

## Interpreting profiles

| Profile | Enforcement | AI autonomy | Min score | Reviewers |
|---|---|---|---|---|
| federal-defense | blocking | suggest_only | 95 | 2 |
| regulated | blocking | propose_pr | 90 | 2 |
| commercial | warning | propose_pr | 75 | 1 |

## Framework mappings

Each control carries mappings (NIST 800-53, NIST SSDF/EO 14028, SLSA, SOC2,
PCI-DSS, HIPAA, DORA). Use `references/framework-crosswalk.md` to answer "which
controls satisfy X?" questions for auditors.

## Evidence

The Markdown report + `.sre/audit.jsonl` (hash-chain verified) are your audit
evidence. Never fabricate results; always cite the engine output.
