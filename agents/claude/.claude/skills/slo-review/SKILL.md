---
name: slo-review
description: Review, validate, or author Service Level Objectives (SLOs) and error-budget policy for a service. Use when the user mentions SLOs, SLIs, error budgets, reliability targets, or control SRE-SLO-001 / SRE-EB-002.
---

# SLO Review Skill

Help teams define good SLOs and a usable error-budget policy — the backbone of
SRE and of controls `SRE-SLO-001` and `SRE-EB-002`.

## What good looks like

A `.sre/slo.yaml` that declares, per service:
- `service`, `owner`
- one or more SLOs, each with: `name`, `sli` (a ratio of good/total events),
  `objective` (e.g., 99.9), and `window` (e.g., 30d).

An error-budget policy declared via `.sre/governance.yaml`
(`sre.error_budget_policy_defined: true`) with the agreed consequence when the
budget is exhausted (e.g., feature freeze until burn recovers).

## Review checklist

1. Is every user-facing journey covered by at least one SLI (availability +
   latency at minimum)?
2. Are objectives realistic (not 100%) and measured over a rolling window?
3. Is the SLI a ratio of *good events / valid events* (not an average)?
4. Is there an explicit error-budget policy with an owner and an action?
5. Are alerts tied to **burn rate**, not static thresholds?

## Authoring

When asked to create SLOs, propose a starter `.sre/slo.yaml` with conservative
objectives and ask the team to ratify the targets. Then run:

```bash
PYTHONPATH=src python -m sre_governance.cli scan --repo . --profile <profile>
```

to confirm `SRE-SLO-001` and `SRE-EB-002` now pass. Keep changes minimal and open
a PR for approval.

## Reference

`references/slo-template.yaml` contains a ready-to-edit template.
