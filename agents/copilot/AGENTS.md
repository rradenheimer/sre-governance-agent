# AGENTS.md — SRE Governance Agent (GitHub Copilot coding agent)

This repository is governed by the **SRE Governance Agent**. When the Copilot
coding agent works here, it must follow these rules (they mirror
`.github/copilot-instructions.md`).

## Setup

```bash
pip install pyyaml pytest
export PYTHONPATH=src
```

## Validate before you finish

Always run these and ensure they pass:

```bash
python -m sre_governance.cli validate-config      # catalog + profiles sane
python -m pytest -q                                # engine + script tests green
python -m sre_governance.cli scan --repo . --profile commercial --format json   # self-scan
python scripts/opa_gate.py --report sre-reports/sre-governance-report.json       # policy gate
```

## Hard rules

- The deterministic engine decides pass/fail. Never hard-code or fake a result.
- Changes land via pull request with CODEOWNERS review. Never self-approve/merge.
- Do not weaken a control, threshold, or profile to make a scan pass. If a
  control is genuinely not applicable, mark it `not_applicable` in the profile
  with a justification in the PR description.
- Keep secrets out of code, logs, prompts, and `.sre/audit.jsonl`.
- Respect the active profile's `ai_autonomy`:
  `suggest_only` → no file edits; `propose_pr` → PRs only.

## Where things live

| Path | Purpose |
|---|---|
| `config/control-catalog.yaml` | Source-of-truth controls + framework mappings |
| `config/industry-profiles/` | Federal/Defense, Regulated, Commercial overlays |
| `src/sre_governance/` | Deterministic engine + CLI (no AI, no network) |
| `policies/` | Human-readable policies + OPA rego |
| `tests/` | Engine + policy tests |
