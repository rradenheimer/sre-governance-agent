# SRE Governance Agent — GitHub Copilot edition

Drop-in agent configuration for GitHub Copilot (VS Code + Copilot coding agent).

## Contents

| File | Purpose |
|---|---|
| `.github/copilot-instructions.md` | Repo-wide custom instructions (always applied) |
| `.github/chatmodes/sre-governance.chatmode.md` | Read-only **audit** chat mode |
| `.github/prompts/sre-scan.prompt.md` | `/sre-scan` — full compliance scan |
| `.github/prompts/sre-remediate.prompt.md` | `/sre-remediate` — minimal fix via PR |
| `.github/prompts/sre-onboard.prompt.md` | `/sre-onboard` — baseline a new repo |
| `.github/workflows/sre-governance.yml` | Read-only CI scan and policy gate |
| `.github/workflows/sre-governance-report.yml` | Trusted SARIF upload and PR report publisher |
| `.github/workflows/policy-validation.yml` | Validate catalog/profiles + run engine tests |
| `AGENTS.md` | Rules for the Copilot coding agent |

## Install

Copy the `.github/` contents into the target repository (or into your org's
`.github` template repo to apply fleet-wide). Ensure the engine is available —
either vendor `src/sre_governance/` or `pip install` the internal package.

## Use

- In VS Code Copilot Chat, select the **SRE Governance** chat mode, or run a
  prompt: `/sre-scan`, `/sre-remediate`, `/sre-onboard`.
- On every PR, the `SRE Governance` workflow scans and enforces the gate per the
  repo's `.sre/profile`; its trusted report workflow publishes the results.

## Guarantees

Agent instructions direct it to propose changes only as reviewed PRs, never
self-approve/merge, and record actions to `.sre/audit.jsonl`. These are behavioral
guardrails, not runtime enforcement of file edits or PR creation. Pass/fail is
always computed by the deterministic engine, never by the model.
