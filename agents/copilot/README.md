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
| `.github/workflows/sre-governance.yml` | CI gate: scan → SARIF → PR comment → enforce |
| `.github/workflows/dependency-review.yml` | Fail PRs with critical dependency vulnerabilities |
| `.github/workflows/policy-validation.yml` | Validate catalog/profiles + run engine tests |
| `AGENTS.md` | Rules for the Copilot coding agent |

## Install

Copy the `.github/` contents into the target repository (or into your org's
`.github` template repo to apply fleet-wide). The governance workflow checks out
the engine and its catalog/profile configuration from the pinned `v1.0.0` release;
update that checkout ref when adopting a newer release.

## Use

- In VS Code Copilot Chat, select the **SRE Governance** chat mode, or run a
  prompt: `/sre-scan`, `/sre-remediate`, `/sre-onboard`.
- On every PR, the `SRE Governance` workflow posts the report and enforces the
  gate per the repo's `.sre/profile`.

## Guarantees

The agent is read-only by default, proposes changes only as reviewed PRs, never
self-approves/merges, and records all actions to `.sre/audit.jsonl`. Pass/fail is
always computed by the deterministic engine, never by the model.
