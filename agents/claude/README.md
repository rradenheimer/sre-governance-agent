# SRE Governance Agent — Claude edition

Drop-in configuration for **Claude Code**.

## Contents

| File | Purpose |
|---|---|
| `CLAUDE.md` | Project memory / operating rules (always loaded) |
| `.claude/settings.json` | Least-privilege permissions + hook wiring |
| `.claude/agents/sre-governance-auditor.md` | Read-only audit subagent |
| `.claude/agents/remediation-engineer.md` | Minimal-fix-via-PR subagent |
| `.claude/skills/slo-review/SKILL.md` | SLO/error-budget skill (+ template) |
| `.claude/skills/governance-audit/SKILL.md` | Audit + framework-crosswalk skill |
| `.claude/commands/sre-scan.md` | `/sre-scan` slash command |
| `.claude/commands/sre-remediate.md` | `/sre-remediate` slash command |
| `.claude/commands/sre-onboard.md` | `/sre-onboard` slash command |
| `.claude/hooks/secret_guard.py` | **PreToolUse** — blocks secrets, force-push, audit edits |
| `.claude/hooks/audit_logger.py` | **PostToolUse/Stop** — appends hash-chained audit records |

## Install

Copy `CLAUDE.md` and `.claude/` into the target repository. Ensure the engine is
available (vendor `src/sre_governance/` or `pip install` the internal package).
The hooks are plain Python with no third-party deps.

## Use

- Ask Claude to audit the repo → the `sre-governance-auditor` subagent runs the
  engine and reports findings with framework mappings.
- Run `/sre-scan`, `/sre-remediate <CONTROL-ID>`, or `/sre-onboard`.
- To fix an issue, Claude delegates to `remediation-engineer`, which opens a PR.

## Safety wiring (enforced, not just instructed)

- `secret_guard` (PreToolUse) blocks credential writes, `git push --force`,
  `gh pr merge`, and any edit to `.sre/audit.jsonl` (exit code 2 → tool blocked).
- `audit_logger` (PostToolUse/Stop) appends tamper-evident records that the
  engine's `verify-audit` can validate.
- `settings.json` denies reading `.env`/keys and asks before `git push`.
- The active profile's `ai_autonomy` configures agent guidance (for example,
  `suggest_only` for Federal/Defense); it is not runtime enforcement of edits
  or PR creation.
