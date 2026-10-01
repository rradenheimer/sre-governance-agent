# Safety & Transparency

This program lets AI operate across thousands of repositories in highly regulated
environments. Safety is achieved by **constraining what the AI is allowed to
decide and do**, and by making **everything it does observable and reversible**.

## 1. The AI never decides compliance

Pass/fail is computed only by the deterministic engine. The agent instructions
(both editions) forbid asserting a control's status without engine output. This
removes hallucinated compliance — the #1 risk of "AI auditing."

## 2. Least privilege, change only via review

- Agents are **read-only by default**.
- Changes are **pull requests** reviewed by CODEOWNERS. No self-approval, no
  merge, no force-push.
- Enforced technically:
  - Claude: `.claude/settings.json` `permissions.deny` + `secret_guard` PreToolUse hook.
  - Copilot/CI: workflow `permissions:` are least-privilege. Administrators must
    configure branch protection separately; the scanner cannot enforce it.

## 3. Profile-bound autonomy

`ai_autonomy` in each profile:

| Value | Behavior | Default profile |
|---|---|---|
| `suggest_only` | Describe fixes; **no file edits** | federal-defense |
| `propose_pr` | Open PRs; human approves | regulated, commercial |
| `never` | Reporting only | (opt-in) |

## 4. Data handling

Per-profile `data_handling`:

- `allow_external_ai_calls: false` for federal-defense — keep inference in an
  approved boundary (e.g., FedRAMP-authorized or on-prem model).
- `redact_secrets_in_prompts: true` everywhere.
- `retain_audit_days` sets evidence retention (≈7 years for Fed/Regulated).

Secrets are never read, printed, committed, or transmitted. The `secret_guard`
hook blocks obvious credential writes and forbidden commands before they run.

## 5. Tamper-evident audit trail

Every scan, report, and action is appended to `.sre/audit.jsonl`. Each record
embeds the SHA-256 of the previous record (hash chain). Any edit breaks the
chain, which `python -m sre_governance.cli verify-audit` detects. The audit log
is append-only — the hook and permission rules block edits to it. This satisfies
control `CMP-AUDIT-033` and NIST 800-53 AU-2/AU-3/AU-12.

## 6. Reproducibility & provenance

Reports embed a provenance block (generator, timestamp, profile, catalog version,
runtime). Given the same repository contents and declared metadata, reviewers
can reproduce the result; declared remote settings are not independently verified.

## 7. Defense in depth

The same decision is enforced at multiple layers: the engine gate (exit code),
the CI workflow and the OPA/Rego policy (`policies/opa/`). Branch protection
must be configured on the hosting platform independently.

## Alignment

These controls align with **NIST AI RMF** (Govern/Map/Measure/Manage), **NIST SSDF
(SP 800-218)**, **EO 14028**, and the auditability expectations of **SOC 2**,
**PCI-DSS**, **HIPAA**, and **FedRAMP**.
