# Policy: Responsible AI Automation

**Policy ID:** POL-AI-SAFE · **Control:** `CMP-AUDIT-033` (+ all data_handling settings)
**Applies to:** the SRE Governance Agent itself (Copilot & Claude variants)

## Statement

AI automation in this program MUST be **safe, transparent, bounded, and
auditable**. The AI never decides compliance and never makes unreviewed changes.

## Requirements

1. **Determinism of judgment.** Pass/fail is computed only by the offline policy
   engine. AI interprets results and drafts remediations; it never asserts
   compliance.
2. **Least privilege.** Agents are read-only by default. Changes are proposed as
   pull requests under CODEOWNERS review. No self-approval, no merge, no
   force-push (enforced by hooks and CI permissions).
3. **Profile-bound autonomy.** `ai_autonomy` governs behavior:
   `suggest_only` (Federal/Defense), `propose_pr` (Regulated/Commercial), `never`.
4. **Data handling.** Respect each profile's `data_handling`:
   `allow_external_ai_calls` (false for Federal/Defense), `redact_secrets_in_prompts`,
   and audit retention. Secrets are never read, printed, committed, or transmitted
   (enforced by the `secret_guard` PreToolUse hook).
5. **Transparency.** Every agent action is appended to a hash-chained audit log
   (`.sre/audit.jsonl`) with provenance, verifiable via `cli verify-audit`.
6. **Reversibility.** All changes land through version control and are revertible.
7. **Human accountability.** A human owner approves and is accountable for every
   merged change.

## Rationale

High-assurance environments require that autonomy be constrained and every action
attributable. Maps to NIST 800-53 AU-2/AU-3/AU-12, and aligns with NIST AI RMF
(Govern/Map/Measure/Manage) and the EO 14028 secure-development expectations.

## Verification

`CMP-AUDIT-033` requires `governance.audit_logging: true`; hooks and CI
permissions enforce the behavioral constraints; `cli verify-audit` proves the
log is intact.
