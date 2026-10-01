---
mode: agent
description: Propose the minimal change to fix a specific failing control, as a reviewable PR.
tools: ['codebase', 'editFiles', 'runCommands']
---

# /sre-remediate

Input: a control ID (e.g., `GOV-BP-010`) or "top" to pick the highest-severity
mandatory failure.

Guardrails:
- Only proceed if the active profile's `ai_autonomy` is `propose_pr`. If it is
  `suggest_only` (Federal/Defense), output the exact change as a diff/snippet and
  STOP — do not edit files.
- Make the **smallest** change that flips the control to PASS. Do not touch
  unrelated files or bundle extra work.
- Put SLO/governance declarations under `.sre/`. Follow the catalog `remediation`.

Steps:
1. Run `python -m sre_governance.cli scan --repo . --profile ${input:profile}` to
   confirm the control currently fails and capture the reason.
2. Apply the minimal fix (new file or metadata field).
3. Re-run the scan to prove the control now passes and the score improved.
4. Summarize: what changed, why, the control(s) affected, and framework mappings.
5. Open a pull request titled `sre-governance: fix <CONTROL-ID>`; request review
   from CODEOWNERS. Never self-approve or merge.

All actions are recorded in `.sre/audit.jsonl`.
