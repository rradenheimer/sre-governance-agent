---
description: Fix one failing governance control with the minimal, reviewable change (opens a PR).
allowed-tools: Bash, Read, Grep, Glob, Edit, Write
---

Remediate a specific control. Target control (or "top"): $ARGUMENTS

Delegate to the `remediation-engineer` subagent and enforce:
- If the profile is `suggest_only` (Federal/Defense): output the exact diff and
  STOP — do not edit files.
- If `propose_pr`: apply the minimal fix, re-run the scan to prove the control
  passes and the score improved, then open a PR titled
  `sre-governance: fix <CONTROL-ID>` requesting CODEOWNERS review.

Never weaken a control/threshold to pass. Never self-approve, merge, or
force-push. Never write secrets. All actions are audited to `.sre/audit.jsonl`.
