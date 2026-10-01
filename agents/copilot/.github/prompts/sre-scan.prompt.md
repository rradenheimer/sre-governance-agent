---
mode: agent
description: Run a full SRE governance scan of this repository and summarize findings.
tools: ['codebase', 'runCommands']
---

# /sre-scan

1. Determine the industry profile: read `.sre/profile` if present, else ask the
   user to choose `federal-defense`, `regulated`, or `commercial`.
2. Run:
   ```
   python -m sre_governance.cli scan --repo . --profile ${input:profile} --format all
   ```
3. Report, in this order:
   - Compliance score and policy-gate decision (and whether it would fail CI).
   - Failed **mandatory** controls (ID, severity, reason, remediation, frameworks).
   - Failed **recommended** controls (condensed).
4. Point to `sre-reports/` artifacts (Markdown, JSON, SARIF).
5. Offer to run `/sre-remediate` for the top fix (only edit files if the profile
   allows `propose_pr`).

Never state a control passed/failed without the engine output to back it.
