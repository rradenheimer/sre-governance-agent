---
description: Scan this repository and report SRE governance compliance for the active profile.
allowed-tools: Bash, Read, Grep, Glob
---

Run a full SRE governance assessment.

1. Resolve the profile from `.sre/profile` (default `commercial`). Profile arg: $ARGUMENTS
2. Execute:
   ```bash
   PYTHONPATH=src python -m sre_governance.cli scan --repo . --profile <profile> --format all
   PYTHONPATH=src python -m sre_governance.cli verify-audit --audit .sre/audit.jsonl
   ```
3. Summarize: gate decision + score (and CI impact), then failed **mandatory**
   controls first (ID, severity, reason, remediation, frameworks), then failed
   recommended controls briefly.
4. Link `sre-reports/` artifacts. Do not edit any files in this command.
