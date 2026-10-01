---
description: Onboard a new repository to the SRE Governance Agent (profile + .sre scaffolding + baseline).
allowed-tools: Bash, Read, Grep, Glob, Edit, Write
---

Onboard this repository to governance. Requested profile: $ARGUMENTS

1. Confirm the industry profile (`federal-defense`, `regulated`, `commercial`)
   and write it to `.sre/profile`.
2. Create a conservative `.sre/governance.yaml` — mark any attestation you cannot
   verify as `false` so gaps surface honestly rather than inflating the score.
3. Run `PYTHONPATH=src python -m sre_governance.cli scan --repo . --profile <profile>`
   to capture the baseline.
4. Present a prioritized remediation backlog (mandatory-critical first) and, for
   `propose_pr` profiles, offer to open PRs via `/sre-remediate`.
5. Explain the audit log and the CI gate that will enforce compliance going forward.

Do not attest to controls that are not actually in place.
