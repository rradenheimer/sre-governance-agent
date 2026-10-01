---
description: Onboard a new repository to the SRE Governance Agent (profile + .sre scaffolding + baseline).
allowed-tools: Bash, Read, Grep, Glob, Edit, Write
---

Onboard this repository to governance. Requested profile: $ARGUMENTS

1. Confirm the industry profile (`federal-defense`, `regulated`, `commercial`)
   and read its `ai_autonomy` setting in `config/industry-profiles/<profile>.yaml`.
2. For `suggest_only` profiles, do not edit files or run commands that write to the
   repository; present proposed diffs for `.sre/profile` and `.sre/governance.yaml`.
   For `propose_pr` profiles, write the profile to `.sre/profile` and create a
   conservative `.sre/governance.yaml` — mark any attestation you cannot verify as
   `false` so gaps surface honestly rather than inflating the score.
3. For `propose_pr` profiles, run
   `PYTHONPATH=src python -m sre_governance.cli scan --repo . --profile <profile>`
   to capture the baseline. For `suggest_only`, show this command for a human to
   run after applying the proposed diffs.
4. Present a prioritized remediation backlog (mandatory-critical first) and, for
   `propose_pr` profiles, offer to open PRs via `/sre-remediate`.
5. Explain the audit log and the CI gate that will enforce compliance going forward.

Do not attest to controls that are not actually in place.
