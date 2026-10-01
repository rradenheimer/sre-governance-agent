---
mode: agent
description: Onboard a new repository to the SRE Governance Agent (profile + .sre scaffolding).
tools: ['codebase', 'editFiles', 'runCommands']
---

# /sre-onboard

Bring a repository under governance for the first time.

1. Ask which industry profile applies (`federal-defense`, `regulated`,
   `commercial`) and write it to `.sre/profile`.
2. Create a starter `.sre/governance.yaml` with honest, conservative defaults —
   mark attestations you cannot verify as `false` so they surface as findings
   rather than false assurances.
3. Run `python -m sre_governance.cli scan --repo . --profile <profile>` to get the
   baseline score.
4. Produce a prioritized remediation backlog (mandatory-critical first) and offer
   to open PRs for `propose_pr` profiles.
5. Explain the audit log and the CI workflow that will enforce the gate going
   forward.

Be explicit that this establishes a measurable baseline; do not inflate the score
by attesting to controls that are not actually in place.
