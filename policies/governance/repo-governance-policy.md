# Policy: Repository Governance Baseline

**Policy ID:** POL-GOV-REPO · **Controls:** `GOV-BP-010`, `GOV-REV-011`,
`GOV-CODEOWNERS-012`, `GOV-SIGN-013`, `CMP-AUDIT-033`
**Applies to:** every repository · **Enforcement:** per industry profile

## Statement

Every repository MUST enforce source-integrity controls proportional to its
industry profile before code reaches a production branch.

## Requirements

| Requirement | Control | Commercial | Regulated | Federal/Defense |
|---|---|---|---|---|
| Protected default branch (no direct/force push) | `GOV-BP-010` | Required | Required | Required |
| Minimum approving reviewers | `GOV-REV-011` | 1 | 2 | 2 |
| CODEOWNERS routing | `GOV-CODEOWNERS-012` | Recommended | Required | Required |
| Signed commits | `GOV-SIGN-013` | Recommended | Required | Required |
| Immutable automation audit log | `CMP-AUDIT-033` | Required | Required | Required |

## Separation of duties

The author of a change MUST NOT be its sole approver. Automated agents MUST NOT
self-approve or merge. All agent actions are recorded to a hash-chained audit log
(`.sre/audit.jsonl`), verifiable via `cli verify-audit`.

## Rationale

Branch protection, peer review, ownership, and signing are the baseline
integrity controls for source code. Maps to NIST 800-53 AC-5/CM-5/SI-7, NIST SSDF
PS.1/PW.7, SLSA Source L2, and SOC 2 CC8.1.

## Verification

Declared posture lives in `.sre/governance.yaml`. The bundled CI workflow
evaluates these attestations; independently verify the corresponding GitHub
settings before asserting the controls are enforced remotely.
