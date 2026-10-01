# SRE Governance Agent

A portable, **AI-assisted but deterministic** governance agent that helps 2,000+
teams adopt and sustain SRE practices and governance controls across **every**
repository — safely, transparently, and at scale. It ships in two interchangeable
flavors that share one engine:

- **GitHub Copilot edition** — `agents/copilot/`
- **Claude (Claude Code) edition** — `agents/claude/`

It serves three industry archetypes out of the box via swappable **profiles**:

| Profile | For | Enforcement | AI autonomy | Min score | Reviewers |
|---|---|---|---|---|---|
| `federal-defense` | Federal agencies, DoD, contractors (CUI/FedRAMP/CMMC) | blocking | suggest-only | 95% | 2 |
| `regulated` | Finance, healthcare, critical infra (SOC2/PCI/HIPAA/DORA) | blocking | propose-PR | 90% | 2 |
| `commercial` | General commercial / product teams | warning | propose-PR | 75% | 1 |

## Why it's safe

The hard governance decision (**pass/fail**) is made by a **deterministic,
offline Python engine** — never by the model. The AI only *interprets* results
and *drafts* minimal remediations, always through reviewed pull requests. Every
action is appended to a **hash-chained, tamper-evident audit log**
(`.sre/audit.jsonl`) and can be independently verified. See
[docs/SAFETY-AND-TRANSPARENCY.md](docs/SAFETY-AND-TRANSPARENCY.md).

```
          ┌──────────────────────────────────────────────┐
          │  AI agent (Copilot OR Claude)                 │
          │  • interprets findings  • drafts PRs          │
          │  • bounded by profile autonomy + hooks        │
          └───────────────┬──────────────────────────────┘
                          │ calls (never decides compliance)
          ┌───────────────▼──────────────────────────────┐
          │  Deterministic engine  (src/sre_governance)   │
          │  scan → evaluate 21 controls → score → gate   │
          │  reports: Markdown · JSON · SARIF             │
          └───────────────┬──────────────────────────────┘
                          │ writes
          ┌───────────────▼──────────────────────────────┐
          │  Hash-chained audit log  (.sre/audit.jsonl)   │
          └──────────────────────────────────────────────┘
```

## What it checks (21 controls)

Reliability/SRE (SLOs, error budgets, incidents, observability, safe change, DR,
toil, on-call), governance (branch protection, reviews, CODEOWNERS, signing),
security/supply-chain (secret scanning, SAST, SCA, SBOM, IaC), and compliance
hygiene (SECURITY.md, license, README, **AI audit trail**). Each control maps to
frameworks — see [docs/FRAMEWORK-CROSSWALK.md](docs/FRAMEWORK-CROSSWALK.md).

**Evidence boundary:** Checks of remote hosting settings use declarations in
`.sre/governance.yaml`, not live GitHub API evidence. A PASS for branch protection,
reviewers, signing, or secret scanning is an attestation, not independent
verification. Verify remote settings separately before asserting compliance.

## Quick start

```bash
pip install -r requirements.txt
export PYTHONPATH=src                       # Windows: $env:PYTHONPATH="src"

# Validate the policy definitions themselves
python -m sre_governance.cli validate-config

# Scan a repo against a profile (emits Markdown + JSON + SARIF)
python -m sre_governance.cli scan --repo . --profile commercial

# Verify the audit chain is intact
python -m sre_governance.cli verify-audit --audit .sre/audit.jsonl
```

## Repository layout

| Path | What |
|---|---|
| `config/control-catalog.yaml` | Source-of-truth controls + framework mappings |
| `config/industry-profiles/` | Federal/Defense, Regulated, Commercial overlays |
| `src/sre_governance/` | Deterministic engine + CLI (no AI, no network) |
| `policies/` | Human-readable policies + OPA/Rego policy-as-code |
| `agents/copilot/` | **GitHub Copilot** edition (instructions, chat mode, prompts, workflows) |
| `agents/claude/` | **Claude** edition (CLAUDE.md, subagents, skills, commands, hooks) |
| `reporting/` | Report templates/assets |
| `tests/` | Engine, report, and hook tests (+ fixtures) |
| `docs/` | Architecture, safety, deployment, crosswalk |

## Deploy to 2,000 repos

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for the rollout playbook (org-wide
templates, phased enforcement, and fleet reporting).

## License

See [LICENSE](LICENSE).
