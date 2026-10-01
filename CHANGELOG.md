# Changelog

All notable changes to the SRE Governance Agent are documented here.
The catalog version is stamped into every report's provenance block.

## [1.0.0] - 2026-10-01

### Added
- Deterministic policy engine (`src/sre_governance/`) with 11 check types,
  severity-weighted scoring, and a profile-driven policy gate.
- Master control catalog of **21 controls** across reliability/SRE, observability,
  governance, security/supply-chain, and compliance — each mapped to NIST 800-53,
  NIST SSDF, EO 14028, SLSA, SOC 2, PCI-DSS, HIPAA, and DORA.
- Three industry profiles: `federal-defense`, `regulated`, `commercial`.
- Reporting in Markdown, JSON, and SARIF with provenance.
- Hash-chained, tamper-evident audit log + `verify-audit`.
- **GitHub Copilot edition**: instructions, audit chat mode, `/sre-scan`,
  `/sre-remediate`, `/sre-onboard` prompts, `AGENTS.md`, and two CI workflows.
- **Claude edition**: `CLAUDE.md`, two subagents, two skills, three slash
  commands, and PreToolUse/PostToolUse safety + audit hooks.
- OPA/Rego policy-as-code gate (`policies/opa/`).
- Human-readable policies (`policies/`), architecture/safety/deployment docs,
  generated framework crosswalk, and a 21-test suite (engine + report + hooks).
