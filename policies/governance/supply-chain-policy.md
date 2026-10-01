# Policy: Secure Software Supply Chain

**Policy ID:** POL-SEC-SUPPLY · **Controls:** `SEC-SECRETS-020`, `SEC-SAST-021`,
`SEC-SCA-022`, `SEC-SBOM-023`, `SEC-IAC-024`, `CMP-SECPOL-030`
**Applies to:** every repository · **Enforcement:** per industry profile

## Statement

Every repository MUST protect its software supply chain from secret leakage,
known-vulnerable dependencies, insecure code, and misconfigured infrastructure,
and MUST be able to produce an SBOM.

## Requirements

1. **Secret scanning + push protection** enabled; exposed secrets rotated
   immediately (`SEC-SECRETS-020`).
2. **SAST / code scanning** runs on PRs and the default branch (`SEC-SAST-021`).
3. **Dependency / SCA scanning** (Dependabot/Renovate) enabled; CI fails on
   critical advisories (`SEC-SCA-022`).
4. **SBOM** (CycloneDX/SPDX) generated and published per release (`SEC-SBOM-023`).
5. **IaC scanning** (Checkov/tfsec) runs when IaC is present (`SEC-IAC-024`).
6. **SECURITY.md** describes coordinated vulnerability disclosure
   (`CMP-SECPOL-030`).

## Rationale

The majority of modern code is third-party, and leaked credentials and cloud
misconfigurations are leading breach vectors. Maps to NIST SSDF (PW.4/PW.5/PW.8,
PS.3), EO 14028 §4, SLSA Build/Provenance L2, NIST 800-53 RA-5/SA-11, and
PCI-DSS 6.3.

## Verification

Evaluated by the `SEC-*` and `CMP-SECPOL-030` controls; failures are also emitted
as SARIF to the GitHub Security tab.
