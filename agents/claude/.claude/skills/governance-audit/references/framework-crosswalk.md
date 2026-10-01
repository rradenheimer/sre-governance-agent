# Framework Crosswalk

Generated from `config/control-catalog.yaml`. Maps each compliance framework to the SRE Governance controls that satisfy it.

## DORA-EU

| Control | Framework reference(s) |
|---|---|
| `SRE-SLO-001` | Art.6 |

## EO-14028

| Control | Framework reference(s) |
|---|---|
| `SEC-SBOM-023` | Sec.4 |

## HIPAA

| Control | Framework reference(s) |
|---|---|
| `CMP-AUDIT-033` | 164.312(b) |
| `SRE-DR-006` | 164.308(a)(7) |
| `SRE-INC-003` | 164.308(a)(6) |

## NIST-800-53

| Control | Framework reference(s) |
|---|---|
| `CMP-AUDIT-033` | AU-2, AU-3, AU-12 |
| `CMP-SECPOL-030` | RA-5 |
| `GOV-BP-010` | CM-5, AC-6 |
| `GOV-CODEOWNERS-012` | AC-5, PS-2 |
| `GOV-REV-011` | AC-5, SA-11 |
| `GOV-SIGN-013` | CM-5, SI-7 |
| `SEC-IAC-024` | CM-6, CM-7 |
| `SEC-SAST-021` | RA-5, SA-11 |
| `SEC-SBOM-023` | SA-8 |
| `SEC-SCA-022` | RA-5, SA-12 |
| `SEC-SECRETS-020` | IA-5, SA-15 |
| `SRE-CHG-005` | CM-3, CM-4 |
| `SRE-DR-006` | CP-9, CP-10 |
| `SRE-EB-002` | CP-2 |
| `SRE-INC-003` | IR-4, IR-8 |
| `SRE-OBS-004` | AU-6, SI-4 |
| `SRE-ONCALL-008` | IR-7 |
| `SRE-SLO-001` | CP-2, SA-4 |
| `SRE-TOIL-007` | PL-2 |

## NIST-SSDF

| Control | Framework reference(s) |
|---|---|
| `CMP-SECPOL-030` | RV.1 |
| `GOV-BP-010` | PS.1, PO.5 |
| `GOV-REV-011` | PW.7 |
| `GOV-SIGN-013` | PS.2 |
| `SEC-IAC-024` | PW.5 |
| `SEC-SAST-021` | PW.8 |
| `SEC-SBOM-023` | PS.3 |
| `SEC-SCA-022` | PW.4, RV.1 |
| `SEC-SECRETS-020` | PW.4 |
| `SRE-CHG-005` | PO.3, PW.6 |

## PCI-DSS

| Control | Framework reference(s) |
|---|---|
| `SEC-SAST-021` | 6.3.2 |
| `SEC-SECRETS-020` | 3.5, 6.3 |

## SLSA

| Control | Framework reference(s) |
|---|---|
| `GOV-BP-010` | Source L2 |
| `GOV-SIGN-013` | Provenance L2 |
| `SEC-SBOM-023` | Provenance L2 |
| `SEC-SCA-022` | Build L2 |

## SOC2

| Control | Framework reference(s) |
|---|---|
| `CMP-AUDIT-033` | CC7.2 |
| `CMP-LICENSE-031` | CC1.1 |
| `CMP-README-032` | CC2.2 |
| `GOV-BP-010` | CC8.1 |
| `GOV-CODEOWNERS-012` | CC1.3 |
| `GOV-REV-011` | CC8.1 |
| `SRE-CHG-005` | CC8.1 |
| `SRE-DR-006` | A1.2 |
| `SRE-EB-002` | A1.1 |
| `SRE-INC-003` | CC7.3, CC7.4 |
| `SRE-OBS-004` | CC7.1, CC7.2 |
| `SRE-ONCALL-008` | CC7.3 |
| `SRE-SLO-001` | A1.1 |
