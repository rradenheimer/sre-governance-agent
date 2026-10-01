# Policy: Incident Management & Blameless Postmortems

**Policy ID:** POL-SRE-INC · **Controls:** `SRE-INC-003`, `SRE-ONCALL-008`
**Applies to:** all production services · **Enforcement:** per industry profile

## Statement

Every production service MUST have a documented incident-response process, a
sustainable on-call rotation with defined escalation, and a blameless postmortem
practice.

## Requirements

1. An incident-response document (`docs/incident-response.md` or `runbooks/`)
   defines severities, roles (IC, comms, ops), and communication channels.
2. A blameless postmortem template exists and postmortems are required for all
   SEV1/SEV2 incidents within a defined SLA.
3. On-call rotation and escalation are declared (`sre.oncall_defined: true`) and
   are humane (coverage, handoff, compensation per org policy).
4. Action items from postmortems are tracked to closure.

## Rationale

Consistent incident handling reduces MTTR; blameless postmortems convert
incidents into durable learning. Maps to NIST 800-53 IR-4/IR-7/IR-8, SOC 2
CC7.3/CC7.4, and HIPAA 164.308(a)(6).

## Verification

Evaluated by `SRE-INC-003` and `SRE-ONCALL-008` in the policy engine.
