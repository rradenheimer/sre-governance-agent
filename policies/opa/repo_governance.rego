# SRE Governance — policy-as-code gate (Rego / OPA, for `conftest test`)
#
# Evaluates the engine's JSON report (sre-reports/sre-governance-report.json).
# Use in CI or admission control to deny merges/promotions that violate the gate:
#
#   conftest test sre-reports/sre-governance-report.json --policy policies/opa
#
# This complements (does not replace) the engine's own gate; it lets platform
# teams enforce the same decision in OPA/Gatekeeper pipelines.

package sre.governance

import rego.v1

# Hard gate: honor the engine's blocking decision.
deny contains msg if {
	input.gate.should_fail_pipeline == true
	some reason in input.gate.reasons
	msg := sprintf("policy gate failed: %s", [reason])
}

# No mandatory CRITICAL control may fail, regardless of enforcement mode.
deny contains msg if {
	some r in input.results
	r.status == "FAIL"
	r.applicability == "mandatory"
	r.severity == "critical"
	msg := sprintf("mandatory CRITICAL control failed: %s — %s", [r.control_id, r.reason])
}

# Audit integrity control (CMP-AUDIT-033) must pass everywhere.
deny contains msg if {
	some r in input.results
	r.control_id == "CMP-AUDIT-033"
	r.status == "FAIL"
	msg := "audit logging control CMP-AUDIT-033 must pass: enable governance.audit_logging"
}

# Warn (does not fail) on mandatory HIGH failures so teams see trajectory.
warn contains msg if {
	some r in input.results
	r.status == "FAIL"
	r.applicability == "mandatory"
	r.severity == "high"
	msg := sprintf("mandatory HIGH control failed: %s — %s", [r.control_id, r.remediation])
}
