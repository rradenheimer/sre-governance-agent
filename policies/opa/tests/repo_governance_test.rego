# Rego unit tests for policies/opa/repo_governance.rego
# Run with:  opa test policies/opa -v
#
# These verify the gate logic against synthetic reports so the policy-as-code is
# tested like code (same spirit as the Python engine tests).

package sre.governance_test

import rego.v1

import data.sre.governance

# --- helpers ---------------------------------------------------------------

compliant_report := {
	"gate": {"should_fail_pipeline": false, "reasons": []},
	"results": [
		{"control_id": "CMP-AUDIT-033", "status": "PASS", "applicability": "mandatory", "severity": "high", "reason": "ok", "remediation": "-"},
		{"control_id": "SRE-SLO-001", "status": "PASS", "applicability": "mandatory", "severity": "critical", "reason": "ok", "remediation": "-"},
	],
}

gate_failed_report := {
	"gate": {"should_fail_pipeline": true, "reasons": ["compliance score 40 below minimum 75"]},
	"results": [{"control_id": "CMP-AUDIT-033", "status": "PASS", "applicability": "mandatory", "severity": "high", "reason": "ok", "remediation": "-"}],
}

critical_fail_report := {
	"gate": {"should_fail_pipeline": false, "reasons": []},
	"results": [{"control_id": "SEC-SECRETS-020", "status": "FAIL", "applicability": "mandatory", "severity": "critical", "reason": "no secret scanning", "remediation": "enable it"}],
}

audit_fail_report := {
	"gate": {"should_fail_pipeline": false, "reasons": []},
	"results": [{"control_id": "CMP-AUDIT-033", "status": "FAIL", "applicability": "mandatory", "severity": "high", "reason": "audit off", "remediation": "enable audit"}],
}

high_fail_report := {
	"gate": {"should_fail_pipeline": false, "reasons": []},
	"results": [{"control_id": "SEC-SAST-021", "status": "FAIL", "applicability": "mandatory", "severity": "high", "reason": "no sast", "remediation": "add codeql"}],
}

# --- tests -----------------------------------------------------------------

test_compliant_report_has_no_denies if {
	count(governance.deny) == 0 with input as compliant_report
}

test_gate_failure_denies if {
	count(governance.deny) > 0 with input as gate_failed_report
}

test_mandatory_critical_failure_denies if {
	some msg in governance.deny with input as critical_fail_report
	contains(msg, "SEC-SECRETS-020")
}

test_audit_control_failure_denies if {
	some msg in governance.deny with input as audit_fail_report
	contains(msg, "CMP-AUDIT-033")
}

test_mandatory_high_failure_warns_not_denies if {
	count(governance.deny) == 0 with input as high_fail_report
	count(governance.warn) > 0 with input as high_fail_report
}
