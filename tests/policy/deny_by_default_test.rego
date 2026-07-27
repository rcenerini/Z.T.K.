package ztk.deny_by_default

import rego.v1

# ── deny_by_default ───────────────────────────────────────────────

test_read_code_allowed if {
    allow with input as {"operation": "read_code", "resource_type": "repository"}
}

test_read_finding_allowed if {
    allow with input as {"operation": "read_finding", "resource_type": "dynamodb"}
}

test_containment_dry_run_allowed if {
    allow with input as {"operation": "containment_dry_run", "resource_type": "waf_rule", "dry_run": true}
}

test_containment_live_denied if {
    not allow with input as {"operation": "containment_dry_run", "resource_type": "waf_rule", "dry_run": false}
}

test_merge_pr_allowed_with_review if {
    allow with input as {"operation": "merge_pr", "resource_type": "code", "security_review_passed": true, "severity": "P2"}
}

test_merge_pr_denied_p0 if {
    not allow with input as {"operation": "merge_pr", "resource_type": "code", "security_review_passed": true, "severity": "P0"}
}

test_merge_pr_denied_p1 if {
    not allow with input as {"operation": "merge_pr", "resource_type": "code", "security_review_passed": true, "severity": "P1"}
}

test_merge_pr_denied_no_review if {
    not allow with input as {"operation": "merge_pr", "resource_type": "code", "security_review_passed": false, "severity": "P2"}
}

test_deploy_prod_requires_cab if {
    allow with input as {"operation": "deploy", "environment": "production", "cab_approved": true}
}

test_deploy_prod_denied_no_cab if {
    not allow with input as {"operation": "deploy", "environment": "production", "cab_approved": false}
}

test_audit_event_always_allowed if {
    allow with input as {"operation": "write_audit_event", "resource_type": "audit_log"}
}

test_kill_switch_soc_allowed if {
    allow with input as {"operation": "kill_switch", "authority": "SOC"}
}

test_kill_switch_others_denied if {
    not allow with input as {"operation": "kill_switch", "authority": "ENGINEERING"}
}

test_unknown_operation_denied if {
    not allow with input as {"operation": "admin_all_things", "resource_type": "*"}
}

test_audit_gap_detected if {
    violations := deny_audit_gap with input as {"operation": "deploy", "environment": "production", "cab_approved": true}
    count(violations) > 0
}

# ── iam_least_privilege ───────────────────────────────────────────