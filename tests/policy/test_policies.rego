# Tests for Z.T.K. OPA Policies
# Run: opa test infra/policies/ -v

package ztk.deny_by_default_test

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

package ztk.iam_least_privilege_test

import rego.v1

test_no_violations_for_compliant_policy if {
    violations := violation with input as {
        "iam_policies": [
            {
                "PolicyName": "lambda-execution",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": ["dynamodb:GetItem", "dynamodb:PutItem"],
                    "Resource": ["arn:aws:dynamodb:*:*:table/ztk-*"]
                }]
            }
        ]
    }
    count(violations) == 0
}

test_detect_allow_star_star if {
    violations := violation with input as {
        "iam_policies": [
            {
                "PolicyName": "dangerous-policy",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": ["*"],
                    "Resource": ["*"]
                }]
            }
        ]
    }
    count(violations) > 0
}

test_detect_resource_star_no_condition if {
    violations := violation with input as {
        "iam_policies": [
            {
                "PolicyName": "loose-policy",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": ["s3:GetObject"],
                    "Resource": ["*"]
                }]
            }
        ]
    }
    count(violations) > 0
}

test_detect_dangerous_iam_action if {
    violations := violation with input as {
        "iam_policies": [
            {
                "PolicyName": "admin-policy",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": ["iam:*"],
                    "Resource": ["arn:aws:iam::*:role/ztk-*"]
                }]
            }
        ]
    }
    count(violations) > 0
}

test_no_kms_rotation_violation if {
    violations := violation with input as {
        "kms_keys": [{"key_id": "key-1", "enable_key_rotation": false}]
    }
    count(violations) > 0
}

test_public_bucket_violation if {
    violations := violation with input as {
        "s3_buckets": [{"name": "public-bucket", "block_public_access": false}]
    }
    count(violations) > 0
}

test_dynamodb_no_pitr_violation if {
    violations := violation with input as {
        "dynamodb_tables": [{"name": "findings", "point_in_time_recovery": false, "encryption_enabled": true}]
    }
    count(violations) > 0
}

test_dynamodb_no_encryption_violation if {
    violations := violation with input as {
        "dynamodb_tables": [{"name": "findings", "point_in_time_recovery": true, "encryption_enabled": false}]
    }
    count(violations) > 0
}

# ── data_sovereignty ──────────────────────────────────────────────

package ztk.data_sovereignty_test

import rego.v1

test_no_violations_for_compliant_routing if {
    violations := violation with input as {
        "llm_requests": [
            {"finding_id": "f1", "data_scope": "NON_PCI", "provider": "bedrock", "user_message": "analyze code"}
        ],
        "vllm_instances": []
    }
    count(violations) == 0
}

test_detect_pci_to_bedrock if {
    violations := violation with input as {
        "llm_requests": [
            {"finding_id": "f1", "data_scope": "PCI", "provider": "bedrock", "user_message": "analyze"}
        ],
        "vllm_instances": []
    }
    count(violations) > 0
}

test_detect_pii_to_bedrock_no_force_local if {
    violations := violation with input as {
        "llm_requests": [
            {"finding_id": "f1", "data_scope": "PII", "provider": "bedrock", "force_local": false, "user_message": "analyze"}
        ],
        "vllm_instances": []
    }
    count(violations) > 0
}

test_detect_pan_in_bedrock_prompt if {
    violations := violation with input as {
        "llm_requests": [
            {"finding_id": "f1", "data_scope": "NON_PCI", "provider": "bedrock", "user_message": "PAN: 4111 1111 1111 1111"}
        ],
        "vllm_instances": []
    }
    count(violations) > 0
}

test_detect_vllm_no_network_isolation if {
    violations := violation with input as {
        "llm_requests": [],
        "vllm_instances": [
            {"instance_id": "i-pci", "network_isolation": false, "persistent_storage": false}
        ]
    }
    count(violations) > 0
}

test_detect_vllm_persistent_storage if {
    violations := violation with input as {
        "llm_requests": [],
        "vllm_instances": [
            {"instance_id": "i-pci", "network_isolation": true, "persistent_storage": true}
        ]
    }
    count(violations) > 0
}

test_compliant_vllm_config if {
    violations := violation with input as {
        "llm_requests": [],
        "vllm_instances": [
            {"instance_id": "i-safe", "network_isolation": true, "persistent_storage": false}
        ]
    }
    count(violations) == 0
}
