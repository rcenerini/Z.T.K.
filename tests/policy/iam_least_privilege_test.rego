package ztk.iam_least_privilege

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