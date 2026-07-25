package ztk.agent_onboarding_test

import data.ztk.agent_onboarding

test_allow_complete_agent if {
    agent_onboarding.allow with input as {
        "agent_id": "L2.01",
        "camada": 2,
        "has_handler": true,
        "has_tests": true,
        "has_audit_event": true,
        "has_fail_closed": true,
        "iam_role_exists": true,
        "shadow_mode_defined": true
    }
}

test_deny_missing_handler if {
    not agent_onboarding.allow with input as {
        "agent_id": "L2.01",
        "camada": 2,
        "has_handler": false,
        "has_tests": true,
        "has_audit_event": true,
        "has_fail_closed": true,
        "iam_role_exists": true,
        "shadow_mode_defined": true
    }
    agent_onboarding.violations["Agente deve ter handler.py definido"] with input as {
        "agent_id": "L2.01",
        "camada": 2,
        "has_handler": false,
        "has_tests": true,
        "has_audit_event": true,
        "has_fail_closed": true,
        "iam_role_exists": true,
        "shadow_mode_defined": true
    }
}

test_deny_missing_tests if {
    not agent_onboarding.allow with input as {
        "agent_id": "L2.01",
        "camada": 2,
        "has_handler": true,
        "has_tests": false,
        "has_audit_event": true,
        "has_fail_closed": true,
        "iam_role_exists": true,
        "shadow_mode_defined": true
    }
}

test_deny_missing_audit if {
    not agent_onboarding.allow with input as {
        "agent_id": "L2.01",
        "camada": 2,
        "has_handler": true,
        "has_tests": true,
        "has_audit_event": false,
        "has_fail_closed": true,
        "iam_role_exists": true,
        "shadow_mode_defined": true
    }
}

test_deny_missing_fail_closed if {
    not agent_onboarding.allow with input as {
        "agent_id": "L2.01",
        "camada": 2,
        "has_handler": true,
        "has_tests": true,
        "has_audit_event": true,
        "has_fail_closed": false,
        "iam_role_exists": true,
        "shadow_mode_defined": true
    }
}

test_deny_missing_iam if {
    not agent_onboarding.allow with input as {
        "agent_id": "L2.01",
        "camada": 2,
        "has_handler": true,
        "has_tests": true,
        "has_audit_event": true,
        "has_fail_closed": true,
        "iam_role_exists": false,
        "shadow_mode_defined": true
    }
}

test_deny_missing_shadow if {
    not agent_onboarding.allow with input as {
        "agent_id": "L2.01",
        "camada": 2,
        "has_handler": true,
        "has_tests": true,
        "has_audit_event": true,
        "has_fail_closed": true,
        "iam_role_exists": true,
        "shadow_mode_defined": false
    }
}
