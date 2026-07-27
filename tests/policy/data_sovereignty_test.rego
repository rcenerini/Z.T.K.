package ztk.data_sovereignty

import rego.v1

test_no_violations_for_compliant_routing if {
    violations = violation with input as {
        "llm_requests": [
            {"finding_id": "f1", "data_scope": "NON_PCI", "provider": "bedrock", "user_message": "analyze code"}
        ],
        "vllm_instances": []
    }
    count(violations) == 0
}

test_detect_pci_to_bedrock if {
    violations = violation with input as {
        "llm_requests": [
            {"finding_id": "f1", "data_scope": "PCI", "provider": "bedrock", "user_message": "analyze"}
        ],
        "vllm_instances": []
    }
    count(violations) > 0
}

test_detect_pii_to_bedrock_no_force_local if {
    violations = violation with input as {
        "llm_requests": [
            {"finding_id": "f1", "data_scope": "PII", "provider": "bedrock", "force_local": false, "user_message": "analyze"}
        ],
        "vllm_instances": []
    }
    count(violations) > 0
}

test_detect_pan_in_bedrock_prompt if {
    violations = violation with input as {
        "llm_requests": [
            {"finding_id": "f1", "data_scope": "NON_PCI", "provider": "bedrock", "user_message": "PAN: 4111 1111 1111 1111"}
        ],
        "vllm_instances": []
    }
    count(violations) > 0
}

test_detect_vllm_no_network_isolation if {
    violations = violation with input as {
        "llm_requests": [],
        "vllm_instances": [
            {"instance_id": "i-pci", "network_isolation": false, "persistent_storage": false}
        ]
    }
    count(violations) > 0
}

test_detect_vllm_persistent_storage if {
    violations = violation with input as {
        "llm_requests": [],
        "vllm_instances": [
            {"instance_id": "i-pci", "network_isolation": true, "persistent_storage": true}
        ]
    }
    count(violations) > 0
}

test_compliant_vllm_config if {
    violations = violation with input as {
        "llm_requests": [],
        "vllm_instances": [
            {"instance_id": "i-safe", "network_isolation": true, "persistent_storage": false}
        ]
    }
    count(violations) == 0
}