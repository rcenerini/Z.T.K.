# policy: data_sovereignty.rego
# Garante que dados PCI/PII nunca sao enviados para Bedrock ou servicos externos.
# Aplicado no router LLM (Camada 7) — runtime enforcement.
#
# Regra de ouro: data_scope=PCI|PII → provider=vllm_local OBRIGATORIAMENTE
# Sem excecoes. Sem bypass.

package ztk.data_sovereignty

import rego.v1

# ── PCI / PII routing enforcement ─────────────────────────────────

# Violacao: dados PCI roteados para Bedrock
violation[msg] {
    request := input.llm_requests[_]
    request.data_scope == "PCI"
    request.provider == "bedrock"
    msg := sprintf("CRITICAL: finding '%s' — PCI data routed to Bedrock (must use vllm_local)", [request.finding_id])
}

# Violacao: dados PII roteados para Bedrock sem force_local
violation[msg] {
    request := input.llm_requests[_]
    request.data_scope == "PII"
    request.provider == "bedrock"
    not request.force_local
    msg := sprintf("HIGH: finding '%s' — PII data routed to Bedrock without force_local flag", [request.finding_id])
}

# Violacao: force_local=false com data_scope=PCI (deveria ser impossivel)
violation[msg] {
    request := input.llm_requests[_]
    request.data_scope == "PCI"
    request.force_local == false
    msg := sprintf("CRITICAL: finding '%s' — PCI data with force_local=false (should never happen)", [request.finding_id])
}

# Violacao: dados PAN detectados em prompt para Bedrock
pan_patterns := [
    "\\b[34]\\d{3}[ -]?\\d{4}[ -]?\\d{4}[ -]?\\d{4}\\b",  # PAN-like 16-digit
    "\\b\\d{4}[ -]\\d{6}[ -]\\d{5}\\b",                      # PAN com espacos
]

violation[msg] {
    request := input.llm_requests[_]
    request.provider == "bedrock"
    pattern := pan_patterns[_]
    regex.match(pattern, request.user_message)
    msg := sprintf("CRITICAL: PAN pattern detected in Bedrock prompt for finding '%s'", [request.finding_id])
}

# ── vLLM local security ──────────────────────────────────────────

# Violacao: vLLM local sem isolamento de rede
violation[msg] {
    instance := input.vllm_instances[_]
    not instance.network_isolation
    msg := sprintf("HIGH: vLLM instance '%s' processing PCI data without network isolation", [instance.instance_id])
}

# Violacao: vLLM local com storage persistente (dados PCI podem vazar)
violation[msg] {
    instance := input.vllm_instances[_]
    instance.persistent_storage
    msg := sprintf("HIGH: vLLM instance '%s' has persistent storage enabled (PCI data must be ephemeral)", [instance.instance_id])
}

# ── Default ───────────────────────────────────────────────────────

default compliant := false

compliant if {
    count(violation) == 0
}
