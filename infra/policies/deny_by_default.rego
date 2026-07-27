# policy: deny_by_default.rego
# Baseline de seguranca — nega tudo que nao for explicitamente permitido.
# Aplicado como admission control no pipeline CI/CD e em runtime via OPA.
#
# Principio: toda operacao sensivel (IAM change, deploy, WAF rule, PR merge)
# deve ter uma politica explicita que a permita. Tudo o mais e negado.

package ztk.deny_by_default

import rego.v1

# ── Default deny ──────────────────────────────────────────────────

# Regra universal: nega tudo que nao for explicitamente permitido
default allow := false

# ── Operacoes explicitamente permitidas ───────────────────────────

# Leitura de codigo-fonte (read-only, sem risco)
allow if {
    input.operation == "read_code"
    input.resource_type == "repository"
}

# Leitura de findings (read-only)
allow if {
    input.operation == "read_finding"
    input.resource_type == "dynamodb"
}

# Dry-run de regra de contencao (sem efeito colateral)
allow if {
    input.operation == "containment_dry_run"
    input.resource_type == "waf_rule"
    input.dry_run == true
}

# Geracao de patch (validado em sandbox antes de qualquer merge)
allow if {
    input.operation == "generate_patch"
    input.resource_type == "code"
}

# ── Operacoes que exigem HITL (Human-in-the-Loop) ─────────────────

# Merge de PR so permitido se: (1) security review passou, (2) nao e P0/P1
allow if {
    input.operation == "merge_pr"
    input.resource_type == "code"
    input.security_review_passed == true
    input.severity != "P0"
    input.severity != "P1"
}

# Deploy so permitido apos aprovacao CAB
allow if {
    input.operation == "deploy"
    input.environment == "production"
    input.cab_approved == true
}

# ── Auditoria (sempre permitida, append-only) ─────────────────────

allow if {
    input.operation == "write_audit_event"
    input.resource_type == "audit_log"
}

# ── Kill switch (sempre permitido, autoridade SOC) ────────────────

allow if {
    input.operation == "kill_switch"
    input.authority == "SOC"
}

# ── Regras de validacao auxiliares ────────────────────────────────

# Nenhuma operacao de escrita deve ser permitida sem audit_event
deny_audit_gap[msg] {
    input.operation != "write_audit_event"
    not input.audit_enabled
    msg := sprintf("operation '%s' requires audit_enabled=true", [input.operation])
}
