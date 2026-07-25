# Policy-as-Code — ZTK
# Deny-by-default para todo agente novo

package ztk.agent_onboarding

import future.keywords.if
import future.keywords.in

# Dados esperados no input
# input = {
#   "agent_id": "L2.01",
#   "camada": 2,
#   "has_handler": true,
#   "has_tests": true,
#   "has_audit_event": true,
#   "has_fail_closed": true,
#   "iam_role_exists": true,
#   "shadow_mode_defined": true,
#   "pci_scope": false
# }

# Regra default: negar tudo
default allow := false

# Permitir se TODAS as condicoes obrigatorias forem verdadeiras
allow if {
  input.has_handler
  input.has_tests
  input.has_audit_event
  input.has_fail_closed
  input.iam_role_exists
  input.shadow_mode_defined
}

# Mensagens de violacao
violations contains msg if {
  not input.has_handler
  msg := "Agente deve ter handler.py definido"
}

violations contains msg if {
  not input.has_tests
  msg := "Agente deve ter testes (cobertura >= 85%)"
}

violations contains msg if {
  not input.has_audit_event
  msg := "Agente deve emitir audit event para toda acao"
}

violations contains msg if {
  not input.has_fail_closed
  msg := "Agente deve implementar comportamento fail-closed"
}

violations contains msg if {
  not input.iam_role_exists
  msg := "Agente deve ter role IAM dedicada (least privilege)"
}

violations contains msg if {
  not input.shadow_mode_defined
  msg := "Agente deve suportar shadow_mode desde v1"
}

# Pisos de severidade — nao negociaveis
package ztk.severity_floor

default floor := "P4"

floor = "P1" if {
  input.data_classification == "CHD"
}

floor = "P1" if {
  input.pci_scope == true
}

floor = "P0" if {
  input.domain == "antifraude"
}

floor = "P1" if {
  input.domain == "lgpd_sensivel"
}

# Debate nao pode rebaixar abaixo do piso
debate_result_valid if {
  input.debate_severity >= floor
}

# Roteamento LLM — escopo PCI
package ztk.model_routing

default use_bedrock := true

use_bedrock := false if {
  input.pci_scope == true
}

use_bedrock := false if {
  input.contains_chd == true
}

use_bedrock := false if {
  input.contains_pan == true
}

# Validacao de container — security context
package ztk.container_security

allow if {
  input.security_context.runAsNonRoot == true
  input.security_context.readOnlyRootFilesystem == true
  input.security_context.allowPrivilegeEscalation == false
  input.resources.limits.cpu != ""
  input.resources.limits.memory != ""
}
