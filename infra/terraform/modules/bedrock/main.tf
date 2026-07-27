# Bedrock — Configuracao de acesso a modelos Claude
# Nao cria recursos AWS (Bedrock e servico gerenciado)
# Apenas configura IAM + guardrails + model IDs

locals {
  # Modelos Claude 3.5 disponiveis via Bedrock
  models = {
    haiku  = "anthropic.claude-3-5-haiku-20241022-v1:0"
    sonnet = "anthropic.claude-3-5-sonnet-20241022-v2:0"
  }
}

# Bedrock Guardrail — previne saidas inseguras
# (Nota: guardrails sao aplicados no codigo via prompt_builder, nao via Bedrock API)
resource "aws_bedrock_guardrail" "main" {
  name                      = "${var.name_prefix}-guardrail"
  description               = "Guardrail para saidas do copilot Z.T.K."
  blocked_outputs_messaging = "NONE"
  blocked_input_messaging   = "NONE"

  content_policy_config {
    # Filtros de conteudo padrao
    filters_config {
      input_strength  = "NONE"   # Input: nao filtramos (codigo e tecnico)
      output_strength = "MEDIUM" # Output: filtro medio (analises nao devem ser toxicas)
      type            = "HATE"
    }
    filters_config {
      input_strength  = "NONE"
      output_strength = "MEDIUM"
      type            = "SEXUAL"
    }
    filters_config {
      input_strength  = "NONE"
      output_strength = "MEDIUM"
      type            = "VIOLENCE"
    }
  }

  # Palavras bloqueadas em output
  # Nao bloquear palavras comuns de seguranca (SQL, injection, etc.)
  word_policy_config {
    managed_word_lists_config {
      type = "PROFANITY"
    }
  }

  tags = var.tags
}
