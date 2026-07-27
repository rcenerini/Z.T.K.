# Bedrock — Configuracao de acesso a modelos Claude
# Bedrock e servico gerenciado — nao cria clusters/servers
# Apenas configura: IAM + guardrails + cost budget + model access

locals {
  models = {
    haiku  = "anthropic.claude-3-5-haiku-20241022-v1:0"
    sonnet = "anthropic.claude-3-5-sonnet-20241022-v2:0"
  }
}

# Bedrock Guardrail — previne saidas inseguras
resource "aws_bedrock_guardrail" "main" {
  name                      = "${var.name_prefix}-guardrail"
  description               = "Guardrail para saidas do copilot Z.T.K."
  blocked_outputs_messaging = "NONE"
  blocked_input_messaging   = "NONE"

  content_policy_config {
    filters_config {
      input_strength  = "NONE"
      output_strength = "MEDIUM"
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

  word_policy_config {
    managed_word_lists_config {
      type = "PROFANITY"
    }
  }

  tags = var.tags
}

# Bedrock Model Invocation Logging (PCI DSS 10.2)
resource "aws_bedrock_model_invocation_logging_configuration" "main" {
  logging_config {
    cloudwatch_config {
      log_group_name = aws_cloudwatch_log_group.bedrock.name
      role_arn       = aws_iam_role.bedrock_logging.arn
    }
    s3_config {
      bucket_name = "${var.name_prefix}-bedrock-logs"
    }
    embedding_data_delivery_enabled = false
    image_data_delivery_enabled     = false
    text_data_delivery_enabled      = true
  }
}

resource "aws_cloudwatch_log_group" "bedrock" {
  name              = "/aws/bedrock/${var.name_prefix}"
  retention_in_days = 365
  kms_key_id        = var.kms_key_arn
  tags              = var.tags
}

# IAM Role for Bedrock logging
resource "aws_iam_role" "bedrock_logging" {
  name = "${var.name_prefix}-bedrock-logging"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { Service = "bedrock.amazonaws.com" }
      Action = "sts:AssumeRole"
    }]
  })
  tags = var.tags
}

resource "aws_iam_role_policy" "bedrock_logging" {
  name = "${var.name_prefix}-bedrock-logging-policy"
  role = aws_iam_role.bedrock_logging.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = ["${aws_cloudwatch_log_group.bedrock.arn}:*"]
    }]
  })
}

# Bedrock Cost Budget (AWS Budgets)
resource "aws_budgets_budget" "bedrock" {
  name              = "${var.name_prefix}-bedrock-monthly"
  budget_type       = "COST"
  limit_amount      = var.bedrock_monthly_budget_usd
  limit_unit        = "USD"
  time_unit         = "MONTHLY"
  time_period_start = "2026-01-01_00:00"

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = var.budget_alert_emails
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = var.budget_alert_emails
  }
}
