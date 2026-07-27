# SQS — Filas do pipeline Z.T.K.
# Cada fila tem DLQ associada para mensagens que falham apos 3 retentativas

locals {
  queues = {
    ingestion     = { visibility = 300, max_receive = 3, retention = 1209600 }
    normalization = { visibility = 300, max_receive = 3, retention = 1209600 }
    decision      = { visibility = 120, max_receive = 3, retention = 345600 }
    copilot       = { visibility = 600, max_receive = 2, retention = 345600 }
    hitl          = { visibility = 3600, max_receive = 2, retention = 1209600 }
    remediation   = { visibility = 900, max_receive = 3, retention = 345600 }
  }
}

resource "aws_sqs_queue" "main" {
  for_each = local.queues

  name                       = "${var.name_prefix}-${each.key}"
  visibility_timeout_seconds = each.value.visibility
  message_retention_seconds  = each.value.retention

  # Criptografia em repouso (PCI DSS 3.4)
  sqs_managed_sse_enabled = true

  # Deduplicacao (FIFO nao necessario para pipeline idempotente)
  fifo_queue = false

  # Redrive policy para DLQ
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.dlq[each.key].arn
    maxReceiveCount     = each.value.max_receive
  })

  tags = merge(var.tags, {
    Name     = "${var.name_prefix}-${each.key}"
    Pipeline = each.key
  })
}

resource "aws_sqs_queue" "dlq" {
  for_each = local.queues

  name                      = "${var.name_prefix}-${each.key}-dlq"
  message_retention_seconds = 1209600 # 14 dias (PCI DSS 10.3)

  sqs_managed_sse_enabled = true

  tags = merge(var.tags, {
    Name     = "${var.name_prefix}-${each.key}-dlq"
    Pipeline = each.key
    DLQ      = "true"
  })
}
