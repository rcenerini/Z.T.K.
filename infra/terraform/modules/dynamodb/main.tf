# DynamoDB — Tabelas principais do Z.T.K.
# PCI DSS Req. 3.4: SSE-KMS em todos os dados em repouso
# PCI DSS Req. 10: PITR habilitado para tabelas criticas

resource "aws_dynamodb_table" "findings" {
  name         = "${var.name_prefix}-findings"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "finding_id"
  range_key    = "tenant_id"

  attribute {
    name = "finding_id"
    type = "S"
  }
  attribute {
    name = "tenant_id"
    type = "S"
  }
  attribute {
    name = "status"
    type = "S"
  }

  # GSI: busca por status + updated_at (dashboard)
  global_secondary_index {
    name            = "status-updated-index"
    hash_key        = "status"
    range_key       = "updated_at"
    projection_type = "ALL"
  }

  # GSI: busca cross-tenant (auditoria, SOC)
  global_secondary_index {
    name            = "tenant-index"
    hash_key        = "tenant_id"
    projection_type = "ALL"
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }

  point_in_time_recovery {
    enabled = true
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-findings"
    DataClass = "PCI"
    Backup    = "PITR"
  })
}

resource "aws_dynamodb_table" "decisions" {
  name         = "${var.name_prefix}-decisions"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "finding_id"
  range_key    = "decision_id"

  attribute {
    name = "finding_id"
    type = "S"
  }
  attribute {
    name = "decision_id"
    type = "S"
  }
  attribute {
    name = "tier"
    type = "S"
  }

  global_secondary_index {
    name            = "tier-index"
    hash_key        = "tier"
    projection_type = "ALL"
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }

  point_in_time_recovery {
    enabled = true
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-decisions"
    DataClass = "PCI"
  })
}

resource "aws_dynamodb_table" "audit_events" {
  name         = "${var.name_prefix}-audit-events"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "event_id"

  attribute {
    name = "event_id"
    type = "S"
  }
  attribute {
    name = "finding_id"
    type = "S"
  }

  global_secondary_index {
    name            = "finding-index"
    hash_key        = "finding_id"
    projection_type = "ALL"
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-audit-events"
    DataClass = "PCI"
    Immutable = "true"
  })
}

resource "aws_dynamodb_table" "containment_rules" {
  name         = "${var.name_prefix}-containment-rules"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "rule_id"

  attribute {
    name = "rule_id"
    type = "S"
  }
  attribute {
    name = "finding_id"
    type = "S"
  }
  attribute {
    name = "status"
    type = "S"
  }

  global_secondary_index {
    name            = "finding-index"
    hash_key        = "finding_id"
    projection_type = "ALL"
  }

  global_secondary_index {
    name            = "status-index"
    hash_key        = "status"
    projection_type = "ALL"
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }

  point_in_time_recovery {
    enabled = true
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-containment-rules"
    DataClass = "PCI"
  })
}

resource "aws_dynamodb_table" "exceptions" {
  name         = "${var.name_prefix}-exceptions"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "exception_id"

  attribute {
    name = "exception_id"
    type = "S"
  }
  attribute {
    name = "finding_id"
    type = "S"
  }

  global_secondary_index {
    name            = "finding-index"
    hash_key        = "finding_id"
    projection_type = "ALL"
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }

  point_in_time_recovery {
    enabled = true
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-exceptions"
    DataClass = "PCI"
  })
}

# Terraform state lock table
resource "aws_dynamodb_table" "terraform_locks" {
  name         = "${var.name_prefix}-terraform-locks"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }

  server_side_encryption {
    enabled = true
  }

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-terraform-locks"
  })
}
