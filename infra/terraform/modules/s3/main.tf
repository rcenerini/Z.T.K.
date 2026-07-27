# S3 — Buckets do Z.T.K.
# PCI DSS Req. 3.4: criptografia SSE-KMS obrigatoria
# PCI DSS Req. 10: append-only para audit trail

# Bucket de auditoria (append-only via S3 Object Lock)
resource "aws_s3_bucket" "audit_trail" {
  bucket = "${var.name_prefix}-audit-trail"
  tags   = merge(var.tags, { Name = "${var.name_prefix}-audit-trail", Immutable = "true" })
}

resource "aws_s3_bucket_versioning" "audit_trail" {
  bucket = aws_s3_bucket.audit_trail.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit_trail" {
  bucket = aws_s3_bucket.audit_trail.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = var.kms_key_arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "audit_trail" {
  bucket                  = aws_s3_bucket.audit_trail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "audit_trail" {
  bucket = aws_s3_bucket.audit_trail.id
  rule {
    id     = "archive"
    status = "Enabled"
    filter {
      prefix = ""
    }
    transition {
      days          = 90
      storage_class = "GLACIER"
    }
    expiration {
      days = 1825 # 5 anos (PCI DSS Requisito 10.7)
    }
  }
}

# Bucket de evidencias (codigo fonte, logs de SAST)
resource "aws_s3_bucket" "evidence" {
  bucket = "${var.name_prefix}-evidence"
  tags   = merge(var.tags, { Name = "${var.name_prefix}-evidence" })
}

resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = var.kms_key_arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket                  = aws_s3_bucket.evidence.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    id     = "expire"
    status = "Enabled"
    filter {
      prefix = ""
    }
    expiration {
      days = 365
    }
  }
}

# Bucket de artefatos Lambda
resource "aws_s3_bucket" "lambda_artifacts" {
  bucket = "${var.name_prefix}-lambda-artifacts"
  tags   = merge(var.tags, { Name = "${var.name_prefix}-lambda-artifacts" })
}

resource "aws_s3_bucket_versioning" "lambda_artifacts" {
  bucket = aws_s3_bucket.lambda_artifacts.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "lambda_artifacts" {
  bucket = aws_s3_bucket.lambda_artifacts.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "lambda_artifacts" {
  bucket                  = aws_s3_bucket.lambda_artifacts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Terraform state bucket
resource "aws_s3_bucket" "terraform_state" {
  bucket = "${var.name_prefix}-terraform-state"
  tags   = merge(var.tags, { Name = "${var.name_prefix}-terraform-state" })
}

resource "aws_s3_bucket_versioning" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "terraform_state" {
  bucket                  = aws_s3_bucket.terraform_state.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
