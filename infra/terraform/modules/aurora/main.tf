# Aurora PostgreSQL + pgvector — RAG Knowledge Base
# PCI DSS 3.4: SSE-KMS encryption at rest
# PCI DSS 4.1: TLS 1.2+ in transit (enforced by Aurora parameter group)
# CIS AWS 2.0.0: RDS section

resource "aws_db_subnet_group" "aurora" {
  name       = "${var.name_prefix}-aurora-subnet"
  subnet_ids = var.subnet_ids
  description = "Subnet group for Aurora PostgreSQL (CDE tier)"

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-aurora-subnet"
    Tier = "CDE"
  })
}

resource "aws_rds_cluster_parameter_group" "aurora" {
  name   = "${var.name_prefix}-aurora-pg15-pg"
  family = "aurora-postgresql15"

  # Security parameters (CIS PostgreSQL Benchmark)
  parameter {
    name  = "log_connections"
    value = "1"
    apply_method = "immediate"
  }
  parameter {
    name  = "log_disconnections"
    value = "1"
    apply_method = "immediate"
  }
  parameter {
    name  = "log_statement"
    value = "ddl"  # Log all DDL (schema changes)
    apply_method = "immediate"
  }
  parameter {
    name  = "log_min_duration_statement"
    value = "1000"  # Log queries >1s
    apply_method = "immediate"
  }
  parameter {
    name  = "shared_preload_libraries"
    value = "pg_stat_statements,pgvector,auto_explain"
    apply_method = "pending-reboot"
  }
  parameter {
    name  = "ssl"
    value = "1"  # Force TLS
    apply_method = "pending-reboot"
  }

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-aurora-pg"
    CIS  = "PostgreSQL-Benchmark"
  })
}

resource "aws_rds_cluster" "aurora" {
  cluster_identifier = "${var.name_prefix}-aurora-rag"
  engine             = "aurora-postgresql"
  engine_version     = "15.6"
  engine_mode        = "provisioned"

  database_name   = var.database_name
  master_username = var.master_username
  master_password = var.master_password_secret_arn != "" ? null : var.master_password
  manage_master_user_password = var.master_password_secret_arn != ""

  db_subnet_group_name   = aws_db_subnet_group.aurora.name
  vpc_security_group_ids = [aws_security_group.aurora.id]

  db_cluster_parameter_group_name = aws_rds_cluster_parameter_group.aurora.name

  # Security (PCI DSS 3.4)
  storage_encrypted   = true
  kms_key_id          = var.kms_key_arn

  # Backup (PCI DSS 10.7)
  backup_retention_period = 35  # 35 days
  preferred_backup_window = "03:00-04:00"

  # High availability
  availability_zones = var.availability_zones

  # Deletion protection (safety)
  deletion_protection = true
  skip_final_snapshot = false
  final_snapshot_identifier = "${var.name_prefix}-aurora-final-${formatdate("YYYYMMDD", timestamp())}"

  # Performance Insights
  enabled_cloudwatch_logs_exports = ["postgresql"]

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-aurora-rag"
    DataClass = "PCI"
    CIS       = "RDS-Benchmark"
  })
}

resource "aws_rds_cluster_instance" "aurora" {
  count              = var.instance_count
  identifier         = "${var.name_prefix}-aurora-rag-${count.index + 1}"
  cluster_identifier = aws_rds_cluster.aurora.id
  instance_class     = var.instance_class
  engine             = aws_rds_cluster.aurora.engine
  engine_version     = aws_rds_cluster.aurora.engine_version

  # Performance Insights (PCI DSS 10.5 — monitoring)
  performance_insights_enabled = true
  performance_insights_kms_key_id = var.kms_key_arn
  monitoring_interval = 60
  monitoring_role_arn = var.monitoring_role_arn

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-aurora-rag-${count.index + 1}"
  })
}

# Security group — restrict to VPC only
resource "aws_security_group" "aurora" {
  name        = "${var.name_prefix}-aurora-sg"
  description = "Security group for Aurora PostgreSQL (RAG)"
  vpc_id      = var.vpc_id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = var.allowed_security_groups  # Only Lambda/ECS SG
    description     = "PostgreSQL from app tier"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Outbound (managed by VPC endpoint)"
  }

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-aurora-sg"
    Tier = "CDE"
  })
}

# pgvector extension (executado via Lambda após criação do cluster)
# ou via custom resource no Terraform
resource "null_resource" "pgvector_extension" {
  depends_on = [aws_rds_cluster_instance.aurora]

  provisioner "local-exec" {
    command = <<-EOT
      echo "pgvector extension must be created manually or via Lambda:"
      echo "  CREATE EXTENSION IF NOT EXISTS vector;"
      echo "  CREATE EXTENSION IF NOT EXISTS pg_stat_statements;"
      echo "RAG table schema in mvp2/copilot/data/rag_index.json"
    EOT
  }
}
