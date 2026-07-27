terraform {
  required_version = ">= 1.7.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.35"
    }
  }
  backend "s3" {
    bucket         = "ztk-terraform-state"
    key            = "ztk/main.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "ztk-terraform-locks"
  }
}

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      Project     = "ZTK"
      Environment = var.environment
      ManagedBy   = "Terraform"
      Compliance  = "PCI-DSS-4.0"
    }
  }
}

locals {
  name_prefix = "ztk-${var.environment}"
  common_tags = {
    Project     = "ZTK"
    Environment = var.environment
  }
}

# VPC Base (se nao existir VPC compartilhada)
module "vpc" {
  source             = "./modules/vpc"
  name_prefix        = local.name_prefix
  vpc_cidr           = var.vpc_cidr
  availability_zones = var.availability_zones
  tags               = local.common_tags
}

# DynamoDB — Tabelas principais
module "dynamodb" {
  source      = "./modules/dynamodb"
  name_prefix = local.name_prefix
  kms_key_arn = module.iam.kms_key_arn
  tags        = local.common_tags
}

# S3 — Data lake de auditoria + snapshots
module "s3" {
  source      = "./modules/s3"
  name_prefix = local.name_prefix
  kms_key_arn = module.iam.kms_key_arn
  tags        = local.common_tags
}

# SQS — Filas por conector + DLQ
module "sqs" {
  source      = "./modules/sqs"
  name_prefix = local.name_prefix
  tags        = local.common_tags
}

# Lambda — Camada 1 (Ingestao/Triagem) + conectores leves
module "lambda_ingest" {
  source        = "./modules/lambda"
  name_prefix   = local.name_prefix
  function_name = "ingest"
  runtime       = "python3.12"
  memory_size   = 512
  timeout       = 300
  vpc_id        = module.vpc.vpc_id
  subnet_ids    = module.vpc.private_subnet_ids
  tags          = local.common_tags
}

# ECS Fargate — Camada 2/3 (SAST, PoC efemero)
module "ecs_agents" {
  source       = "./modules/ecs_fargate"
  name_prefix  = local.name_prefix
  cluster_name = "agents"
  vpc_id       = module.vpc.vpc_id
  subnet_ids   = module.vpc.private_subnet_ids
  enable_spot  = true
  tags         = local.common_tags
}

# EC2 GPU — vLLM local (Camada 7, escopo PCI)
module "ec2_gpu" {
  source        = "./modules/ec2_gpu"
  name_prefix   = local.name_prefix
  instance_type = var.gpu_instance_type # g5.xlarge spot
  vpc_id        = module.vpc.vpc_id
  subnet_ids    = module.vpc.private_subnet_ids
  use_spot      = true
  tags          = merge(local.common_tags, { DataScope = "PCI" })
}

# IAM — Roles base (least privilege)
module "iam" {
  source      = "./modules/iam"
  name_prefix = local.name_prefix
  tags        = local.common_tags
}

# Grafana — Dashboard Enterprise
module "grafana" {
  source      = "./modules/grafana"
  name_prefix = local.name_prefix
  vpc_id      = module.vpc.vpc_id
  subnet_ids  = module.vpc.private_subnet_ids
  tags        = local.common_tags
}

# Aurora PostgreSQL + pgvector — RAG Knowledge Base (CDE, PCI DSS)
module "aurora_rag" {
  source                    = "./modules/aurora"
  name_prefix               = local.name_prefix
  kms_key_arn               = module.iam.kms_key_arn
  vpc_id                    = module.vpc.vpc_id
  subnet_ids                = module.vpc.cde_subnet_ids
  availability_zones        = var.availability_zones
  allowed_security_groups   = []
  tags                      = local.common_tags
}
