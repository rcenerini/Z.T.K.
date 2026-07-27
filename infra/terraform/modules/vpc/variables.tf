variable "name_prefix" {
  description = "Prefixo para nomes de recursos"
  type        = string
}

variable "vpc_cidr" {
  description = "CIDR block da VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "CIDRs das subnets publicas (DMZ)"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "private_subnet_cidrs" {
  description = "CIDRs das subnets privadas (aplicacao)"
  type        = list(string)
  default     = ["10.0.10.0/24", "10.0.11.0/24"]
}

variable "cde_subnet_cidrs" {
  description = "CIDRs das subnets CDE (isoladas)"
  type        = list(string)
  default     = ["10.0.100.0/24", "10.0.101.0/24"]
}

variable "availability_zones" {
  description = "AZs para alta disponibilidade"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b"]
}

variable "aws_region" {
  description = "Regiao AWS"
  type        = string
  default     = "us-east-1"
}

variable "enable_cde" {
  description = "Habilita subnet CDE isolada (PCI DSS)"
  type        = bool
  default     = true
}

variable "enable_flow_logs" {
  description = "Habilita VPC Flow Logs para auditoria"
  type        = bool
  default     = false
}

variable "flow_logs_iam_role_arn" {
  description = "IAM Role para VPC Flow Logs"
  type        = string
  default     = ""
}

variable "flow_logs_bucket_arn" {
  description = "S3 Bucket ARN para VPC Flow Logs"
  type        = string
  default     = ""
}

variable "tags" {
  description = "Tags comuns para todos os recursos"
  type        = map(string)
  default     = {}
}
