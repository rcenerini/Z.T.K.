variable "aws_region" {
  description = "Regiao AWS"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Ambiente (dev, staging, prod)"
  type        = string
  default     = "dev"
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Ambiente deve ser dev, staging ou prod."
  }
}

variable "vpc_cidr" {
  description = "CIDR da VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "availability_zones" {
  description = "AZs a usar"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b", "us-east-1c"]
}

variable "gpu_instance_type" {
  description = "Tipo de instancia GPU para vLLM"
  type        = string
  default     = "g5.xlarge"
}

variable "bedrock_models" {
  description = "Modelos Bedrock habilitados"
  type        = list(string)
  default = [
    "anthropic.claude-3-sonnet-20240229-v1:0",
    "anthropic.claude-3-haiku-20240307-v1:0"
  ]
}

variable "enable_pci_scope" {
  description = "Habilita recursos de escopo PCI (vLLM local, VPC isolada)"
  type        = bool
  default     = true
}

variable "cost_budget_usd" {
  description = "Budget mensal estimado em USD"
  type        = number
  default     = 5000
}
