variable "name_prefix" {
  description = "Prefixo para nomes de recursos"
  type        = string
}

variable "aws_region" {
  description = "Regiao AWS"
  type        = string
  default     = "us-east-1"
}

variable "tags" {
  description = "Tags comuns"
  type        = map(string)
  default     = {}
}
