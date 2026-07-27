variable "name_prefix" {
  description = "Prefixo para nomes de recursos"
  type        = string
}

variable "allowed_roles" {
  description = "IAM Roles autorizadas a invocar Bedrock"
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Tags comuns"
  type        = map(string)
  default     = {}
}
