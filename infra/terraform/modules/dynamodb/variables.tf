variable "name_prefix" {
  description = "Prefixo para nomes de recursos"
  type        = string
}

variable "kms_key_arn" {
  description = "ARN da KMS Key para criptografia (SSE-KMS)"
  type        = string
}

variable "tags" {
  description = "Tags comuns"
  type        = map(string)
  default     = {}
}
