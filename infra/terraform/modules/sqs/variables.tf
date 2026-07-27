variable "name_prefix" {
  description = "Prefixo para nomes de recursos"
  type        = string
}

variable "tags" {
  description = "Tags comuns"
  type        = map(string)
  default     = {}
}
