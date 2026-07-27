variable "name_prefix" {
  type = string
}
variable "allowed_roles" {
  type    = list(string)
  default = []
}
variable "kms_key_arn" {
  type    = string
  default = ""
}
variable "bedrock_monthly_budget_usd" {
  type    = number
  default = 1500
}
variable "budget_alert_emails" {
  type    = list(string)
  default = []
}
variable "tags" {
  type    = map(string)
  default = {}
}
