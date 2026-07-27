variable "name_prefix" {
  type = string
}
variable "kms_key_arn" {
  type = string
}
variable "vpc_id" {
  type = string
}
variable "subnet_ids" {
  type = list(string)
}
variable "availability_zones" {
  type = list(string)
}
variable "allowed_security_groups" {
  type    = list(string)
  default = []
}
variable "database_name" {
  type    = string
  default = "ztk_rag"
}
variable "master_username" {
  type    = string
  default = "ztk_admin"
}
variable "master_password" {
  type      = string
  default   = ""
  sensitive = true
}
variable "master_password_secret_arn" {
  type    = string
  default = ""
}
variable "instance_class" {
  type    = string
  default = "db.r6g.large"
}
variable "instance_count" {
  type    = number
  default = 2
}
variable "monitoring_role_arn" {
  type    = string
  default = ""
}
variable "tags" {
  type    = map(string)
  default = {}
}
