output "vpc_id" {
  description = "ID da VPC"
  value       = aws_vpc.main.id
}

output "vpc_cidr" {
  description = "CIDR block da VPC"
  value       = aws_vpc.main.cidr_block
}

output "public_subnet_ids" {
  description = "IDs das subnets publicas (DMZ)"
  value       = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  description = "IDs das subnets privadas (aplicacao)"
  value       = aws_subnet.private[*].id
}

output "cde_subnet_ids" {
  description = "IDs das subnets CDE (isoladas)"
  value       = var.enable_cde ? aws_subnet.cde[*].id : []
}
