output "vpc_id" {
  description = "ID da VPC"
  value       = module.vpc.vpc_id
}

output "dynamodb_tables" {
  description = "Nomes das tabelas DynamoDB"
  value       = module.dynamodb.table_names
}

output "s3_audit_bucket" {
  description = "Bucket S3 para audit trail"
  value       = module.s3.audit_bucket
}

output "sqs_queues" {
  description = "URLs das filas SQS"
  value       = module.sqs.queue_urls
}

output "ecs_cluster_arn" {
  description = "ARN do cluster ECS"
  value       = module.ecs_agents.cluster_arn
}

output "ec2_gpu_instance_id" {
  description = "ID da instancia GPU (vLLM)"
  value       = module.ec2_gpu.instance_id
}

output "grafana_endpoint" {
  description = "Endpoint do Grafana Enterprise"
  value       = module.grafana.endpoint
}

output "bedrock_invoke_role" {
  description = "Role IAM para invocar Bedrock"
  value       = module.iam.bedrock_invoke_role_arn
}
