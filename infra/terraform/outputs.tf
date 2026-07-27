output "vpc_id" {
  description = "ID da VPC"
  value       = module.vpc.vpc_id
}

output "dynamodb_tables" {
  description = "Tabelas DynamoDB provisionadas"
  value = {
    findings          = module.dynamodb.findings_table_name
    decisions         = module.dynamodb.decisions_table_name
    audit_events      = module.dynamodb.audit_events_table_name
    containment_rules = module.dynamodb.containment_rules_table_name
    exceptions        = module.dynamodb.exceptions_table_name
  }
}

output "s3_buckets" {
  description = "Buckets S3 provisionados"
  value = {
    audit_trail      = module.s3.audit_trail_bucket_name
    evidence         = module.s3.evidence_bucket_name
    lambda_artifacts = module.s3.lambda_artifacts_bucket_name
    terraform_state  = module.s3.terraform_state_bucket_name
  }
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
