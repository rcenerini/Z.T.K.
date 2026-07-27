output "lambda_execution_role_arn" {
  description = "ARN da IAM Role para execucao Lambda"
  value       = aws_iam_role.lambda_execution.arn
}

output "ecs_execution_role_arn" {
  description = "ARN da IAM Role para execucao ECS"
  value       = aws_iam_role.ecs_execution.arn
}

output "ecs_task_role_arn" {
  description = "ARN da IAM Role para tasks ECS"
  value       = aws_iam_role.ecs_task.arn
}

output "bedrock_invoke_role_arn" {
  description = "ARN da IAM Role para invocacao Bedrock"
  value       = aws_iam_role.bedrock_invoke.arn
}

output "kms_key_arn" {
  description = "ARN da KMS Key principal"
  value       = aws_kms_key.main.arn
}

output "kms_key_id" {
  description = "ID da KMS Key principal"
  value       = aws_kms_key.main.key_id
}
