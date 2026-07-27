output "audit_trail_bucket_name" {
  value = aws_s3_bucket.audit_trail.id
}

output "evidence_bucket_name" {
  value = aws_s3_bucket.evidence.id
}

output "lambda_artifacts_bucket_name" {
  value = aws_s3_bucket.lambda_artifacts.id
}

output "terraform_state_bucket_name" {
  value = aws_s3_bucket.terraform_state.id
}
