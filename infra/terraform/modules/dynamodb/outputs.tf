output "findings_table_name" {
  value = aws_dynamodb_table.findings.name
}

output "decisions_table_name" {
  value = aws_dynamodb_table.decisions.name
}

output "audit_events_table_name" {
  value = aws_dynamodb_table.audit_events.name
}

output "containment_rules_table_name" {
  value = aws_dynamodb_table.containment_rules.name
}

output "exceptions_table_name" {
  value = aws_dynamodb_table.exceptions.name
}
