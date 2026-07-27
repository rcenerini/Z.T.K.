output "queue_urls" {
  value = { for k, v in aws_sqs_queue.main : k => v.id }
}

output "dlq_urls" {
  value = { for k, v in aws_sqs_queue.dlq : k => v.id }
}
