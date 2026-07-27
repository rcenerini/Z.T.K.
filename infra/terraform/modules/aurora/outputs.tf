output "cluster_endpoint" { value = aws_rds_cluster.aurora.endpoint }
output "cluster_reader_endpoint" { value = aws_rds_cluster.aurora.reader_endpoint }
output "cluster_port" { value = aws_rds_cluster.aurora.port }
output "cluster_arn" { value = aws_rds_cluster.aurora.arn }
output "security_group_id" { value = aws_security_group.aurora.id }
