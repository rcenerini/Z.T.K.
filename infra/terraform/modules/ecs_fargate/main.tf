# Modulo ECS Fargate — Agente Medio (Camada 2, SAST wrappers)

variable "name_prefix" {
  type = string
}

variable "cluster_name" {
  type = string
}

variable "vpc_id" {
  type = string
}

variable "subnet_ids" {
  type = list(string)
}

variable "enable_spot" {
  type    = bool
  default = true
}

variable "tags" {
  type    = map(string)
  default = {}
}

resource "aws_ecs_cluster" "this" {
  name = "${var.name_prefix}-${var.cluster_name}"
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
  tags = var.tags
}

resource "aws_ecs_cluster_capacity_providers" "this" {
  cluster_name = aws_ecs_cluster.this.name
  capacity_providers = var.enable_spot ? ["FARGATE", "FARGATE_SPOT"] : ["FARGATE"]
  default_capacity_provider_strategy {
    base              = 1
    weight            = var.enable_spot ? 3 : 0
    capacity_provider = var.enable_spot ? "FARGATE_SPOT" : "FARGATE"
  }
}

resource "aws_security_group" "ecs_tasks" {
  name        = "${var.name_prefix}-${var.cluster_name}-tasks-sg"
  description = "Security group para tarefas ECS"
  vpc_id      = var.vpc_id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = var.tags
}

output "cluster_arn" {
  value = aws_ecs_cluster.this.arn
}

output "cluster_name" {
  value = aws_ecs_cluster.this.name
}

output "task_security_group_id" {
  value = aws_security_group.ecs_tasks.id
}
