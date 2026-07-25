# Modulo Grafana Enterprise

variable "name_prefix" {
  type = string
}

variable "vpc_id" {
  type = string
}

variable "subnet_ids" {
  type = list(string)
}

variable "tags" {
  type    = map(string)
  default = {}
}

resource "aws_security_group" "grafana" {
  name        = "${var.name_prefix}-grafana-sg"
  description = "Security group para Grafana Enterprise"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    cidr_blocks = [data.aws_vpc.selected.cidr_block]
    description = "Grafana UI interna"
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Restrito via WAF/ALB em prod
    description = "HTTPS publico (restrito via ALB rules)"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = var.tags
}

data "aws_vpc" "selected" {
  id = var.vpc_id
}

# ECS Service para Grafana (alternativa mais barata que EKS para workload unico)
resource "aws_ecs_task_definition" "grafana" {
  family                   = "${var.name_prefix}-grafana"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "1024"
  memory                   = "2048"
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  container_definitions = jsonencode([
    {
      name  = "grafana"
      image = "grafana/grafana-enterprise:11.0.0"
      essential = true
      portMappings = [
        {
          containerPort = 3000
          protocol      = "tcp"
        }
      ]
      environment = [
        { name = "GF_SECURITY_ADMIN_USER", value = "admin" },
        { name = "GF_INSTALL_PLUGINS", value = "grafana-clock-panel,grafana-simple-json-datasource" }
      ]
      secrets = [
        {
          name      = "GF_SECURITY_ADMIN_PASSWORD"
          valueFrom = aws_secretsmanager_secret.grafana_admin.arn
        }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.grafana.name
          awslogs-region        = data.aws_region.current.name
          awslogs-stream-prefix = "grafana"
        }
      }
      mountPoints = []
      volumesFrom = []
    }
  ])

  tags = var.tags
}

resource "aws_ecs_service" "grafana" {
  name            = "${var.name_prefix}-grafana"
  cluster         = aws_ecs_cluster.grafana.id
  task_definition = aws_ecs_task_definition.grafana.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.subnet_ids
    security_groups  = [aws_security_group.grafana.id]
    assign_public_ip = true  # Em prod, usar ALB + private subnets
  }

  tags = var.tags
}

resource "aws_ecs_cluster" "grafana" {
  name = "${var.name_prefix}-grafana"
  tags = var.tags
}

resource "aws_cloudwatch_log_group" "grafana" {
  name              = "/ecs/${var.name_prefix}-grafana"
  retention_in_days = 30
  tags              = var.tags
}

resource "aws_iam_role" "ecs_execution" {
  name = "${var.name_prefix}-grafana-ecs-execution"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })
  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "ecs_execution" {
  role       = aws_iam_role.ecs_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role" "ecs_task" {
  name = "${var.name_prefix}-grafana-ecs-task"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })
  tags = var.tags
}

resource "aws_secretsmanager_secret" "grafana_admin" {
  name                    = "${var.name_prefix}-grafana-admin-password"
  description             = "Senha admin do Grafana Enterprise"
  kms_key_id              = aws_kms_key.grafana.arn
  recovery_window_in_days = 7
  tags                    = var.tags
}

resource "aws_kms_key" "grafana" {
  description             = "KMS para secrets Grafana"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  tags                    = var.tags
}

data "aws_region" "current" {}

output "endpoint" {
  value = "http://${aws_ecs_service.grafana.name}.${aws_ecs_cluster.grafana.name}.local:3000"
}

output "task_definition_arn" {
  value = aws_ecs_task_definition.grafana.arn
}
