# Modulo Lambda — Agente Leve (Camada 1, conectores)

variable "name_prefix" {
  type = string
}

variable "function_name" {
  type = string
}

variable "runtime" {
  type    = string
  default = "python3.12"
}

variable "memory_size" {
  type    = number
  default = 512
}

variable "timeout" {
  type    = number
  default = 300
}

variable "vpc_id" {
  type    = string
  default = ""
}

variable "subnet_ids" {
  type    = list(string)
  default = []
}

variable "tags" {
  type    = map(string)
  default = {}
}

resource "aws_iam_role" "lambda" {
  name = "${var.name_prefix}-${var.function_name}-lambda-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "lambda_custom" {
  name = "${var.name_prefix}-${var.function_name}-custom-policy"
  role = aws_iam_role.lambda.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SecretsManagerReadOnly"
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Resource = "arn:aws:secretsmanager:*:*:secret:${var.name_prefix}/*"
      },
      {
        Sid    = "DynamoDBLimited"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
          "dynamodb:Query"
        ]
        Resource = "arn:aws:dynamodb:*:*:table/${var.name_prefix}-*"
      },
      {
        Sid    = "S3AuditWrite"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject"
        ]
        Resource = "arn:aws:s3:::${var.name_prefix}-audit-*/*"
      },
      {
        Sid    = "SQSSendReceive"
        Effect = "Allow"
        Action = [
          "sqs:SendMessage",
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes"
        ]
        Resource = "arn:aws:sqs:*:*:${var.name_prefix}-*"
      }
    ]
  })
}

resource "aws_lambda_function" "this" {
  function_name = "${var.name_prefix}-${var.function_name}"
  role          = aws_iam_role.lambda.arn
  runtime       = var.runtime
  handler       = "handler.lambda_handler"
  memory_size   = var.memory_size
  timeout       = var.timeout
  filename      = "dummy.zip"  # Atualizado via CI/CD
  source_code_hash = filebase64sha256("dummy.zip")
  
  vpc_config {
    subnet_ids         = var.subnet_ids
    security_group_ids = [aws_security_group.lambda.id]
  }

  environment {
    variables = {
      STAGE       = var.name_prefix
      LOG_LEVEL   = "INFO"
      REGION      = data.aws_region.current.name
    }
  }

  tracing_config {
    mode = "Active"
  }

  tags = var.tags
}

resource "aws_security_group" "lambda" {
  name        = "${var.name_prefix}-${var.function_name}-sg"
  description = "Security group para Lambda ${var.function_name}"
  vpc_id      = var.vpc_id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = var.tags
}

data "aws_region" "current" {}

output "function_arn" {
  value = aws_lambda_function.this.arn
}

output "function_name" {
  value = aws_lambda_function.this.function_name
}

output "role_arn" {
  value = aws_iam_role.lambda.arn
}
