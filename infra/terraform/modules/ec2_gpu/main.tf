# Modulo EC2 GPU — vLLM Local (Camada 7, escopo PCI)

variable "name_prefix" {
  type = string
}

variable "instance_type" {
  type    = string
  default = "g5.xlarge"
}

variable "vpc_id" {
  type = string
}

variable "subnet_ids" {
  type = list(string)
}

variable "use_spot" {
  type    = bool
  default = true
}

variable "tags" {
  type    = map(string)
  default = {}
}

locals {
  ami = data.aws_ami.amazon_linux_gpu.id
}

data "aws_ami" "amazon_linux_gpu" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "aws_iam_role" "ec2_gpu" {
  name = "${var.name_prefix}-ec2-gpu-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.ec2_gpu.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "ec2_gpu" {
  name = "${var.name_prefix}-ec2-gpu-profile"
  role = aws_iam_role.ec2_gpu.name
}

resource "aws_security_group" "ec2_gpu" {
  name        = "${var.name_prefix}-ec2-gpu-sg"
  description = "Security group para instancia GPU (vLLM). Nenhum ingresso publico."
  vpc_id      = var.vpc_id

  # Apenas acesso interno via VPC (por ALB/NLB interno ou peering)
  ingress {
    from_port   = 8000
    to_port     = 8000
    protocol    = "tcp"
    cidr_blocks = [data.aws_vpc.selected.cidr_block]
    description = "vLLM API interna apenas"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Egress para pull de modelos (restrito via NACL em prod)"
  }

  tags = merge(var.tags, { DataScope = "PCI" })
}

data "aws_vpc" "selected" {
  id = var.vpc_id
}

resource "aws_instance" "gpu" {
  ami                    = local.ami
  instance_type          = var.instance_type
  iam_instance_profile   = aws_iam_instance_profile.ec2_gpu.name
  subnet_id              = var.subnet_ids[0]
  vpc_security_group_ids = [aws_security_group.ec2_gpu.id]

  user_data = base64encode(templatefile("${path.module}/user_data.sh", {
    model_name = "meta-llama/Llama-3.3-70B-Instruct"
    api_key    = "" # Placeholder — substituir via Secrets Manager no bootstrap
  }))

  root_block_device {
    volume_size           = 100
    volume_type           = "gp3"
    encrypted             = true
    kms_key_id            = aws_kms_key.ec2.arn
    delete_on_termination = true
  }

  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    http_endpoint               = "enabled"
  }

  monitoring = true

  instance_market_options {
    market_type = var.use_spot ? "spot" : "on-demand"
    spot_options {
      max_price                      = null # Preco sob demanda
      spot_instance_type             = "one-time"
      instance_interruption_behavior = "terminate"
    }
  }

  tags = merge(var.tags, {
    Name       = "${var.name_prefix}-vllm-gpu"
    DataScope  = "PCI"
    CostCenter = "security-ml"
  })
}

resource "aws_kms_key" "ec2" {
  description             = "KMS key para volumes EC2 GPU (PCI escopo)"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  tags                    = var.tags
}

resource "aws_kms_alias" "ec2" {
  name          = "alias/${var.name_prefix}-ec2-gpu"
  target_key_id = aws_kms_key.ec2.key_id
}

output "instance_id" {
  value = aws_instance.gpu.id
}

output "private_ip" {
  value = aws_instance.gpu.private_ip
}

output "vllm_endpoint" {
  value = "http://${aws_instance.gpu.private_ip}:8000"
}
