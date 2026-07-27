# Infraestrutura Z.T.K. — Documentação Técnica

> **Versão:** 1.0 | **Fase:** F0.2 | **Terraform:** 1.7+ | **Provider AWS:** 5.35+

---

## 1. Visão Geral

A infraestrutura Z.T.K. é provisionada como código (IaC) via Terraform, seguindo
princípios **Zero Trust** e **PCI DSS 4.0**. Todos os recursos são criados em VPC
privada com segmentação CDE, criptografia SSE-KMS e least privilege IAM.

---

## 2. Arquitetura de Rede (VPC)

```
┌──────────────────────────────────────────────────────────┐
│ VPC (10.0.0.0/16)                                        │
│                                                          │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐ │
│  │ DMZ (public) │  │ APP (private)│  │ CDE (isolated)   │ │
│  │ 10.0.1.0/24  │  │ 10.0.10.0/24 │  │ 10.0.100.0/24   │ │
│  │ 10.0.2.0/24  │  │ 10.0.11.0/24 │  │ 10.0.101.0/24   │ │
│  └──────┬──────┘  └──────┬───────┘  └────────┬─────────┘ │
│         │                │                    │          │
│    Internet GW      NAT Gateway          Sem internet   │
│         │                │              VPC Endpoints    │
│         │           ┌────┴────┐       (DynamoDB, S3,    │
│         │           │ Lambda  │        SQS, Bedrock,     │
│         │           │ ECS     │        KMS)              │
│         │           │ EC2 GPU │                          │
│         │           └─────────┘                          │
└──────────────────────────────────────────────────────────┘
```

**Segmentação PCI DSS:**
- CDE: subnet isolada, sem rota para internet, apenas VPC endpoints
- APP: subnets privadas com NAT Gateway para atualizações de segurança
- DMZ: apenas para load balancers e WAF

---

## 3. Módulos

| Módulo | Recursos | PCI DSS |
|--------|----------|---------|
| `vpc` | VPC, 6 subnets, IGW, NAT GW, VPC endpoints, NACLs, Flow Logs | Req. 1, 10 |
| `dynamodb` | 5 tabelas + 1 lock table, SSE-KMS, PITR, GSI | Req. 3.4, 10 |
| `s3` | 4 buckets (audit, evidence, artifacts, state), versioning, lifecycle | Req. 3.4, 10.7 |
| `sqs` | 6 filas + 6 DLQs, criptografia, DLQ redrive | Req. 3.4 |
| `iam` | 4 roles + KMS key, least privilege policies | Req. 7 |
| `lambda` | Função Lambda com VPC, security group, IAM role | — |
| `ecs_fargate` | Cluster ECS Fargate Spot para agentes SAST | — |
| `ec2_gpu` | Instância GPU (g5.xlarge) para vLLM local | — |
| `bedrock` | Guardrail de conteúdo para saídas Claude | — |
| `grafana` | Grafana Enterprise em ECS Fargate | — |

---

## 4. Tabelas DynamoDB

| Tabela | PK | GSI | PITR | TTL |
|--------|-----|-----|------|-----|
| `findings` | finding_id + tenant_id | status, tenant | ✅ | ✅ |
| `decisions` | finding_id + decision_id | tier | ✅ | ✅ |
| `audit_events` | event_id | finding_id | ✅ | — |
| `containment_rules` | rule_id | finding_id, status | ✅ | ✅ |
| `exceptions` | exception_id | finding_id | ✅ | ✅ |

---

## 5. Filas SQS

| Fila | Visibilidade | Retenção | DLQ Redrive |
|------|-------------|----------|-------------|
| `ingestion` | 300s | 14 dias | 3 retentativas |
| `normalization` | 300s | 14 dias | 3 retentativas |
| `decision` | 120s | 4 dias | 3 retentativas |
| `copilot` | 600s | 4 dias | 2 retentativas |
| `hitl` | 3600s | 14 dias | 2 retentativas |
| `remediation` | 900s | 4 dias | 3 retentativas |

---

## 6. Buckets S3

| Bucket | Criptografia | Versioning | Lifecycle |
|--------|------------|------------|-----------|
| `audit-trail` | SSE-KMS | ✅ | 90d STANDARD → 1825d (5 anos) GLACIER |
| `evidence` | SSE-KMS | ✅ | 365d → expira |
| `lambda-artifacts` | AES256 | ✅ | — |
| `terraform-state` | AES256 | ✅ | — |

---

## 7. IAM Roles (Least Privilege)

| Role | Serviço | Permissões |
|------|---------|-----------|
| `lambda-execution` | Lambda | DynamoDB R/W, SQS send/receive, S3 R/W, KMS decrypt |
| `ecs-execution` | ECS | ECR pull, CloudWatch logs |
| `ecs-task` | ECS | S3 evidence R/W, DynamoDB findings R/W |
| `bedrock-invoke` | Bedrock | InvokeModel |

---

## 8. Deploy

```bash
# Inicializar (primeira vez)
cd infra/terraform
terraform init

# Planejar
terraform plan -var-file="environment/dev/terraform.tfvars" -out=tfplan

# Aplicar
terraform apply tfplan

# Validar
terraform validate

# Destruir (apenas dev!)
terraform destroy -var-file="environment/dev/terraform.tfvars"
```

---

## 9. Compliance

| Requisito PCI DSS | Controle |
|-------------------|----------|
| 1.1 — Firewall | NACLs + Security Groups |
| 1.3 — CDE isolado | Subnet CDE sem internet |
| 3.4 — PAN ilegível | SSE-KMS em DynamoDB e S3 |
| 7.1 — Least privilege | IAM roles com mínimo escopo |
| 10.2 — Logs automatizados | VPC Flow Logs, S3 audit trail |
| 10.7 — Retenção 1 ano | S3 lifecycle 5 anos |
