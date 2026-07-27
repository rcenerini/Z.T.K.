# Runbook: Deploy em Produção

> **Versão:** 1.0 | **Data:** 2026-07-27 | **Ambiente:** AWS Production (`cielo-ztk-prod`)

---

## 1. Pré-requisitos

- [ ] Acesso à conta AWS `cielo-ztk-prod` (IAM role `ZTKDeployRole`)
- [ ] Terraform 1.7+ instalado
- [ ] AWS CLI configurado (`aws sso login --profile cielo-ztk-prod`)
- [ ] Aprovação CAB para deploy em produção
- [ ] Todos os quality gates passando no commit de release:
  - `make test` — 100% pass
  - `make typecheck` — mypy strict zero erros
  - `make security-sast` — bandit zero HIGH/CRITICAL
  - `make security-secrets` — trufflehog zero leaks
  - `make security-iac` — checkov zero HIGH

---

## 2. Pipeline de Deploy

### Passo 1: Validar Release (5 min)

```bash
# 1. Verificar tag de release
git tag -l "v*" --sort=-version:refname | head -1
# Deve ser algo como v0.1.0

# 2. Verificar changelog
git log $(git describe --tags --abbrev=0)..HEAD --oneline

# 3. Rodar quality gates completos
make quality-gates
```

### Passo 2: Terraform Plan (10 min)

```bash
cd infra/terraform

# Inicializar (se necessário)
terraform init -backend-config="environment/prod/backend.tfvars"

# Planejar
terraform plan \
  -var-file="environment/prod/terraform.tfvars" \
  -out=prod.tfplan

# Revisar plano manualmente
terraform show prod.tfplan | less
```

### Passo 3: Aprovação Humana (GATE)

- [ ] Revisar `terraform plan` — confirmar resources que serão criados/modificados/destruídos
- [ ] Validar que não há destruição de recursos críticos (DynamoDB, S3, KMS)
- [ ] Aprovador: Tech Lead ou Arquiteto

### Passo 4: Aplicar (15 min)

```bash
terraform apply prod.tfplan
```

### Passo 5: Health Check (5 min)

```bash
# 1. Lambda: invocar função de health check
aws lambda invoke \
  --function-name ztk-copilot-prod \
  --payload '{"health_check": true}' \
  /tmp/response.json

# 2. Verificar resposta
cat /tmp/response.json | jq '.statusCode'
# Deve ser 200

# 3. Verificar métricas CloudWatch
aws cloudwatch get-metric-statistics \
  --namespace ZTK/Copilot \
  --metric-name Errors \
  --start-time $(date -u -d '5 minutes ago' +%Y-%m-%dT%H:%M:%SZ) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%SZ) \
  --period 60 \
  --statistics Sum

# 4. Verificar dashboard Grafana
open https://grafana.cielo.internal/d/ztk-producao
```

### Passo 6: Smoke Test (10 min)

```bash
# Enviar um CopilotRequest de teste para a fila SQS
aws sqs send-message \
  --queue-url https://sqs.us-east-1.amazonaws.com/123456789/ztk-copilot-queue-prod \
  --message-body '{
    "finding": {
      "finding_id": "00000000-0000-0000-0000-000000000001",
      "tenant_id": "smoke-test",
      "source": "Semgrep",
      "severity": "P3",
      "cwe_ids": ["CWE-327"],
      "file_path": "test/smoke.py",
      "line_number": 1,
      "description": "Smoke test finding for deploy validation",
      "evidence": "hashlib.md5(b\"test\")",
      "decision_tier": "ATTEND",
      "score": 3.0
    },
    "shadow_mode": true
  }'

# Aguardar 30 segundos e verificar logs
aws logs tail /aws/lambda/ztk-copilot-prod --since 1m
```

---

## 3. Rollback

### Gatilhos de Rollback

| Gatilho | Ação |
|---------|------|
| Health check falha | Rollback imediato |
| Error rate > 5% nos primeiros 15 min | Rollback imediato |
| Latência > 10s por análise | Investigar, rollback se necessário |
| Custo > 2x baseline | Rollback de L7, manter L1-L6 |

### Procedimento

```bash
# 1. Reverter para a tag anterior
git checkout $(git describe --tags --abbrev=0 --exclude="v$(cat VERSION)")

# 2. Terraform apply da versão anterior
cd infra/terraform
terraform apply previous.tfplan

# 3. Verificar health check
make health-check

# 4. Notificar canal de incidente
# Slack: #incident-ztk-prod
```

---

## 4. Checklist de Deploy

- [ ] CAB approval documentado
- [ ] Terraform plan revisado por 2 pessoas
- [ ] Backup de dados críticos (DynamoDB PITR habilitado)
- [ ] Rollback testado em staging
- [ ] Health check automatizado configurado
- [ ] Alertas CloudWatch configurados
- [ ] Canal de incidente (#incident-ztk-prod) notificado
- [ ] Smoke test passou
- [ ] Métricas estáveis por 30 minutos

---

## 5. Contatos de Emergência

| Papel | Contato | Quando acionar |
|-------|---------|---------------|
| Tech Lead ZTK | [definir] | Deploy falhou ou rollback necessário |
| SOC | [definir] | Kill switch ou incidente de segurança |
| CISO | [definir] | Violação PCI ou vazamento de dados |
| Infra AWS | [definir] | Problemas com Bedrock, Lambda, VPC |
