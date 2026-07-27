# Observabilidade — Z.T.K. Grafana Dashboards

![Grafana](https://img.shields.io/badge/Grafana-Enterprise-ff6b35?logo=grafana)
![Metrics](https://img.shields.io/badge/metrics-4_panels-00d4ff)
![Status](https://img.shields.io/badge/status-active-00ff88)

> **Versão:** 1.0 | **Fase:** M10 | **Data:** 2026-07-27

---

## 1. Visão Geral

O dashboard de observabilidade do Z.T.K. fornece visibilidade completa sobre
o pipeline multiagente em 4 dimensões:

| Painel | Métricas | Público |
|--------|----------|---------|
| **01 — Operations** | Pipeline health, throughput, latency, queues | Engenharia, SRE |
| **02 — Security** | Findings por severity, SAST agents, prompt guard, top CWE | SOC, AppSec |
| **03 — Cost & LLM** | Bedrock cost, token usage, circuit breaker | FinOps, Arquitetura |
| **04 — Compliance** | PCI DSS coverage, exceptions, audit timeline | Compliance, DPO |

---

## 2. Métricas Chave

### Operations

| Métrica | Fonte | Threshold |
|---------|-------|-----------|
| `findings_processed_24h` | DynamoDB count | — |
| `pipeline_success_rate` | Lambda Error / Invocation | >99% |
| `avg_processing_time_ms` | X-Ray traces | <3s |
| `hitl_queue_depth` | SQS ApproximateNumberOfMessages | <10 |

### Security

| Métrica | Fonte | Alert |
|---------|-------|-------|
| `findings_by_severity` | DynamoDB GSI | P0 > 0 = alert |
| `prompt_guard_blocks` | CloudWatch custom metric | >10/min = alert |
| `containment_rules_active` | DynamoDB count | >50 = warning |
| `kill_switch_status` | API endpoint | Active = critical |

### Cost

| Métrica | Fonte | Threshold |
|---------|-------|-----------|
| `bedrock_monthly_cost_usd` | Bedrock cost explorer | >$1,200 (80%) = warning |
| `sonnet_escalation_rate` | Copilot metrics | >25% = warning |
| `circuit_breaker_status` | Cost monitor | 100% = block |
| `tokens_per_finding` | LLM request logs | >50K = warning |

### Compliance

| Métrica | Fonte | PCI DSS |
|---------|-------|---------|
| `pci_dss_coverage_pct` | Manual tracking | Req. 12 |
| `active_exceptions` | API endpoint | — |
| `audit_events_24h` | S3 count | Req. 10 |
| `retention_policy_enforced` | S3 lifecycle | Req. 10.7 |

---

## 3. Integração

### CloudWatch Metrics

```python
# Emitir métricas customizadas
import boto3
cw = boto3.client('cloudwatch')
cw.put_metric_data(
    Namespace='ZTK/Copilot',
    MetricData=[{
        'MetricName': 'AnalysisTime',
        'Value': 1500,
        'Unit': 'Milliseconds',
        'Dimensions': [{'Name': 'Model', 'Value': 'haiku'}]
    }]
)
```

### Grafana Data Source

```
URL: https://grafana.ztk.internal
Data Sources:
  - CloudWatch (ZTK namespace)
  - DynamoDB (via Timestream)
  - S3 (audit logs via Athena)
```

---

## 4. Alertas Configurados

| Alerta | Condição | Canal | Severidade |
|--------|----------|-------|-----------|
| Pipeline Error Rate >5% | 5 min sustained | Slack #ztk-alerts | HIGH |
| Kill Switch Activated | Instant | Slack + PagerDuty | CRITICAL |
| Bedrock Cost >$1,200/mo | Daily check | Email FinOps | MEDIUM |
| HITL Queue >20 items | 15 min sustained | Slack #ztk-hitl | HIGH |
| Audit Event Gap >1h | Hourly check | Slack #ztk-alerts | CRITICAL |
