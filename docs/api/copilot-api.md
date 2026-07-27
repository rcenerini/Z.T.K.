# API do Módulo Copilot — MVP2 (M4)

> **Versão:** 1.0 | **Módulo:** `mvp2/copilot/` | **Protocolo:** AWS Lambda (SQS trigger)

---

## 1. Visão Geral

O Copilot é um consumidor SQS que processa `DecisionRecord` do Decision Engine (MVP1) para achados tier ATTEND. Análise via Claude 3.5 (Bedrock) com contexto RAG.

---

## 2. Entrada: CopilotRequest

### SQS Message Body

```json
{
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "finding": {
    "finding_id": "660e8400-e29b-41d4-a716-446655440001",
    "tenant_id": "cielo-ztk",
    "source": "Semgrep",
    "severity": "P1",
    "cwe_ids": ["CWE-89"],
    "file_path": "src/api/auth.py",
    "line_number": 142,
    "description": "SQL injection via unsanitized user input in login query",
    "evidence": "cursor.execute(f\"SELECT * FROM users WHERE email='{email}'\")",
    "decision_tier": "ATTEND",
    "score": 7.5,
    "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    "language": "python",
    "related_findings": [],
    "metadata": {}
  },
  "force_model": null,
  "shadow_mode": true,
  "timestamp": "2026-07-27T14:30:00Z"
}
```

### Campos

| Campo | Tipo | Obrigatório | Descrição |
|-------|------|------------|-----------|
| `request_id` | UUID | Sim | ID da requisição (auto-gerado se ausente) |
| `finding.finding_id` | UUID | Sim | ID do achado original |
| `finding.tenant_id` | string | Sim | Identificador do tenant |
| `finding.source` | string | Sim | Ferramenta de origem (Semgrep, Tenable, etc.) |
| `finding.severity` | P0-P4 | Sim | Severidade normalizada |
| `finding.cwe_ids` | string[] | Sim | Lista de CWE IDs (min 1) |
| `finding.description` | string | Sim | Descrição (min 10 chars) |
| `finding.evidence` | string | Sim | Evidência bruta |
| `finding.decision_tier` | string | Sim | Deve ser "ATTEND" para este módulo |
| `finding.score` | float | Sim | Score 0-10 do Decision Engine |
| `force_model` | string \| null | Não | Override do modelo (debug) |
| `shadow_mode` | bool | Sim | Se true, análise é read-only |

---

## 3. Saída: CopilotResponse

### Sucesso

```json
{
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "finding_id": "660e8400-e29b-41d4-a716-446655440001",
  "analysis": {
    "analysis_id": "770e8400-e29b-41d4-a716-446655440002",
    "finding_id": "660e8400-e29b-41d4-a716-446655440001",
    "tier_requested": "ATTEND",
    "tier_actual": "ATTEND",
    "model_used": "anthropic.claude-3-5-haiku-20241022-v1:0",
    "confidence": "HIGH",
    "summary": "SQL injection confirmed with clear evidence in authentication endpoint",
    "recommendation": "Replace f-string with parameterized query. Add email format validation.",
    "ambiguity_signals": [],
    "rag_hits": 1,
    "rag_relevant": 1,
    "prompt_version": "1.0.0",
    "processing_time_ms": 1500,
    "timestamp": "2026-07-27T14:30:01Z",
    "escalation_required": false
  },
  "error": null,
  "shadow_mode": true,
  "escalation_triggered": false,
  "processing_time_ms": 1500,
  "timestamp": "2026-07-27T14:30:01Z"
}
```

### Erro (Bedrock indisponível)

```json
{
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "finding_id": "660e8400-e29b-41d4-a716-446655440001",
  "analysis": null,
  "error": "Bedrock client unavailable. Set COPILOT_BEDROCK_REGION and ensure AWS credentials are configured.",
  "shadow_mode": true,
  "escalation_triggered": false,
  "processing_time_ms": 500,
  "timestamp": "2026-07-27T14:30:01Z"
}
```

---

## 4. Variáveis de Ambiente

| Variável | Obrigatória | Default | Descrição |
|----------|------------|---------|-----------|
| `COPILOT_BEDROCK_REGION` | Sim | `us-east-1` | Região AWS do Bedrock |
| `COPILOT_BEDROCK_HAIKU_MODEL` | Não | `anthropic.claude-3-5-haiku-20241022-v1:0` | Modelo para rotina |
| `COPILOT_BEDROCK_SONNET_MODEL` | Não | `anthropic.claude-3-5-sonnet-20241022-v2:0` | Modelo para escalação |
| `COPILOT_BEDROCK_MAX_TOKENS` | Não | `4096` | Tokens máximos |
| `COPILOT_BEDROCK_TEMPERATURE` | Não | `0.1` | Temperatura (0-1) |
| `COPILOT_BEDROCK_TIMEOUT_SECONDS` | Não | `60` | Timeout da API |
| `COPILOT_RAG_INDEX_PATH` | Não | `mvp2/copilot/data/rag_index.json` | Caminho do índice RAG |
| `COPILOT_RAG_MAX_DOCS` | Não | `5` | Máximo de documentos RAG |
| `COPILOT_AMBIGUITY_ESCALATION_THRESHOLD` | Não | `2` | Sinais para escalar ao Sonnet |
| `COPILOT_LOG_LEVEL` | Não | `INFO` | Nível de log |
| `COPILOT_SHADOW_MODE_DEFAULT` | Não | `true` | Shadow mode padrão |

---

## 5. Fluxo de Processamento

```
SQS Message → Lambda Handler
  ├── 1. Validate CopilotRequest (Pydantic)
  ├── 2. RAG Retrieval (CWE matching, Jaccard similarity)
  ├── 3. Build Prompt (fixed context + RAG + finding)
  ├── 4. Call Claude Haiku (Bedrock)
  ├── 5. Parse AmbiguitySignals from LLM response
  ├── 6. [if signals >= threshold] → Call Claude Sonnet
  ├── 7. Build CopilotAnalysis
  └── 8. Return CopilotResponse
```

---

## 6. Escalação Haiku → Sonnet

Quando Haiku retorna `ambiguity_signals >= COPILOT_AMBIGUITY_ESCALATION_THRESHOLD`:

1. Contexto RAG + finding é reenviado para Claude Sonnet
2. Prompt inclui nota de escalação e solicita análise mais profunda
3. Se Sonnet também não consegue resolver → `escalation_required = true`
4. Métricas registradas: `sonnet_escalations` incrementado

---

## 7. Métricas (CloudWatch)

| Métrica | Descrição |
|---------|-----------|
| `copilot.total_analyses` | Total de análises realizadas |
| `copilot.haiku_analyses` | Análises com Haiku |
| `copilot.sonnet_escalations` | Escalações para Sonnet |
| `copilot.rag_hits_total` | Total de documentos RAG recuperados |
| `copilot.ambiguity_signals_total` | Total de sinais de ambiguidade |
| `copilot.errors` | Total de erros |
| `copilot.avg_processing_time_ms` | Tempo médio de processamento |
| `copilot.escalation_rate` | Taxa de escalação (Sonnet/Total) |

---

## 8. Limitações Conhecidas

| Limitação | Impacto | Plano |
|-----------|---------|-------|
| RAG via JSON local | Baixa precisão semântica | Migrar para Aurora pgvector |
| Bedrock não configurado | Handler retorna erro | Aguardando time de plataforma |
| Sem cache de prompts | Maior latência e custo | Prompt caching Anthropic no futuro |
| Single-tenant | Sem isolamento de dados entre tenants | v2: tenant_id no DynamoDB partition key |
