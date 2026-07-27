# Z.T.K. — Zero Trust Kill

> Sistema multiagente deterministico de analise e autocorrecao de seguranca de codigo
> para ambiente de adquirência / PCI DSS 4.0

---

## Visao Geral

O **Z.T.K.** (Zero Trust Kill) e um sistema multiagente que automatiza o ciclo completo
de deteccao, triagem, validacao, priorizacao e remediacao de vulnerabilidades em codigo,
infraestrutura e dependencias. Opera em ambiente de adquirência com requisitos rigorosos de
**PCI DSS 4.0**, **LGPD** e resolucoes do **Bacen**.

### Merge MVP1 + MVP2

Este repositorio unifica dois projetos:

| Componente | Descricao | Status |
|-----------|-----------|--------|
| **MVP1** (SAGA-SAGV_V2) | Pipeline SSVC de priorizacao: ingestion, normalization, enrichment, decision engine | 37/42 tarefas (88%) |
| **MVP2** (Z.T.K.) | Modulo M4: Copiloto LLM para analise de achados tier ATTEND | Em desenvolvimento |

### Principio Central

> **"Sempre que existir uma ferramenta determinística capaz de resolver a tarefa,
> o LLM nao decide — ele apenas interpreta a saida da ferramenta."**

---

## Arquitetura (8 Camadas)

| Camada | Nome | Funcao | LLM? |
|--------|------|--------|------|
| **L1** | Entrada & Triagem | Ingestao de codigo, classificacao de linguagem, prompt-injection guard | Nao |
| **L2** | Especialistas | 30+ agentes SAST, SCA, Hardening, Secrets (por linguagem/ferramenta) | Parcial (L2.16) |
| **L3** | Validacao | Reachability, PoC sandboxed, fuzzing (HITL), motor de score | Nao (score) |
| **L4** | Consenso/Debate | CVSS+EPSS+SSVC, piso nao-negociavel, debate adversarial | Sim (debate) |
| **L5** | Remediacao | Trilha A (patch codigo) + Trilha B (contencao WAF/Firewall) | Sim (patch) |
| **L6** | Governanca | Policy engine (OPA/Rego), auditoria unificada, HITL gateway, four-eyes | Nao |
| **L7** | Model Ensemble | Roteamento LLM (local vs Bedrock), ensemble, circuit breaker de custo | Sim (roteamento) |
| **L8** | Escala | Ativacao condicional, onboarding de agentes, multi-tenancy | Nao |

---

## Stack Tecnologica

- **Linguagem:** Python 3.12+ (type hints obrigatorios, mypy --strict)
- **Schemas:** Pydantic v2 para todos os modelos de dados
- **Infra:** AWS (Lambda, ECS Fargate, Bedrock, DynamoDB, S3, SQS, EventBridge)
- **IaC:** Terraform 1.7+ com modulos provisionados
- **Politicas:** OPA/Rego
- **Observabilidade:** structlog JSON + Grafana
- **Testes:** pytest (cobertura minima 85%), bandit, truffleHog

---

## Modulo MVP2 — Copiloto LLM (M4)

O módulo `/mvp2/copilot/` e o **Copiloto LLM para achados tier ATTEND**, um consumidor
READ-ONLY da saida do Decision Engine do MVP1.

### Componentes

| Arquivo | Funcao |
|---------|--------|
| `models.py` | Schemas Pydantic: CopilotAnalysis, AmbiguitySignal, FindingContext |
| `config.py` | Settings via env vars (Bedrock region, model IDs, thresholds) |
| `prompt_builder.py` | Montagem de prompts com contexto fixo (SSVC tree) + RAG |
| `rag_retriever.py` | Recuperacao de contexto via indice JSON local (futuro: pgvector) |
| `claude_client.py` | Cliente Bedrock para Claude 3.5 (Haiku rotina, Sonnet escalacao) |
| `handler.py` | SQS consumer — orquestra RAG → prompt → Claude → parse |
| `observability.py` | Logging JSON estruturado + metricas de desempenho |

### Fluxo do Copiloto

```
SQS (DecisionRecord) → CopilotHandler
  ├── RAG retrieval (CWE matching)
  ├── Prompt build (fixed context + RAG + finding)
  ├── Claude Haiku (routine analysis)
  ├── [ambiguity ≥ threshold] → Claude Sonnet (escalation)
  └── CopilotResponse (CopilotAnalysis + AmbiguitySignals)
```

### Modo Shadow

Por padrao, o copiloto opera em **modo shadow**: analisa mas nao produz efeitos colaterais.
Isso permite validacao antes da ativacao em producao.

### Modelos Claude via Bedrock

| Modelo | Uso | Tier |
|--------|-----|------|
| Claude 3.5 Haiku | Analise de rotina (alta velocidade) | Volume |
| Claude 3.5 Sonnet | Escalacao em ambiguidade (raciocinio profundo) | Reasoning |

---

## Configuracao OpenCode

O projeto usa **12 agentes especializados** configurados via `opencode.json`:

| Agente | LLM | Funcao |
|--------|-----|--------|
| `@ztk-orchestrator` | Kimi | Orquestrador de workflows multi-agente |
| `@ztk-build` | Kimi | Builder principal — implementacao |
| `@ztk-backend` | Kimi | Backend Python/AWS |
| `@ztk-infra` | Kimi | Terraform/Infra |
| `@ztk-qa` | Kimi | Quality gates e testes |
| `@ztk-strategist` | DeepSeek | Arquitetura e threat modeling |
| `@ztk-reviewer` | DeepSeek | Revisao de seguranca |
| `@ztk-governance` | DeepSeek | GRC e compliance |
| `@ztk-security-ops` | DeepSeek | SOC e hardening PCI |
| `@ztk-regulatory` | DeepSeek | Auditoria e evidencias |
| `@ztk-po` | DeepSeek | Product Owner |
| `@ztk-pm` | DeepSeek | Project Manager |

---

## Quality Gates (Obrigatorios)

Todo codigo deve passar:

```bash
# Testes unitarios
python -m pytest mvp2/copilot/tests/ -v

# Type checking
python -m mypy mvp2/copilot/src/copilot/ --strict

# Lint
python -m ruff check mvp2/copilot/

# Security SAST
python -m bandit -r mvp2/copilot/

# Secret scan
grep -r "verify=False" --include="*.py" mvp2/
grep -r "api_key\s*=\s*['\"]" --include="*.py" mvp2/
grep -r "password\s*=\s*['\"]" --include="*.py" mvp2/

# Infra scan
terraform validate infra/terraform/
```

---

## Roadmap (52 semanas)

| Milestone | Semanas | Entregavel |
|-----------|---------|------------|
| M0 | 1-4 | Fundacao (schemas, infra, CI/CD) |
| M1 | 5-6 | Camada 1 — Entrada & Triagem |
| M2 | 7-10 | Camada 6 — Governanca transversal |
| M3 | 11-18 | Camada 2 — Especialistas (30+ agentes) |
| M4 | 19-24 | Camada 3 — Validacao (PoC, fuzzing) |
| M5 | 25-28 | Camada 4 — Consenso/Debate |
| M6 | 29-34 | Camada 5 — Remediacao (patch + contencao) |
| M7 | 35-38 | Camada 7 — Model Ensemble |
| M8 | 39-42 | Camada 8 — Escala |
| M9-M12 | 43-52 | Interface, Docs, SecTests, Governance Review |

Detalhes completos em `TASKS_ZTK.md` e `.opencode/steering/ZTK_LAYER_ROADMAP.md`.

---

## Quick Start (Desenvolvimento Local)

```bash
# 1. Criar venv e instalar dependencias
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
# .venv\Scripts\activate   # Windows
pip install -e .

# 2. Configurar env vars (NUNCA hardcode credenciais)
export COPILOT_BEDROCK_REGION=us-east-1
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...

# 3. Rodar testes
python -m pytest mvp2/copilot/tests/test_copilot.py -v

# 4. Quality gates completos
make test lint typecheck security-sast security-secrets
```

---

## Compliance

- **PCI DSS 4.0**: requisitos 6 (desenvolvimento seguro), 10 (logging), 11 (testes), 12 (IR)
- **LGPD**: minimizacao de dados, criptografia, direito a exclusao
- **Bacen**: Resolucoes 4658, 4893, 85, 3909

---

## Licenca

Uso restrito ao ambiente de adquirência. Distribuição sob autorização.
