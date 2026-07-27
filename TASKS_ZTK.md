# TASKS_ZTK.md — Backlog Estruturado do Projeto Z.T.K.
## Zero Trust Kill: Sistema Multiagente de Análise e Autocorreção de Segurança de Código

> **Versão:** 1.0 | **Data:** 2026-07-25
> **Princípio:** Cada task ataca UM único módulo/componente. NUNCA agrupa múltiplas camadas.
> **Status Legend:** `[ ]` Backlog | `[-]` Em progresso | `[x]` Concluído | `[~]` Bloqueado

---

## STATUS ATUAL — 2026-07-26

### MVP2 — Modulo Copiloto LLM (M4)

Status: **Fase de desenvolvimento inicial. Nucleo implementado, 39/49 testes passando.**

- [x] **M4.01** — `mvp2/copilot/src/copilot/models.py` — Schemas Pydantic: FindingContext, CopilotAnalysis, AmbiguitySignal
- [x] **M4.02** — `mvp2/copilot/src/copilot/config.py` — Settings env-var-driven: Bedrock region, modelos, thresholds
- [x] **M4.03** — `mvp2/copilot/src/copilot/prompt_builder.py` — Montagem de prompts com contexto fixo + SSVC tree
- [x] **M4.04** — `mvp2/copilot/src/copilot/rag_retriever.py` — RAG stub com indice JSON local (futuro: pgvector)
- [x] **M4.05** — `mvp2/copilot/src/copilot/claude_client.py` — Cliente Bedrock para Claude 3.5 Haiku/Sonnet
- [x] **M4.06** — `mvp2/copilot/src/copilot/handler.py` — SQS consumer com fluxo completo (RAG → prompt → Claude → parse)
- [x] **M4.07** — `mvp2/copilot/src/copilot/observability.py` — Logging JSON estruturado + metricas CopilotMetrics
- [x] **M4.08** — `mvp2/copilot/data/prompt_schema.json` — SSVC tree + severity pisos + CWE categories
- [x] **M4.09** — `mvp2/copilot/data/rag_index.json` — 10 documentos RAG (CWE-89, CWE-79, CWE-502, etc.)
- [x] **M4.10** — `mvp2/copilot/tests/test_copilot.py` — 49 testes (39 passando, 10 falhando)
- [ ] **M4.11** — Corrigir 10 testes falhando (logger kwargs, parse enum, double-count metrics)
- [ ] **M4.12** — Pipeline CI/CD para mvp2/copilot/
- [~] **M4.13** — Substituir RAG JSON por Aurora PostgreSQL + pgvector (bloqueado: futuro)
- [~] **M4.14** — Ativar Bedrock real (bloqueado: time de plataforma)

### Fase 0 — Fundacao (progresso)

- [x] **F0.1** — Shared Schemas & Core Library (5 schemas Pydantic + 3 utils, 40/40 testes)
- [x] **F0.2** — Infra Terraform (10 modulos: 6 novos + 4 revisados, `terraform validate` passou)
- [ ] **F0.3** — OPA Policies (deny_by_default + testes)
- [ ] **F0.4** — CI/CD Pipeline completo

### MVP1 — Gates Humanos (bloqueados)

- [~] **G2** — Jira Assets schema (aguardando stakeholders externos)
- [~] **G5** — CAB runbook approval (aguardando stakeholders externos)
- [~] **G7** — AWS deploy real (aguardando stakeholders externos)
- [~] **G9** — Shadow validation (depende de G7)
- [~] **G10** — Pos-shadow tuning (depende de G9)

---

## FASE 0: FUNDAÇÃO (Shared + Infra Base)

### F0.1 — Shared Schemas & Core Library

- [ ] **F0.1.1** — `shared/schemas/finding.py` — Schema base `Finding` (Pydantic v2) com campos obrigatórios: `finding_id`, `tenant_id`, `source`, `severity`, `cwe_ids`, `file_path`, `line_number`, `confidence`, `timestamp`, `audit_trail`
  - **Agente:** backend | **Dependências:** nenhuma | **Critérios:** mypy strict passa, 100% campos tipados, validators Pydantic para UUID e timestamp | **Est:** 2h
- [ ] **F0.1.2** — `shared/schemas/decision.py` — Schema `Decision` com enum `DecisionAction` (TRACK, TRACK_STAR, ATTEND, ACT_3, ACT_14, P0-P4), `rationale: list[str]`, `score: float`, `piso_applied: bool`
  - **Agente:** backend | **Dependências:** F0.1.1 | **Critérios:** validators para ranges de score, `rationale` nunca vazio | **Est:** 2h
- [ ] **F0.1.3** — `shared/schemas/audit_event.py` — Schema `AuditEvent` com `event_id` (SHA-256), `finding_id`, `stage`, `payload_hash`, `timestamp`, `agent_id`, `tenant_id`
  - **Agente:** backend | **Dependências:** F0.1.1 | **Critérios:** idempotência por trinca `finding_id+stage+payload_hash`, `event_id` gerado determinístico | **Est:** 2h
- [ ] **F0.1.4** — `shared/schemas/llm_request.py` — Schema `LLMRequest` com `tier` (Volume/Reasoning/Generation), `data_scope` (PCI/non-PCI), `max_tokens`, `temperature`, `content_hash`
  - **Agente:** backend | **Dependências:** F0.1.1 | **Critérios:** `data_scope=PCI` implica `provider=LOCAL` (validator Pydantic) | **Est:** 1.5h
- [ ] **F0.1.5** — `shared/schemas/containment.py` — Schema `ContainmentRule` com `cwe_class`, `template_id`, `vendor` (F5/Akamai/Azure), `ttl_hours`, `dry_run_result`, `applied_at`
  - **Agente:** backend | **Dependências:** F0.1.1 | **Critérios:** `ttl_hours` obrigatório e >0 | **Est:** 1.5h
- [ ] **F0.1.6** — `shared/utils/idempotency.py` — Função pura `generate_idempotency_key(*parts: str) -> str` usando SHA-256 separado por `|`
  - **Agente:** backend | **Dependências:** nenhuma | **Critérios:** 100% testado, nunca serializa JSON no hash, retorna mesmo resultado para mesmos inputs | **Est:** 1h
- [ ] **F0.1.7** — `shared/utils/fail_closed.py` — Decorator `fail_closed(default_return)` para handlers Lambda: captura qualquer exceção, loga com structlog, retorna valor conservador
  - **Agente:** backend | **Dependências:** nenhuma | **Critérios:** testes com mock de exceções, nunca propaga exception não tratada, sempre inclui `request_id` no log | **Est:** 2h
- [ ] **F0.1.8** — `shared/utils/structlog_config.py` — Configuração de logging JSON para Lambda + ECS. Campos obrigatórios: `timestamp`, `level`, `agent_id`, `finding_id`, `request_id`, `message`
  - **Agente:** backend | **Dependências:** nenhuma | **Critérios:** log formato JSON, `request_id` propagado via contextvar, compatível com CloudWatch Logs Insights | **Est:** 2h
- [ ] **F0.1.9** — `shared/utils/secrets.py` — Wrapper `SecretsManager` para buscar segredos do AWS Secrets Manager com cache TTL 5min e fallback para Parameter Store
  - **Agente:** backend | **Dependências:** nenhuma | **Critérios:** nunca loga valor do segredo, cache thread-safe, timeout configurável, fail-closed em indisponibilidade | **Est:** 2.5h
- [ ] **F0.1.10** — `shared/utils/dynamodb_client.py` — Cliente DynamoDB async com retries (tenacity), idempotência em `put_item` (ConditionExpression), paginação em `query`
  - **Agente:** backend | **Dependências:** nenhuma | **Critérios:** tests mock com moto, nunca sobrescreve item existente sem confirmação, batch_get/batch_write seguros | **Est:** 3h
- [ ] **F0.1.11** — `shared/utils/s3_client.py` — Cliente S3 async para write append-only com `If-None-Match: *` e particionamento `stage={stage}/dt={date}/finding_id={id}/`
  - **Agente:** backend | **Dependências:** nenhuma | **Critérios:** `head_object` antes de write, skip silencioso se já existe, particionamento conforme especificação | **Est:** 2.5h
- [ ] **F0.1.12** — `shared/utils/sqs_client.py` — Cliente SQS async para publish com DLQ routing, delay seconds, message attributes (`finding_id`, `agent_id`, `tenant_id`)
  - **Agente:** backend | **Dependências:** nenhuma | **Critérios:** message dedup por `finding_id`+`stage`, retry com backoff exponencial, testes com moto | **Est:** 2h

### F0.2 — Infraestrutura Terraform (Módulos Base)

- [ ] **F0.2.1** — `infra/terraform/modules/vpc/main.tf` — VPC com 3 AZs, public + private subnets, NAT Gateway (1 por AZ ou single), VPC Flow Logs para S3, Security Group base
  - **Agente:** infra | **Dependências:** nenhuma | **Critérios:** CIDR parametrizável, flow logs ativados, subnet tagging `Tier=Public/Private`, output de `vpc_id`, `private_subnet_ids`, `public_subnet_ids` | **Est:** 3h
- [ ] **F0.2.2** — `infra/terraform/modules/dynamodb/main.tf` — Tabelas: `Findings` (PK=`tenant_id`, SK=`finding_id`), `AuditEvents` (PK=`finding_id`, SK=`stage#timestamp`), `HITLQueue` (PK=`queue_id`, SK=`status#created_at`), `TenantConfig` (PK=`tenant_id`), `CostMetrics` (PK=`tenant_id`, SK=`date#tier`)
  - **Agente:** infra | **Dependências:** F0.2.1 | **Critérios:** on-demand billing, PITR ativado, SSE com CMK, TTL em `AuditEvents` (retenção PCI), tags de compliance | **Est:** 4h
- [ ] **F0.2.3** — `infra/terraform/modules/s3/main.tf` — Buckets: `ztk-audit-data-lake` (append-only, versioning), `ztk-snapshots` (quarentena de snapshot bruto), `ztk-terraform-state` (existente, validar)
  - **Agente:** infra | **Dependências:** F0.2.1 | **Critérios:** encryption AES-256/SSE-KMS, block public access, lifecycle para IA/ Glacier, logging access | **Est:** 3h
- [ ] **F0.2.4** — `infra/terraform/modules/sqs/main.tf` — Filas: `queue_ingest`, `queue_normalize`, `queue_enrich`, `queue_decide`, `queue_remediate`, `queue_audit`, `queue_hitl`, `dlq_<nome>` por fila. EventBridge Bus para fan-out entre camadas
  - **Agente:** infra | **Dependências:** F0.2.1 | **Critérios:** DLQ com redrive policy maxReceiveCount=3, visibility timeout >= Lambda timeout, fila por fonte (isolamento), tags | **Est:** 3h
- [ ] **F0.2.5** — `infra/terraform/modules/lambda/main.tf` — Módulo genérico de Lambda Python 3.12 com VPC opcional, IAM role least privilege, environment variables do Parameter Store, CloudWatch Logs group com retention 90 dias
  - **Agente:** infra | **Dependências:** F0.2.1, F0.2.4 | **Critérios:** handler genérico via variável, memória/tempo parametrizáveis, sem credenciais em env var, X-Ray ativo | **Est:** 3h
- [ ] **F0.2.6** — `infra/terraform/modules/ecs_fargate/main.tf` — Cluster ECS Fargate Spot, Task Definition genérica (CPU/mem parametrizáveis), Service com Auto Scaling baseado em SQS queue depth, Security Group restrito, IAM Task Role least privilege
  - **Agente:** infra | **Dependências:** F0.2.1, F0.2.4 | **Critérios:** Fargate Spot capacity provider, readOnlyRootFilesystem, runAsNonRoot, noNewPrivileges, health check no container | **Est:** 4h
- [ ] **F0.2.7** — `infra/terraform/modules/ec2_gpu/main.tf` — Launch Template para g5.xlarge Spot, AMI Deep Learning, user-data para instalar vLLM + modelos AWQ, EBS criptografado, Security Group sem ingress público (via Session Manager/SSM)
  - **Agente:** infra | **Dependências:** F0.2.1 | **Critérios:** spot instance com interruption handling (SQS notification), EBS KMS, SSM agent pré-instalado, nenhuma chave SSH, health check via ALB ou NLB | **Est:** 4h
- [ ] **F0.2.8** — `infra/terraform/modules/iam/main.tf` — Roles: `LambdaIngestRole`, `LambdaGovernanceRole`, `ECSTaskRole`, `EC2GpuRole`, `BedrockInvokeRole`, `GrafanaExecutionRole`, `StepFunctionsRole`. Cada role com policy mínima (ARO + inline policy específica)
  - **Agente:** infra | **Dependências:** F0.2.1–F0.2.7 | **Critérios:** nenhuma permissão wildcards (`*:*`), Secrets Manager scoped por secret ARN, DynamoDB scoped por table, S3 scoped por bucket+prefix | **Est:** 4h
- [ ] **F0.2.9** — `infra/terraform/modules/bedrock/main.tf` — IAM permissions para invoke model via `bedrock:InvokeModel` e `bedrock:InvokeModelWithResponseStream`, scoped para modelos específicos (Claude Sonnet/Haiku ARNs)
  - **Agente:** infra | **Dependências:** F0.2.8 | **Critérios:** nenhum acesso a modelos não aprovados, logging via CloudWatch, guardrails association | **Est:** 2h
- [ ] **F0.2.10** — `infra/terraform/modules/grafana/main.tf` — ECS Fargate service para Grafana Enterprise, EFS para dashboards/persistência, ALB interno, Security Group restrito, datasource provisioning via config file
  - **Agente:** infra | **Dependências:** F0.2.1, F0.2.6 | **Critérios:** admin password em Secrets Manager, datasources CloudWatch/Athena/Prometheus auto-provisionados, SSL/TLS no ALB | **Est:** 3h

### F0.3 — Infraestrutura Terraform (Orquestração + Policies)

- [ ] **F0.3.1** — `infra/terraform/modules/step_functions/main.tf` — State Machine `ZTKPipeline` (Camadas 1→5), `ZTKAuditPipeline` (Camada 6), `ZTKRemediationPipeline` (Trilha A+B). Tasks: Lambda Invoke, ECS RunTask, SQS SendMessage, Choice ( branching por score/severidade ), Wait (TTL), Parallel (Trilha A+B)
  - **Agente:** infra | **Dependências:** F0.2.1–F0.2.9 | **Critérios:** ASL JSON versionado, IAM least privilege por state, logging para CloudWatch, X-Ray tracing | **Est:** 5h
- [ ] **F0.3.2** — `infra/policies/` — Estrutura de diretórios para OPA/Rego: `severity/`, `routing/`, `containment/`, `exceptions/`, `cost/`. Policy base `deny_by_default.rego`
  - **Agente:** governance | **Dependências:** nenhuma | **Critérios:** `package ztk.deny_by_default`, `default allow = false`, testes com `opa test` | **Est:** 2h
- [ ] **F0.3.3** — `infra/policies/severity/severity_floors.rego` — Políticas de piso não-negociável: PCI → P1, LGPD → P1, Antifraude → P0. Função `severity_floor(category)` pura
  - **Agente:** governance | **Dependências:** F0.3.2 | **Critérios:** testes cobrindo todos os pisos, nenhum override sem four-eyes (apenas a política, a lógica de aplicação vem na Camada 6) | **Est:** 2h
- [ ] **F0.3.4** — `infra/policies/routing/model_routing.rego` — Regra: `data_scope == "PCI" => provider == "LOCAL"`. Regra: `tier == "Volume" => model_distilled`
  - **Agente:** governance | **Dependências:** F0.3.2 | **Critérios:** testes com mock de input, negação explícita para roteamento PCI→Bedrock | **Est:** 2h
- [ ] **F0.3.5** — `infra/policies/containment/containment_templates.rego` — Registro de templates válidos por CWE class: `template_exists(cwe_class, vendor)` com lista allowlist
  - **Agente:** governance | **Dependências:** F0.3.2 | **Critérios:** deny se CWE sem template para vendor, testes com 5 CWEs principais | **Est:** 2h
- [ ] **F0.3.6** — `infra/policies/exceptions/four_eyes.rego` — Regra: exceção só é permitida se `approver_1 != approver_2` e ambos estão em roles `ExecutiveManager`/`Superintendent`
  - **Agente:** governance | **Dependências:** F0.3.2 | **Critérios:** nega se mesma pessoa, nega se role incorreta, testes com 4 cenários | **Est:** 2h
- [ ] **F0.3.7** — `infra/policies/cost/budget_limits.rego` — Regra: se `tier == "Reasoning"` e `budget_pct > 100` => deny. Exceção: `action in ["HITL", "kill_switch", "containment_critical"]` => allow sempre
  - **Agente:** governance | **Dependências:** F0.3.2 | **Critérios:** testes de circuit breaker, nunca nega ações críticas | **Est:** 2h

### F0.4 — Qualidade Gates & CI/CD

- [ ] **F0.4.1** — `.github/workflows/ci.yml` — Workflow GitHub Actions: checkout → setup Python 3.12 → install deps → ruff check → mypy strict → pytest with coverage → bandit → opa test
  - **Agente:** devsecops | **Dependências:** nenhuma | **Critérios:** falha em qualquer gate bloqueia PR, artifact de coverage report, artifact de bandit report | **Est:** 2h
- [ ] **F0.4.2** — `Makefile` — Validar/ajustar targets: `lint`, `typecheck`, `test`, `test-cov`, `security-sast` (bandit + semgrep), `security-secrets` (truffleHog), `opa-test`, `integration-test`
  - **Agente:** devsecops | **Dependências:** F0.4.1 | **Critérios:** todos os targets funcionam localmente, `make all` executa sequência completa | **Est:** 1.5h
- [ ] **F0.4.3** — `scripts/pre-commit/hooks/` — Hook de pre-commit: ruff, mypy, bandit, truffleHog (staged files), check-json/yaml
  - **Agente:** devsecops | **Dependências:** F0.4.1 | **Critérios:** instalação via `make install-hooks`, falha bloqueia commit, nunca altera arquivo sem aviso | **Est:** 1.5h

### F0.5 — Testes Unitários da Fundação

- [ ] **F0.5.1** — `tests/unit/shared/` — Testes para todos os utilitários em `shared/utils/` (idempotency, fail_closed, structlog, secrets, dynamodb, s3, sqs)
  - **Agente:** qa | **Dependências:** F0.1.6–F0.1.12 | **Critérios:** cobertura >=85%, fixtures parametrizadas, mocks com `unittest.mock` e `moto`, testes de fail-closed com exceções forçadas | **Est:** 4h
- [ ] **F0.5.2** — `tests/unit/schemas/` — Testes para todos os schemas Pydantic: validação de campos obrigatórios, rejeição de valores inválidos, comportamento de defaults
  - **Agente:** qa | **Dependências:** F0.1.1–F0.1.5 | **Critérios:** cobertura 100% dos validators, testes de edge cases (UUID malformado, timestamp futuro) | **Est:** 3h

---

## FASE 1: CAMADA 1 — ENTRADA & TRIAGEM

### F1.1 — Ingestão e Classificação Determinística

- [ ] **F1.1.1** — `src/layer1_ingress/repo_ingestion/handler.py` — Lambda handler `L1.01`: recebe evento EventBridge (repo URL, commit/PR ref), clona repo read-only via Git CLI, extrai diff e metadados
  - **Agente:** backend | **Dependências:** F0.1.1, F0.1.6, F0.1.7, F0.1.8, F0.2.5 | **Critérios:** token com escopo mínimo (`contents:read`), nunca executa código do repo (no build/install), output para SQS `queue_normalize` | **Est:** 3h
- [ ] **F1.1.2** — `src/layer1_ingress/language_classifier/service.py` — Serviço `L1.02`: detecta linguagem/framework via `go-enry` ou `github-linguist` CLI, classifica artefato (backend/frontend/IaC/mobile)
  - **Agente:** backend | **Dependências:** F1.1.1 | **Critérios:** confiança < threshold → retorna `"unclassified"` (fail-closed), nunca infere, output estruturado JSON | **Est:** 2.5h
- [ ] **F1.1.3** — `src/layer1_ingress/prompt_injection_guard/service.py` — Serviço `L1.03`: escaneia comentários, strings, nomes de variáveis por padrões de prompt injection (regex/heurística) + envelopa conteúdo como dado
  - **Agente:** backend | **Dependências:** F1.1.1 | **Critérios:** lista de padrões em config YAML versionada, conteúdo suspeito isolado e sinalizado, nunca passa "cru" para downstream | **Est:** 3h
- [ ] **F1.1.4** — `src/layer1_ingress/business_criticality/service.py` — Serviço `L1.04`: consulta catálogo de serviços/CMDB (mock/configurável) e CODEOWNERS, retorna criticidade (`critical/high/medium/low/unknown`)
  - **Agente:** backend | **Dependências:** F1.1.1 | **Critérios:** catálogo inexistente → `"unknown"` (nunca infere), valor `unknown` propagado como conservador nas camadas seguintes | **Est:** 2h
- [ ] **F1.1.5** — `src/layer1_ingress/pipeline_router/service.py` — Serviço `L1.05`: motor de regras YAML/JSON versionado que decide quais especialistas Camada 2 acionar por arquivo/diff
  - **Agente:** backend | **Dependências:** F1.1.2, F1.1.4 | **Critérios:** arquivo sem regra mapeada → pipeline genérico + log de gap de cobertura, regra carregada de S3/config (não hardcoded) | **Est:** 2.5h
- [ ] **F1.1.6** — `src/layer1_ingress/budget_planner/service.py` — Serviço `L1.06`: decide prioridade de análise e teto de custo/tokens por lote baseado em tamanho do diff e histórico
  - **Agente:** backend | **Dependências:** F1.1.1 | **Critérios:** budget excedido → enfileira restante (nunca trunca silenciosamente), valores configuráveis por tenant | **Est:** 2h
- [ ] **F1.1.7** — `src/layer1_ingress/dedup_generator/service.py` — Serviço `L1.07`: gera SHA-256 do conteúdo normalizado por arquivo/diff para dedup e cache semântico
  - **Agente:** backend | **Dependências:** F0.1.6 | **Critérios:** colisão/erro de hash → força reprocessamento, normalização idempotente (strip whitespace, ordenar imports) | **Est:** 1.5h

### F1.2 — Orquestração Camada 1

- [ ] **F1.2.1** — `src/layer1_ingress/orchestrator/handler.py` — Step Functions state machine `ZTKLayer1Orchestrator` que encadeia L1.01→L1.02→L1.03→L1.04→L1.05→L1.06→L1.07 em sequência, com Choice para conteúdo suspeito (L1.03) e Parallel para L1.06+L1.07
  - **Agente:** infra | **Dependências:** F1.1.1–F1.1.7, F0.3.1 | **Critérios:** ASL versionado, retry por step (max 3), timeout total 15min, output para SQS `queue_layer2` | **Est:** 3h

### F1.3 — Testes Camada 1

- [ ] **F1.3.1** — `tests/unit/layer1_ingress/` — Testes unitários para todos os serviços L1.02–L1.07: mocks de CMDB, testes de fail-closed, validação de output schemas
  - **Agente:** qa | **Dependências:** F1.1.1–F1.1.7 | **Critérios:** cobertura >=85%, testes de caminho feliz + fail-closed + edge cases | **Est:** 4h
- [ ] **F1.3.2** — `tests/integration/layer1_ingress/` — Teste de integração end-to-end: evento EventBridge → handler L1.01 → SQS → processamento → output validado
  - **Agente:** qa | **Dependências:** F1.2.1 | **Critérios:** usa moto para SQS/DynamoDB/S3, valida sequência completa, verifica idempotência | **Est:** 3h

---

## FASE 2: CAMADA 6 — GOVERNANÇA (Policy Engine, Auditoria, HITL)

> **Nota:** Camada 6 é construída ANTES das Camadas 2–5 porque é consumida por todas elas.

### F2.1 — Policy Engine Core

- [ ] **F2.1.1** — `src/layer6_governance/policy_engine/handler.py` — Lambda `L6.01`: avalia toda regra de negócio via OPA/Rego. Input: `action`, `context` (JSON). Output: `allowed: bool`, `violations: list[str]`, `policy_version`
  - **Agente:** governance | **Dependências:** F0.3.2–F0.3.7, F0.1.3 | **Critérios:** consulta OPA via local eval (opa wasm ou subprocess), política ambígua → `allowed=false`, cache de policy version por 60s | **Est:** 3.5h
- [ ] **F2.1.2** — `src/layer6_governance/policy_registry/service.py` — Serviço `L6.02`: versiona políticas em Git (via webhook) e disponibiliza para L6.01. Registro de releases com changelog
  - **Agente:** governance | **Dependências:** F2.1.1 | **Critérios:** hash do commit = version, rollback para versão anterior em <30s, API para listar versões | **Est:** 2.5h
- [ ] **F2.1.3** — `src/layer6_governance/policy_change_gate/service.py` — Serviço `L6.03`: valida que todo PR de política tem dupla aprovação (1 técnico + 1 compliance) antes de merge
  - **Agente:** governance | **Dependências:** F2.1.2 | **Critérios:** integração com GitHub API, bloqueia PR se aprovação insuficiente, comentário automático com checklist | **Est:** 2h
- [ ] **F2.1.4** — `src/layer6_governance/policy_test_runner/service.py` — Serviço `L6.04`: roda `opa test` automaticamente contra políticas no PR, bloqueia merge se falha
  - **Agente:** governance | **Dependências:** F2.1.2 | **Critérios:** execução em container efêmero (ECS Fargate), output de teste como comentário no PR, timeout 5min | **Est:** 2.5h

### F2.2 — Fluxo de Exceção (Four-Eyes)

- [ ] **F2.2.1** — `src/layer6_governance/exception_intake/handler.py` — Lambda `L6.05`: recebe solicitação de exceção pontual (HTTP API Gateway), valida campos obrigatórios (finding_id, justificativa, prazo)
  - **Agente:** governance | **Dependências:** F2.1.1, F0.1.3 | **Critérios:** solicitação incompleta → HTTP 400 com erro estruturado (nunca 500), cria registro em DynamoDB `HITLQueue` | **Est:** 2h
- [ ] **F2.2.2** — `src/layer6_governance/exception_approver/service.py` — Serviço `L6.06+L6.07`: orquestra dupla aprovação. Primeiro aprovador: Gerente Executivo (role IAM). Segundo: Superintendente (role IAM). Mesma pessoa bloqueada.
  - **Agente:** governance | **Dependências:** F2.2.1, F0.3.6 | **Critérios:** aprovação gera token JWT assinado com prazo, mesma identidade em ambas → rejeição, notificação via L6.14–L6.16 | **Est:** 3h
- [ ] **F2.2.3** — `src/layer6_governance/exception_applier/service.py` — Serviço `L6.08`: aplica exceção apenas ao finding específico, com prazo de vigência. Nunca altera política geral.
  - **Agente:** governance | **Dependências:** F2.2.2 | **Critérios:** aplicação gera `AuditEvent`, prazo expira → revert automaticamente para piso original (Lambda Scheduled Event) | **Est:** 2.5h
- [ ] **F2.2.4** — `src/layer6_governance/exception_audit/service.py` — Serviço `L6.09`: registra solicitante, aprovadores, motivo, prazo, finding afetado em `AuditEvents`
  - **Agente:** governance | **Dependências:** F2.2.3, F0.1.3 | **Critérios:** append-only, nunca atualiza registro existente, hash verificável de integridade | **Est:** 1.5h

### F2.3 — Auditoria Unificada

- [ ] **F2.3.1** — `src/layer6_governance/audit_collector/handler.py` — Lambda `L6.10`: recebe eventos de todas as camadas via EventBridge, normaliza para `AuditEvent`, valida schema
  - **Agente:** governance | **Dependências:** F0.1.3, F0.1.8, F0.2.4 | **Critérios:** evento malformado → rejeitado na origem (DLQ para reprocessamento manual), batch write para S3 e DynamoDB | **Est:** 3h
- [ ] **F2.3.2** — `src/layer6_governance/audit_sentinel/service.py` — Serviço `L6.11`: forward de eventos para Microsoft Sentinel (Log Analytics API). Retry com fila local.
  - **Agente:** governance | **Dependências:** F2.3.1 | **Critérios:** falha de envio → fila SQS de retry com backoff, nunca descarta evento, batching para eficiência | **Est:** 2.5h
- [ ] **F2.3.3** — `src/layer6_governance/audit_retention/service.py` — Serviço `L6.12`: monitora retenção S3/DynamoDB. Alerta se abaixo do mínimo PCI DSS req. 10 (1 ano total, 3 meses prontamente disponíveis)
  - **Agente:** governance | **Dependências:** F2.3.1 | **Critérios:** CloudWatch Alarm se lifecycle policy < 365 dias, monthly compliance report | **Est:** 2h

### F2.4 — HITL Gateway Unificado

- [ ] **F2.4.1** — `src/layer6_governance/hitl_queue/service.py` — Serviço `L6.13`: fila única com metadados de origem (fuzzing, divergência, contenção, kill switch, exceção) e urgência
  - **Agente:** governance | **Dependências:** F0.1.3, F0.2.2 | **Critérios:** ordenação por `priority_score` (urgência × criticidade), dedup por `finding_id`+`origin`, status tracking (`pending/assigned/resolved/escalated`) | **Est:** 3h
- [ ] **F2.4.2** — `src/layer6_governance/hitl_notifier/service.py` — Serviço `L6.14+L6.15`: notifica via Microsoft Teams (API) e e-mail (SMTP) com template por tipo de HITL
  - **Agente:** governance | **Dependências:** F2.4.1 | **Critérios:** fallback para e-mail se Teams falha, rate limiting, nunca expõe finding details completos no chat (link seguro para interface) | **Est:** 2.5h
- [ ] **F2.4.3** — `src/layer6_governance/hitl_jira/service.py` — Serviço `L6.16`: abre ticket Jira para rastreabilidade fora do chat efêmero
  - **Agente:** governance | **Dependências:** F2.4.1 | **Critérios:** campo custom `finding_id`, link para timeline de auditoria, status bidirecional (Jira ↔ HITL queue) | **Est:** 2h
- [ ] **F2.4.4** — `src/layer6_governance/hitl_sla_monitor/service.py` — Serviço `L6.17`: monitora tempo de resposta por tipo de HITL, escala se estourar SLA
  - **Agente:** governance | **Dependências:** F2.4.1 | **Critérios:** SLA configurável por categoria, alerta progressivo (15min antes do estouro), reutiliza lógica de L5.17 | **Est:** 2h

### F2.5 — Testes Camada 6

- [ ] **F2.5.1** — `tests/unit/layer6_governance/` — Testes unitários para policy engine, exception flow, audit collector, HITL queue. Mocks de OPA, Jira, Teams API
  - **Agente:** qa | **Dependências:** F2.1.1–F2.4.4 | **Critérios:** cobertura >=85%, testes de four-eyes com mesma pessoa, testes de circuit breaker de retenção | **Est:** 5h
- [ ] **F2.5.2** — `tests/integration/layer6_governance/` — Teste de integração: evento de Camada simulada → audit collector → S3 → validação de particionamento
  - **Agente:** qa | **Dependências:** F2.3.1 | **Critérios:** valida particionamento S3, idempotência de evento duplicado, append-only | **Est:** 3h
- [ ] **F2.5.3** — `tests/e2e/governance_exception_flow.py` — E2E: solicitação de exceção → dupla aprovação simulada → aplicação → auditoria → expiração → reversão
  - **Agente:** qa | **Dependências:** F2.2.1–F2.2.4 | **Critérios:** Step Functions local (moto), valida estado final no DynamoDB, confirma TTL de reversão | **Est:** 3h

---

## FASE 3: CAMADA 2 — ESPECIALISTAS DE SEGURANÇA (Estáticos)

> **Abordagem:** Construir o FRAMEWORK de execução SAST primeiro (wrapper genérico, parser SARIF/JSON, sandbox ECS), depois instanciar por linguagem/ferramenta. Segredos, SCA e Hardening seguem padrão similar.

### F3.1 — Framework de Execução SAST

- [ ] **F3.1.1** — `src/layer2_specialists/sast_framework/executor.py` — Classe base `SASTExecutor` para rodar ferramenta em container ECS Fargate Spot: monta input (código), executa CLI, captura stdout/stderr, timeout configurável
  - **Agente:** backend | **Dependências:** F0.1.7, F0.1.8, F0.2.6 | **Critérios:** readOnlyRootFilesystem, sem montagem de filesystem host, timeout kill -9, output sempre JSON/SARIF | **Est:** 4h
- [ ] **F3.1.2** — `src/layer2_specialists/sast_framework/parser.py` — Parser genérico de SARIF/JSON para `list[Finding]`. Suporta SARIF 2.1.0 e JSON customizado.
  - **Agente:** backend | **Dependências:** F3.1.1, F0.1.1 | **Critérios:** normaliza severidade nativa para escala ZTK, extrai `cwe_id`, `file_path`, `line_number`, nunca falha silenciosamente em parse error | **Est:** 3h
- [ ] **F3.1.3** — `src/layer2_specialists/sast_framework/correlator.py` — Serviço `L2.16`: único ponto com LLM nesta subcamada. Interpreta e correlaciona saídas JSON/SARIF de múltiplas ferramentas SEM reanalisar código-fonte
  - **Agente:** backend | **Dependências:** F3.1.2, F7.1.1 (Camada 7 router) | **Critérios:** input: lista de `Finding` de múltiplas fontes. Output: `CorrelatedFinding` com `consensus_score`. Saída ambígua → `"requer validação humana"` | **Est:** 4h

### F3.2 — SAST por Linguagem × Ferramenta (Instanciações)

- [ ] **F3.2.1** — `src/layer2_specialists/sast_python_bandit/` — Agente `L2.01`: wrapper Bandit para Python. Dockerfile com `bandit>=1.7.7`, saída JSON
  - **Agente:** backend | **Dependências:** F3.1.1, F3.1.2 | **Critérios:** Dockerfile mínimo (python:3.12-slim), bandit config via `.bandit` no repo target, timeout 300s | **Est:** 2h
- [ ] **F3.2.2** — `src/layer2_specialists/sast_python_semgrep/` — Agente `L2.02`: wrapper Semgrep Python ruleset
  - **Agente:** backend | **Dependências:** F3.1.1, F3.1.2 | **Critérios:** ruleset padrão OWASP + custom, config YAML versionada, saída JSON | **Est:** 2h
- [ ] **F3.2.3** — `src/layer2_specialists/sast_java_spotbugs/` — Agente `L2.03`: wrapper SpotBugs + FindSecBugs
  - **Agente:** backend | **Dependências:** F3.1.1, F3.1.2 | **Critérios:** requer build (Maven/Gradle) → se falha, log de gap, nunca assume seguro | **Est:** 2.5h
- [ ] **F3.2.4** — `src/layer2_specialists/sast_java_codeql/` — Agente `L2.04`: wrapper CodeQL Java
  - **Agente:** backend | **Dependências:** F3.1.1, F3.1.2 | **Critérios:** build obrigatório, taint tracking, build falha → escala revisão manual (alto risco) | **Est:** 3h
- [ ] **F3.2.5** — `src/layer2_specialists/sast_js_eslint/` — Agente `L2.05`: wrapper ESLint security
  - **Agente:** backend | **Dependências:** F3.1.1, F3.1.2 | **Critérios:** config ESLint estendida, saída JSON, timeout 180s | **Est:** 2h
- [ ] **F3.2.6** — `src/layer2_specialists/sast_js_semgrep/` — Agente `L2.06`: wrapper Semgrep JS/TS
  - **Agente:** backend | **Dependências:** F3.1.1, F3.1.2 | **Critérios:** ruleset para injection, prototype pollution, XSS server-side | **Est:** 2h
- [ ] **F3.2.7** — `src/layer2_specialists/sast_go_gosec/` — Agente `L2.07`: wrapper gosec
  - **Agente:** backend | **Dependências:** F3.1.1, F3.1.2 | **Critérios:** Dockerfile multi-stage (golang + gosec), saída JSON, timeout 180s | **Est:** 2h
- [ ] **F3.2.8** — `src/layer2_specialists/sast_go_codeql/` — Agente `L2.08`: wrapper CodeQL Go
  - **Agente:** backend | **Dependências:** F3.1.1, F3.1.2 | **Critérios:** build via `go build`, taint tracking | **Est:** 2.5h
- [ ] **F3.2.9** — `src/layer2_specialists/sast_cpp_cppcheck/` — Agente `L2.09`: wrapper cppcheck
  - **Agente:** backend | **Dependências:** F3.1.1, F3.1.2 | **Critérios:** análise rápida (leve), saída XML/JSON, timeout 300s | **Est:** 2h
- [ ] **F3.2.10** — `src/layer2_specialists/sast_cpp_codeql/` — Agente `L2.10`: wrapper CodeQL C/C++
  - **Agente:** backend | **Dependências:** F3.1.1, F3.1.2 | **Critérios:** build obrigatório, memory safety profundo (UAF, overflow), build falha → escala manual | **Est:** 2.5h
- [ ] **F3.2.11** — `src/layer2_specialists/sast_rust_clippy/` — Agente `L2.11`: wrapper clippy + cargo-audit
  - **Agente:** backend | **Dependências:** F3.1.1, F3.1.2 | **Critérios:** Dockerfile rust:slim, cargo audit para deps, saída JSON | **Est:** 2h
- [ ] **F3.2.12** — `src/layer2_specialists/sast_cs_roslyn/` — Agente `L2.12`: wrapper Roslyn security analyzers
  - **Agente:** backend | **Dependências:** F3.1.1, F3.1.2 | **Critérios:** .NET SDK no container, saída SARIF, timeout 300s | **Est:** 2.5h
- [ ] **F3.2.13** — `src/layer2_specialists/sast_php_psalm/` — Agente `L2.13`: wrapper Psalm security
  - **Agente:** backend | **Dependências:** F3.1.1, F3.1.2 | **Critérios:** PHP 8.2+ no container, config XML, saída JSON | **Est:** 2h
- [ ] **F3.2.14** — `src/layer2_specialists/sast_ruby_brakeman/` — Agente `L2.14`: wrapper Brakeman
  - **Agente:** backend | **Dependências:** F3.1.1, F3.1.2 | **Critérios:** Ruby 3.x no container, saída JSON, Rails-specific | **Est:** 2h
- [ ] **F3.2.15** — `src/layer2_specialists/sast_mobile_mobsf/` — Agente `L2.15`: wrapper MobSF estático
  - **Agente:** backend | **Dependências:** F3.1.1, F3.1.2 | **Critérios:** MobSF server efêmero (Docker), API REST para submit/scan/report, timeout 600s | **Est:** 3h

### F3.3 — Hardening por Domínio

- [ ] **F3.3.1** — `src/layer2_specialists/hardening_appsec/` — Agente `L2.17`: Semgrep + OWASP API Security Top 10. Valida contrato OpenAPI se existente
  - **Agente:** backend | **Dependências:** F3.1.1, F3.1.2 | **Critérios:** sem contrato OpenAPI → `"sem cobertura de contrato"` (nunca assume seguro), saída JSON | **Est:** 2.5h
- [ ] **F3.3.2** — `src/layer2_specialists/hardening_db_config/` — Agente `L2.18`: Checkov regras DB + queries de config nativas. Análise estática de schema/migração se sem acesso ao DB
  - **Agente:** backend | **Dependências:** F3.1.1, F3.1.2 | **Critérios:** permissões excessivas, encryption at rest ausente, fail-closed em sem acesso | **Est:** 2.5h
- [ ] **F3.3.3** — `src/layer2_specialists/hardening_db_query/` — Agente `L2.19`: Semgrep regras ORM. Uso inseguro de ORM, queries dinâmicas concatenadas
  - **Agente:** backend | **Dependências:** F3.1.1, F3.1.2 | **Critérios:** detecta SQL injection via ORM bypass, saída JSON | **Est:** 2h
- [ ] **F3.3.4** — `src/layer2_specialists/hardening_infra_terraform/` — Agente `L2.20`: tfsec + Checkov para Terraform
  - **Agente:** backend | **Dependências:** F3.1.1, F3.1.2 | **Critérios:** regras CIS + PCI, IAM excessivo, buckets públicos, saída JSON/SARIF | **Est:** 2h
- [ ] **F3.3.5** — `src/layer2_specialists/hardening_infra_kubernetes/` — Agente `L2.21`: kube-linter + Checkov K8s
  - **Agente:** backend | **Dependências:** F3.1.1, F3.1.2 | **Critérios:** pods privilegiados, network policies ausentes, saída JSON | **Est:** 2h
- [ ] **F3.3.6** — `src/layer2_specialists/hardening_container/` — Agente `L2.22`: Trivy config scan + hadolint
  - **Agente:** backend | **Dependências:** F3.1.1, F3.1.2 | **Critérios:** Dockerfile inseguro, imagem base vulnerável, saída JSON | **Est:** 2h
- [ ] **F3.3.7** — `src/layer2_specialists/hardening_os_cis/` — Agente `L2.23`: OpenSCAP / CIS-CAT scan
  - **Agente:** backend | **Dependências:** F3.1.1, F3.1.2 | **Critérios:** sem acesso ao host → análise contra Dockerfile/AMI definition, saída XML/JSON | **Est:** 2.5h
- [ ] **F3.3.8** — `src/layer2_specialists/hardening_network/` — Agente `L2.24`: Checkov Security Group/NSG
  - **Agente:** backend | **Dependências:** F3.1.1, F3.1.2 | **Critérios:** firewall excessivamente permissivo, saída JSON | **Est:** 2h

### F3.4 — Segredos

- [ ] **F3.4.1** — `src/layer2_specialists/secrets_gitleaks/` — Agente `L2.25`: wrapper gitleaks. Varredura de histórico de commits por credenciais
  - **Agente:** backend | **Dependências:** F3.1.1 | **Critérios:** `--no-git` opcional para scan de arquivo único, saída JSON, falha → bloqueia merge até nova tentativa | **Est:** 2h
- [ ] **F3.4.2** — `src/layer2_specialists/secrets_trufflehog/` — Agente `L2.26`: wrapper truffleHog. Verificação ativa se credencial é válida/viva
  - **Agente:** backend | **Dependências:** F3.1.1 | **Critérios:** `--verify` habilitado, nunca expõe valor do segredo no output, falha → bloqueia merge | **Est:** 2.5h

### F3.5 — Dependências / SBOM / CVE

- [ ] **F3.5.1** — `src/layer2_specialists/sca_sbom/` — Agente `L2.27`: wrapper Syft ou CycloneDX CLI. Gera SBOM a partir do manifesto
  - **Agente:** backend | **Dependências:** F3.1.1 | **Critérios:** manifesto malformado → `"SBOM incompleto"`, nunca omite silenciosamente, saída CycloneDX JSON | **Est:** 2h
- [ ] **F3.5.2** — `src/layer2_specialists/cve_nvd/` — Agente `L2.28`: correlaciona SBOM com CVEs via API NVD. Cache local com timestamp
  - **Agente:** backend | **Dependências:** F3.5.1 | **Critérios:** API indisponível → usa cache local + log, nunca falha silenciosamente, rate limiting NVD | **Est:** 2.5h
- [ ] **F3.5.3** — `src/layer2_specialists/cve_osv/` — Agente `L2.29`: correlaciona SBOM com OSV.dev
  - **Agente:** backend | **Dependências:** F3.5.1 | **Critérios:** batch query para eficiência, cache local, falha explícita | **Est:** 2h
- [ ] **F3.5.4** — `src/layer2_specialists/cve_ghsa/` — Agente `L2.30`: correlaciona SBOM com GitHub Security Advisories
  - **Agente:** backend | **Dependências:** F3.5.1 | **Critérios:** GraphQL API se disponível, cache, falha explícita | **Est:** 2h

### F3.6 — Orquestração Camada 2

- [ ] **F3.6.1** — `src/layer2_specialists/orchestrator/` — Step Functions `ZTKLayer2Orchestrator`: recebe output Camada 1, dispara SAST agents em Parallel (por linguagem detectada), depois Hardening em Parallel, depois Segredos, depois SCA→CVE em sequência, finaliza com L2.16 (Correlator)
  - **Agente:** infra | **Dependências:** F3.1.1–F3.5.4, F0.3.1 | **Critérios:** ativação condicional por linguagem (não dispara Java se código é Python), retry por agente, timeout global 2h, output para `queue_layer3` | **Est:** 4h

### F3.7 — Testes Camada 2

- [ ] **F3.7.1** — `tests/unit/layer2_specialists/` — Testes para framework SAST: executor, parser, correlator. Mocks de subprocess, SARIF fixtures
  - **Agente:** qa | **Dependências:** F3.1.1–F3.1.3 | **Critérios:** cobertura >=85%, testes de timeout, testes de parse error, testes de correlator com LLM mock | **Est:** 4h
- [ ] **F3.7.2** — `tests/integration/layer2_specialists/` — Teste de integração: evento SQS → executor Bandit em container mock → parser → output Finding validado
  - **Agente:** qa | **Dependências:** F3.2.1 | **Critérios:** valida schema Finding, verifica timeout, verifica read-only filesystem | **Est:** 3h
- [ ] **F3.7.3** — `tests/contract/layer2_specialists/` — Contract tests para APIs externas: NVD, OSV, GHSA, TruffleHog verify. Mocks com respostas gravadas (vcr.py)
  - **Agente:** qa | **Dependências:** F3.4.2, F3.5.2–F3.5.4 | **Critérios:** testes contra schemas de resposta reais, detecta breaking changes da API, re-run semanal | **Est:** 3h

---

## FASE 4: CAMADA 3 — VALIDAÇÃO (Reachability, PoC, Fuzzing, Score)

### F4.1 — Reachability

- [ ] **F4.1.1** — `src/layer3_validation/reachability_static/` — Agente `L3.01`: confirma se função vulnerável é chamada no fluxo estático via CodeQL call-graph ou Semgrep taint
  - **Agente:** backend | **Dependências:** F3.1.2, F0.1.1 | **Critérios:** call-graph incompleto → `"reachability estática inconclusiva"`, nunca conclui `"não alcançável"` | **Est:** 3h
- [ ] **F4.1.2** — `src/layer3_validation/reachability_dynamic/` — Agente `L3.02`: instrumenta suíte de testes existente (coverage.py / JaCoCo / Istanbul), observa se caminho vulnerável é exercitado
  - **Agente:** backend | **Dependências:** F4.1.1 | **Critérios:** sem suíte cobrindo área → `"sem evidência dinâmica"`, peso menor no score, nunca executa testes de produção | **Est:** 3h
- [ ] **F4.1.3** — `src/layer3_validation/reachability_config/` — Agente `L3.03`: resolve rotas via configuração (Spring beans, DI containers, rotas declarativas)
  - **Agente:** backend | **Dependências:** F4.1.1 | **Critérios:** parser por framework (Spring, .NET, Flask, FastAPI), framework não suportado → gap explícito registrado | **Est:** 3h

### F4.2 — PoC / Exploit (Sandboxed, por Classe CWE)

- [ ] **F4.2.1** — `src/layer3_validation/poc_framework/` — Framework genérico de execução PoC: container Firecracker/gVisor isolado, sem rede, sem filesystem host, sem dados reais, com TTL de execução
  - **Agente:** backend | **Dependências:** F0.1.7, F0.2.6 | **Critérios:** sandbox com seccomp, gVisor runtime, network namespace isolado, filesystem tmpfs, timeout hard 5min | **Est:** 4h
- [ ] **F4.2.2** — `src/layer3_validation/poc_sqli/` — Agente `L3.04`: payload SQLi real contra banco de teste sintético, confirma exfiltração/alteração
  - **Agente:** backend | **Dependências:** F4.2.1 | **Critérios:** banco 100% sintético (SQLite in-memory ou container Postgres efêmero), nunca dump de produção, confirmação determinística | **Est:** 3h
- [ ] **F4.2.3** — `src/layer3_validation/poc_command_injection/` — Agente `L3.05`: execução de comando real dentro do sandbox, confirma RCE
  - **Agente:** backend | **Dependências:** F4.2.1 | **Critérios:** container sem shell (`/bin/false`), seccomp bloqueia syscalls perigosas, confirmação por arquivo escrito em tmpfs | **Est:** 3h
- [ ] **F4.2.4** — `src/layer3_validation/poc_ssrf/` — Agente `L3.06`: força chamada para endpoint interno controlado (canário), confirma SSRF
  - **Agente:** backend | **Dependências:** F4.2.1 | **Critérios:** rede interna simulada (Docker network isolada), sem rota real para rede corporativa, canário HTTP interno | **Est:** 3h
- [ ] **F4.2.5** — `src/layer3_validation/poc_deserialization/` — Agente `L3.07`: payload de deserialização, confirma execução de código
  - **Agente:** backend | **Dependências:** F4.2.1 | **Critérios:** runtime isolado Firecracker/gVisor, sem persistência, sem rede, confirmação por side-effect controlado | **Est:** 3h
- [ ] **F4.2.6** — `src/layer3_validation/poc_auth_bypass/` — Agente `L3.08`: simula fluxo de autenticação/autorização com credenciais sintéticas
  - **Agente:** backend | **Dependências:** F4.2.1 | **Critérios:** nunca usa credenciais reais, ambiente descartável pós-execução, confirma bypass por status code | **Est:** 2.5h
- [ ] **F4.2.7** — `src/layer3_validation/poc_crypto_weakness/` — Agente `L3.09`: confirma exploitabilidade prática (forjar assinatura, token previsível)
  - **Agente:** backend | **Dependências:** F4.2.1 | **Critérios:** execução limitada por tempo/CPU (cgroup), confirmação por previsão de token | **Est:** 3h
- [ ] **F4.2.8** — `src/layer3_validation/poc_path_traversal/` — Agente `L3.10`: tenta acessar arquivo fora do escopo permitido
  - **Agente:** backend | **Dependências:** F4.2.1 | **Critérios:** filesystem isolado por container, sem montagem real, confirmação por leitura de arquivo canário | **Est:** 2.5h
- [ ] **F4.2.9** — `src/layer3_validation/poc_memory_uaf/` — Agente `L3.11`: executa binário instrumentado (AFL++/libFuzzer + ASan/Valgrind) para confirmar crash/corrupção explorável
  - **Agente:** backend | **Dependências:** F4.2.1 | **Critérios:** VM efêmera dedicada, ASan output parsing, confirmação de crash addressable | **Est:** 3.5h
- [ ] **F4.2.10** — `src/layer3_validation/poc_business_logic_race/` — Agente `L3.12`: cenário concorrente controlado (double-spend, replay transacional, TOCTOU)
  - **Agente:** backend | **Dependências:** F4.2.1 | **Critérios:** staging efêmero, transações sintéticas, confirmação por inconsistência de estado, **prioridade alta (adquirência)** | **Est:** 3.5h

### F4.3 — Fuzzing (Sob HITL)

- [ ] **F4.3.1** — `src/layer3_validation/fuzzing_gateway/handler.py` — Lambda `L3.13`: recebe solicitação humana explícita para campanha de fuzzing. Valida aprovação HITL registrada
  - **Agente:** backend | **Dependências:** F2.4.1, F0.1.3 | **Critérios:** sem aprovação registrada → HTTP 403, sem exceção, cria registro de solicitação em `HITLQueue` | **Est:** 2h
- [ ] **F4.3.2** — `src/layer3_validation/fuzzing_harness_builder/` — Agente `L3.14`: constrói harness de fuzzing (AFL++, libFuzzer, OSS-Fuzz templates)
  - **Agente:** backend | **Dependências:** F4.3.1 | **Critérios:** alvo não harness-ável → escala para engenharia manual, output: harness file + comando de execução | **Est:** 3h
- [ ] **F4.3.3** — `src/layer3_validation/fuzzing_executor/` — Agente `L3.15`: executa campanha com orçamento de tempo/CPU definido pelo solicitante
  - **Agente:** backend | **Dependências:** F4.3.2, F4.2.1 | **Critérios:** VM/container efêmero dedicado (Firecracker), sem rede, teto de tempo atingido → encerra e reporta parcial, exige nova aprovação | **Est:** 3h
- [ ] **F4.3.4** — `src/layer3_validation/fuzzing_crash_triage/` — Agente `L3.16`: classifica crashes (explorável vs não-explorável) via GDB/WinDbg + ASan
  - **Agente:** backend | **Dependências:** F4.3.3 | **Critérios:** classificação inconclusiva → `"requer triagem manual de engenharia"`, output: `CrashClassification` | **Est:** 3h

### F4.4 — Score de Evidência

- [ ] **F4.4.1** — `src/layer3_validation/evidence_aggregator/service.py` — Serviço `L3.17`: coleta todas as evidências de L2 e L3.01–L3.16 por finding
  - **Agente:** backend | **Dependências:** F3.1.2, F4.1.1–F4.3.4 | **Critérios:** estrutura normalizada de evidência (tipo, peso, valor, timestamp), nunca descarta evidência | **Est:** 2.5h
- [ ] **F4.4.2** — `src/layer3_validation/scoring_engine/service.py` — Serviço `L3.18`: calcula score final ponderado por finding conforme tabela de pesos da arquitetura
  - **Agente:** backend | **Dependências:** F4.4.1 | **Critérios:** implementação determinística (sem LLM), faixas de decisão: ≥8 confirmado, 4-7 zona cinzenta, 1-3 observação, ≤0 falso positivo | **Est:** 2.5h

### F4.5 — Orquestração Camada 3

- [ ] **F4.5.1** — `src/layer3_validation/orchestrator/` — Step Functions `ZTKLayer3Orchestrator`: sequência L3.01→L3.02→L3.03 (Parallel opcional), depois PoC agents em Parallel (por CWE detectada em L2), depois fuzzing (se HITL aprovado), finaliza com L3.17+L3.18
  - **Agente:** infra | **Dependências:** F4.1.1–F4.4.2 | **Critérios:** PoC só dispara para CWEs presentes nos findings, fuzzing gateway é Choice (não automático), timeout 4h | **Est:** 4h

### F4.6 — Testes Camada 3

- [ ] **F4.6.1** — `tests/unit/layer3_validation/` — Testes para scoring engine (matriz de pesos), evidence aggregator, reachability services
  - **Agente:** qa | **Dependências:** F4.4.1, F4.4.2 | **Critérios:** cobertura >=85%, testes de todas as combinações de peso, testes de faixas de decisão | **Est:** 4h
- [ ] **F4.6.2** — `tests/integration/layer3_validation/` — Teste de integração: evento de finding → reachability → scoring → output com score validado
  - **Agente:** qa | **Dependências:** F4.5.1 | **Critérios:** valida score ≥8, score 4-7, score ≤0, idempotência | **Est:** 3h
- [ ] **F4.6.3** — `tests/security/layer3_validation/` — Testes de segurança do sandbox: confirma isolamento (sem rede, sem host fs), escape attempts
  - **Agente:** security-ops | **Dependências:** F4.2.1 | **Critérios:** tentativa de breakout documentada e bloqueada, container escape test, network isolation test | **Est:** 4h

---

## FASE 5: CAMADA 4 — CONSENSO / DEBATE (Severidade)

### F5.1 — Scoring Técnico Determinístico

- [ ] **F5.1.1** — `src/layer4_consensus/cvss_calculator/service.py` — Serviço `L4.01`: calcula CVSS v4.0 oficial (FIRST.org). Fórmula pura, sem chamada externa
  - **Agente:** backend | **Dependências:** F0.1.1 | **Critérios:** vetor incompleto → marca campo faltante, nunca assume default, output: `CVSSScore` com `base_score`, `vector_string` | **Est:** 2.5h
- [ ] **F5.1.2** — `src/layer4_consensus/epss_correlator/service.py` — Serviço `L4.02`: consulta API EPSS (FIRST.org). Cache local com timestamp visível
  - **Agente:** backend | **Dependências:** F5.1.1 | **Critérios:** API indisponível → último valor cache + timestamp, rate limiting, nunca bloqueia pipeline por indisponibilidade | **Est:** 2.5h
- [ ] **F5.1.3** — `src/layer4_consensus/ssvc_decision_tree/service.py` — Serviço `L4.03`: aplica árvore de decisão SSVC oficial (Exploitation × Exposure × Mission Impact)
  - **Agente:** backend | **Dependências:** F5.1.1, F5.1.2 | **Critérios:** insumo faltante → força ramo mais conservador, implementação determinística, `rationale` obrigatório | **Est:** 3h
- [ ] **F5.1.4** — `src/layer4_consensus/business_severity_adjuster/service.py` — Serviço `L4.04`: combina CVSS+EPSS+SSVC com criticidade de negócio (L1.04)
  - **Agente:** backend | **Dependências:** F5.1.3, F1.1.4 | **Critérios:** criticidade desconhecida → ajuste conservador (trata como crítico), matriz documentada em código | **Est:** 2h

### F5.2 — Piso de Severidade Não-Negociável

- [ ] **F5.2.1** — `src/layer4_consensus/severity_floor_pci/service.py` — Serviço `L4.05`: aplica piso mínimo P1 para armazenamento/transmissão/processamento de CHD
  - **Agente:** backend | **Dependências:** F5.1.4, F0.3.3 | **Critérios:** debate não pode descer abaixo de P1, override só via L6.05–L6.09 (four-eyes), teste com finding PCI | **Est:** 1.5h
- [ ] **F5.2.2** — `src/layer4_consensus/severity_floor_lgpd/service.py` — Serviço `L4.06`: aplica piso mínimo P1 para dado pessoal sensível (Art. 5º LGPD)
  - **Agente:** backend | **Dependências:** F5.1.4, F0.3.3 | **Critérios:** mesmo comportamento de L4.05, detector de dados sensíveis via regex/heurística ou tag explícita | **Est:** 1.5h
- [ ] **F5.2.3** — `src/layer4_consensus/severity_floor_antifraude/service.py` — Serviço `L4.07`: aplica piso mínimo P0 para fluxo de autorização, validação de saldo, lógica antifraude
  - **Agente:** backend | **Dependências:** F5.1.4, F0.3.3 | **Critérios:** piso mais alto do sistema, nenhum override automático, trigger por palavras-chave de domínio (auth, transaction, balance) | **Est:** 1.5h
- [ ] **F5.2.4** — `src/layer4_consensus/floor_override_gate/service.py` — Serviço `L4.08`: valida que override de piso só ocorre via L6.05–L6.09 (four-eyes documentado)
  - **Agente:** governance | **Dependências:** F5.2.1–F5.2.3, F2.2.1–F2.2.4 | **Critérios:** nega qualquer tentativa de override sem four-eyes aprovado, audit event obrigatório | **Est:** 1.5h

### F5.3 — Debate Adversarial (Zona Cinzenta: Score 4–7)

- [ ] **F5.3.1** — `src/layer4_consensus/debater_prosecutor/service.py` — Serviço `L4.09`: LLM enviesado para "atacar". Argumenta que finding É explorável e severo
  - **Agente:** backend | **Dependências:** F5.1.4, F7.1.1 | **Critérios:** prompt engineering propositalmente enviesado, nunca inventa evidência (só usa dados de L3), output: `ProsecutorOpinion` | **Est:** 3h
- [ ] **F5.3.2** — `src/layer4_consensus/debater_defender/service.py` — Serviço `L4.10`: LLM enviesado para "defender". Argumenta mitigação, contexto que reduz risco, falso positivo
  - **Agente:** backend | **Dependências:** F5.1.4, F7.1.1 | **Critérios:** mesmo padrão de L4.09, output: `DefenderOpinion` | **Est:** 3h
- [ ] **F5.3.3** — `src/layer4_consensus/judge_consensus/service.py` — Serviço `L4.11`: modera debate, pondera contra score e pisos, emite severidade final com justificativa escrita
  - **Agente:** backend | **Dependências:** F5.3.1, F5.3.2, F5.2.1–F5.2.4 | **Critérios:** NUNCA emite severidade abaixo do piso aplicável, justificativa obrigatória (mínimo 50 palavras), output: `ConsensusDecision` | **Est:** 3.5h

### F5.4 — Resolução de Divergência

- [ ] **F5.4.1** — `src/layer4_consensus/divergence_detector/service.py` — Serviço `L4.12`: compara score determinístico (Camada 3) com conclusão do Judge
  - **Agente:** backend | **Dependências:** F5.3.3, F4.4.2 | **Critérios:** automático após debate, detecta discordância de faixa de severidade (ex: score≥8 mas Judge diz P3) | **Est:** 2h
- [ ] **F5.4.2** — `src/layer4_consensus/hitl_escalation_gateway/service.py` — Serviço `L4.13`: escala para humano quando há divergência significativa. Bloqueia avanço automático
  - **Agente:** governance | **Dependências:** F5.4.1, F2.4.1 | **Critérios:** cria item em `HITLQueue` com prioridade máxima, notifica imediatamente, pipeline pausa para este finding | **Est:** 2h
- [ ] **F5.4.3** — `src/layer4_consensus/final_priority_assigner/service.py` — Serviço `L4.14`: atribui prioridade final P0–P4 após resolução
  - **Agente:** backend | **Dependências:** F5.4.1, F5.4.2 | **Critérios:** deterministic mapping de severidade para prioridade, output: `FinalPriority` com `sla_hours` | **Est:** 1.5h

### F5.5 — Orquestração Camada 4

- [ ] **F5.5.1** — `src/layer4_consensus/orchestrator/` — Step Functions `ZTKLayer4Orchestrator`: sequência L4.01→L4.02→L4.03→L4.04 (Parallel L4.01-L4.03), depois Choice (score≥8 ou ≤0: skip debate), depois Parallel L4.09+L4.10 (debate), depois L4.11 (Judge), depois L4.12+L4.13, finaliza L4.14
  - **Agente:** infra | **Dependências:** F5.1.1–F5.4.3 | **Critérios:** debate só acionado para score 4-7, skip determinístico para ≥8 e ≤0, timeout 30min por debate | **Est:** 4h

### F5.6 — Testes Camada 4

- [ ] **F5.6.1** — `tests/unit/layer4_consensus/` — Testes para CVSS calculator (vetores conhecidos), EPSS correlator (mock), SSVC tree (todos os ramos), business adjuster, divergence detector
  - **Agente:** qa | **Dependências:** F5.1.1–F5.4.3 | **Critérios:** cobertura >=85%, testes de todos os ramos SSVC, testes de pisos (PCI/LGPD/Antifraude), testes de debate mock | **Est:** 4h
- [ ] **F5.6.2** — `tests/integration/layer4_consensus/` — Teste: finding com score 6 → debate mock → judge → priority assignment. Valida justificativa e piso
  - **Agente:** qa | **Dependências:** F5.5.1 | **Critérios:** valida que piso nunca é violado, verifica HITL escalation em divergência | **Est:** 3h

---

## FASE 6: CAMADA 5 — REMEDIAÇÃO (Trilha A + Trilha B)

### F6.1 — Gatilho Comum

- [ ] **F6.1.1** — `src/layer5_remediation/remediation_dispatcher/handler.py` — Lambda `L5.01`: recebe finding P0/P1, dispara Trilha A e B em paralelo (Parallel no Step Functions)
  - **Agente:** backend | **Dependências:** F5.4.3, F0.3.1 | **Critérios:** falha ao disparar uma trilha → alerta imediato, nunca silenciosa, retry 3x por trilha | **Est:** 2h

### F6.2 — Trilha A: Fix Definitivo (Código-Fonte)

- [ ] **F6.2.1** — `src/layer5_remediation/patch_generator/service.py` — Serviço `L5.02`: gera diff de correção por linguagem. Input: finding + contexto AST. Usa LLM (ensemble se Camada 7 disponível)
  - **Agente:** backend | **Dependências:** F6.1.1, F7.1.1 | **Critérios:** prompt inclui CWE, linguagem, linha afetada, nunca gera código sem contexto, output: `PatchCandidate` | **Est:** 3.5h
- [ ] **F6.2.2** — `src/layer5_remediation/patch_sandbox_validator/service.py` — Serviço `L5.03`: aplica patch em branch isolada, roda build + testes + linters
  - **Agente:** backend | **Dependências:** F6.2.1 | **Critérios:** teste falha → volta ao gerador (máx. 3 tentativas), depois escala engenharia humana, sandbox container efêmero | **Est:** 3h
- [ ] **F6.2.3** — `src/layer5_remediation/patch_regression_guard/service.py` — Serviço `L5.04`: confirma que patch não altera comportamento fora do escopo. Diff semântico + re-scan focado (Camada 2)
  - **Agente:** backend | **Dependências:** F6.2.2, F3.1.1 | **Critérios:** novo finding introduzido → rejeita automaticamente, comparação AST-level (não apenas texto) | **Est:** 3h
- [ ] **F6.2.4** — `src/layer5_remediation/pr_publisher/service.py` — Serviço `L5.05`: abre PR com diff, evidências e justificativa do Judge
  - **Agente:** backend | **Dependências:** F6.2.3 | **Critérios:** descrição do PR inclui `finding_id`, severidade, evidências, link para auditoria, template de PR versionado | **Est:** 2.5h
- [ ] **F6.2.5** — `src/layer5_remediation/merge_guardrail/service.py` — Serviço `L5.06`: bloqueia merge automático em P0/P1
  - **Agente:** governance | **Dependências:** F6.2.4, F2.1.1 | **Critérios:** branch protection + status check obrigatório, P0/P1 → PR travado até aprovação humana nomeada, sem exceção | **Est:** 2h

### F6.3 — Trilha B: Contenção em Runtime (WAF/Firewall)

- [ ] **F6.3.1** — `src/layer5_remediation/containment_template_selector/service.py` — Serviço `L5.07`: seleciona template validado por classe de CWE
  - **Agente:** backend | **Dependências:** F6.1.1, F0.3.5 | **Critérios:** CWE sem template → não aplica regra, escala HITL imediato, templates versionados em S3/Git | **Est:** 2h
- [ ] **F6.3.2** — `src/layer5_remediation/containment_confidence_gate/service.py` — Serviço `L5.08`: decide full-auto vs HITL rápido. PoC confirmado (score ≥8) → full-auto; sem PoC → HITL
  - **Agente:** backend | **Dependências:** F6.3.1, F4.4.2 | **Critérios:** determinístico, ambíguo → default HITL, nunca aplica sem confirmação explícita | **Est:** 1.5h
- [ ] **F6.3.3** — `src/layer5_remediation/containment_dryrun/service.py` — Serviço `L5.09`: testa regra contra replay de tráfego real recente
  - **Agente:** backend | **Dependências:** F6.3.2 | **Critérios:** logs recentes (últimas 24h) + engine de replay, bloqueia tráfego legítimo → não aplica, escala HITL | **Est:** 3h
- [ ] **F6.3.4** — `src/layer5_remediation/containment_deploy_f5/service.py` — Serviço `L5.10`: aplica regra validada no F5 (AFM/ASM) via iControl REST
  - **Agente:** backend | **Dependências:** F6.3.3 | **Critérios:** API com retry + backoff, rollback automático em falha de health check, dry-run antes de apply | **Est:** 2.5h
- [ ] **F6.3.5** — `src/layer5_remediation/containment_deploy_akamai/service.py` — Serviço `L5.11`: aplica regra no Akamai (Kona/App & API Protector)
  - **Agente:** backend | **Dependências:** F6.3.3 | **Critérios:** Akamai {OPEN} API, activation em staging antes de production, rollback | **Est:** 2.5h
- [ ] **F6.3.6** — `src/layer5_remediation/containment_deploy_azure_waf/service.py` — Serviço `L5.12`: aplica regra no Azure WAF (Application Gateway / Front Door)
  - **Agente:** backend | **Dependências:** F6.3.3 | **Critérios:** Azure ARM API, config versionada, rollback via deployment slots | **Est:** 2.5h
- [ ] **F6.3.7** — `src/layer5_remediation/containment_ttl_manager/service.py` — Serviço `L5.13`: define expiração automática conforme SLA (alinhado PCI DSS 6.3.3). Renova se Trilha A não mergeou
  - **Agente:** backend | **Dependências:** F6.3.4–F6.3.6, F6.2.5 | **Critérios:** TTL configurável por severidade, renovação automática por ciclo adicional, alerta em cada renovação | **Est:** 2h
- [ ] **F6.3.8** — `src/layer5_remediation/containment_audit_logger/service.py` — Serviço `L5.14`: registra finding de origem, template, dry-run, timestamps, vendor
  - **Agente:** backend | **Dependências:** F6.3.7, F2.3.1 | **Critérios:** append-only, `finding_id` correlacionável, vendor + rule_id + timestamp aplicado/removido | **Est:** 1.5h

### F6.4 — Kill Switch e Escalação SLA

- [ ] **F6.4.1** — `src/layer5_remediation/emergency_kill_switch/handler.py` — Lambda `L5.15`: remove imediatamente qualquer regra de contenção ativa em qualquer vendor. Autoridade: time SOC
  - **Agente:** security-ops | **Dependências:** F6.3.4–F6.3.6, F2.4.1 | **Critérios:** acionamento restrito a role IAM `SOC_Emergency`, gera alerta + audit event imediato, rollback em <60s | **Est:** 2.5h
- [ ] **F6.4.2** — `src/layer5_remediation/post_kill_switch_notifier/service.py` — Serviço `L5.16`: notifica owner do serviço + segurança após kill switch
  - **Agente:** security-ops | **Dependências:** F6.4.1, F2.4.2 | **Critérios:** notificação via Slack/PagerDuty/e-mail, inclui finding_id e timestamp do kill switch | **Est:** 1.5h
- [ ] **F6.4.3** — `src/layer5_remediation/sla_breach_escalator/service.py` — Serviço `L5.17`: monitora renovações de TTL sem merge da Trilha A, escala progressivamente
  - **Agente:** governance | **Dependências:** F6.3.7, F6.2.5 | **Critérios:** política de escalação em camadas (1ª: owner, 2ª: eng manager, 3ª: CISO, 4ª+: C-level), notificação automática | **Est:** 2.5h

### F6.5 — Orquestração Camada 5

- [ ] **F6.5.1** — `src/layer5_remediation/orchestrator/` — Step Functions `ZTKLayer5Orchestrator`: L5.01 (Parallel: Trilha A + Trilha B). Trilha A: L5.02→L5.03→L5.04→L5.05→L5.06. Trilha B: L5.07→L5.08→L5.09→(Choice vendor)→L5.10/11/12→L5.13→L5.14. Wait states para TTL check
  - **Agente:** infra | **Dependências:** F6.1.1–F6.4.3 | **Critérios:** Parallel com error handling independente, Trilha A falha não para Trilha B, wait state para TTL renovação | **Est:** 5h

### F6.6 — Testes Camada 5

- [ ] **F6.6.1** — `tests/unit/layer5_remediation/` — Testes para patch generator (mock LLM), sandbox validator (mock build), regression guard, containment selector, confidence gate, TTL manager
  - **Agente:** qa | **Dependências:** F6.2.1–F6.4.3 | **Critérios:** cobertura >=85%, testes de retry (3x), testes de TTL renovação, testes de kill switch autoridade | **Est:** 4h
- [ ] **F6.6.2** — `tests/integration/layer5_remediation/` — Teste: finding P0 → dispatcher → Trilha A (patch mock) + Trilha B (template mock) → valida TTL e auditoria
  - **Agente:** qa | **Dependências:** F6.5.1 | **Critérios:** valida paralelismo, verifica que Trilha B não depende de Trilha A, confirma audit events | **Est:** 3h
- [ ] **F6.6.3** — `tests/e2e/remediation_flow.py` — E2E: finding P1 → pipeline completo até PR aberto + contenção aplicada → kill switch → valida estado final
  - **Agente:** qa | **Dependências:** F6.5.1, F6.4.1 | **Critérios:** Step Functions local (moto), valida PR description, confirma kill switch gera audit event | **Est:** 4h

---

## FASE 7: CAMADA 7 — MODEL ENSEMBLE (Roteamento LLM)

### F7.1 — Roteamento por Escopo e Tier

- [ ] **F7.1.1** — `src/layer7_model_ensemble/data_scope_classifier/service.py` — Serviço `L7.01`: consulta L1.04 para saber se repositório/finding toca CHD/PII
  - **Agente:** backend | **Dependências:** F1.1.4, F0.1.4 | **Critérios:** criticidade `"desconhecida"` → trata como escopo PCI, força roteamento local, nunca fallback para Bedrock | **Est:** 1.5h
- [ ] **F7.1.2** — `src/layer7_model_ensemble/model_router/service.py` — Serviço `L7.02`: decide, por chamada, roteamento local vs Bedrock, com base em L7.01 + tier de tarefa
  - **Agente:** backend | **Dependências:** F7.1.1 | **Critérios:** lookup table determinística (não LLM), input: `LLMRequest`, output: `ModelAssignment` (provider, model_id, endpoint) | **Est:** 2h
- [ ] **F7.1.3** — `src/layer7_model_ensemble/task_tier_classifier/service.py` — Serviço `L7.03`: classifica cada chamada por tier: Volume/Triagem, Reasoning/Debate, Geração de Código
  - **Agente:** backend | **Dependências:** F7.1.2 | **Critérios:** heurística determinística (tokens estimados, complexidade da tarefa), nunca usa LLM para classificar | **Est:** 1.5h

### F7.2 — Infraestrutura Local (vLLM)

- [ ] **F7.2.1** — `src/layer7_model_ensemble/local_inference_cluster/` — Serviço `L7.04`: cliente vLLM para inference local. Health check, queue management, batching
  - **Agente:** backend | **Dependências:** F0.2.7, F7.1.2 | **Critérios:** conexão via HTTP para vLLM em EC2 GPU, health check a cada 30s, fallback para Bedrock NUNCA se escopo PCI | **Est:** 3h
- [ ] **F7.2.2** — `src/layer7_model_ensemble/local_model_frontier/` — Serviço `L7.05`: modelo local de maior capacidade. Load model AWQ, gerencia VRAM
  - **Agente:** backend | **Dependências:** F7.2.1 | **Critérios:** carrega modelo sob demanda (não preload se ocioso), unload após timeout de inatividade, GPU memory monitor | **Est:** 3h
- [ ] **F7.2.3** — `src/layer7_model_ensemble/local_model_distilled/` — Serviço `L7.06`: modelo local menor/mais rápido para volume alto
  - **Agente:** backend | **Dependências:** F7.2.1 | **Critérios:** menor latência, menor VRAM, usado para tier Volume, mesma família do frontier (para consistência) | **Est:** 2.5h
- [ ] **F7.2.4** — `src/layer7_model_ensemble/local_gpu_autoscaler/` — Serviço `L7.07`: escala GPU nodes conforme fila, desliga quando ocioso
  - **Agente:** infra | **Dependências:** F0.2.7, F7.2.1 | **Critérios:** scaling baseado em SQS queue depth do `queue_llm_local`, scale-in quando queue vazia por 15min, nunca desliga durante processamento ativo | **Est:** 3h

### F7.3 — Infraestrutura Comercial (Bedrock)

- [ ] **F7.3.1** — `src/layer7_model_ensemble/bedrock_frontier/` — Serviço `L7.08`: cliente AWS Bedrock para Claude Sonnet/Opus. Retry, streaming, guardrails
  - **Agente:** backend | **Dependências:** F0.2.9, F7.1.2 | **Critérios:** invoke com guardrails, streaming opcional, retry exponencial, nunca envia dados PCI | **Est:** 2.5h
- [ ] **F7.3.2** — `src/layer7_model_ensemble/bedrock_distilled/` — Serviço `L7.09`: cliente Bedrock para Claude Haiku. Volume alto, custo mínimo
  - **Agente:** backend | **Dependências:** F7.3.1 | **Critérios:** batch processing quando possível, caching de respostas por content hash, rate limiting | **Est:** 2h
- [ ] **F7.3.3** — `src/layer7_model_ensemble/bedrock_guardrails/` — Serviço `L7.10`: camada extra de proteção contra prompt injection (reforça L1.03)
  - **Agente:** backend | **Dependências:** F7.3.1 | **Critérios:** filtro de input adicional antes de envio Bedrock, bloqueia padrões suspeitos, log de interceptação | **Est:** 2h

### F7.4 — Ensemble/Voting (Patch Generator)

- [ ] **F7.4.1** — `src/layer7_model_ensemble/patch_ensemble_orchestrator/service.py` — Serviço `L7.11`: envia mesma tarefa de patch para dois modelos independentes
  - **Agente:** backend | **Dependências:** F7.2.2, F7.3.1 | **Critérios:** escopo PCI → ambos locais, não-PCI → pode mixar, nunca um vai para Bedrock se outro é local e escopo PCI | **Est:** 2.5h
- [ ] **F7.4.2** — `src/layer7_model_ensemble/patch_diff_comparator/service.py` — Serviço `L7.12`: compara dois patches (diff semântico, AST-level)
  - **Agente:** backend | **Dependências:** F7.4.1 | **Critérios:** convergem → segue fluxo normal, divergem → ambos para sandbox (L5.03), se ambos passam mas diferentes → HITL | **Est:** 3h

### F7.5 — Circuit Breaker de Custo

- [ ] **F7.5.1** — `src/layer7_model_ensemble/cost_metering/service.py` — Serviço `L7.13`: mede custo por chamada (tokens × preço, + GPU-hora local)
  - **Agente:** backend | **Dependências:** F7.1.2 | **Critérios:** sempre ativo, alimenta `CostMetrics` (DynamoDB), granularity por `tenant_id`, `agent_id`, `tier` | **Est:** 2.5h
- [ ] **F7.5.2** — `src/layer7_model_ensemble/cost_budget_circuit_breaker/service.py` — Serviço `L7.14`: compara gasto acumulado contra teto configurado
  - **Agente:** governance | **Dependências:** F7.5.1, F0.3.7 | **Critérios:** 80% → alerta, 100% → pausa chamadas de tier caro (nunca HITL/kill switch/contenção), política de prioridade de corte configurável | **Est:** 2.5h
- [ ] **F7.5.3** — `src/layer7_model_ensemble/cost_cache_layer/service.py` — Serviço `L7.15`: cache semântico (reusa L1.07) para não reprocessar arquivo/finding sem mudança
  - **Agente:** backend | **Dependências:** F7.5.1, F1.1.7 | **Critérios:** lookup por `content_hash`, TTL configurável, hit/miss metrics para CloudWatch | **Est:** 2h

### F7.6 — Orquestração Camada 7

- [ ] **F7.6.1** — `src/layer7_model_ensemble/orchestrator/` — Step Functions `ZTKLayer7Router`: recebe `LLMRequest`, executa L7.01→L7.02→L7.03, despacha para provider adequado. Parallel para ensemble (L7.11) quando aplicável
  - **Agente:** infra | **Dependências:** F7.1.1–F7.5.3 | **Critérios:** routing table versionada, nunca roteia PCI para Bedrock, timeout por tier, fallback conservador | **Est:** 3h

### F7.7 — Testes Camada 7

- [ ] **F7.7.1** — `tests/unit/layer7_model_ensemble/` — Testes para router (tabela de routing), cost metering (cálculo de tokens), cache layer, guardrails
  - **Agente:** qa | **Dependências:** F7.1.1–F7.5.3 | **Critérios:** cobertura >=85%, testes de roteamento PCI→Local, testes de circuit breaker (100% budget), testes de cache hit/miss | **Est:** 4h
- [ ] **F7.7.2** — `tests/integration/layer7_model_ensemble/` — Teste: LLMRequest com data_scope=PCI → valida que assignment é LOCAL, nunca Bedrock
  - **Agente:** qa | **Dependências:** F7.6.1 | **Critérios:** teste de integração com moto (DynamoDB), valida schema de assignment, verifica negativa de Bedrock | **Est:** 2h
- [ ] **F7.7.3** — `tests/security/layer7_model_ensemble/` — Teste de segurança: tentativa de forçar roteamento PCI para Bedrock via manipulação de input
  - **Agente:** security-ops | **Dependências:** F7.6.1 | **Critérios:** input malicioso → rejeição com log, nunca chega a Bedrock, valida com 3 vetores de ataque | **Est:** 3h

---

## FASE 8: CAMADA 8 — ESCALA E ESPECIALIZAÇÃO

### F8.1 — Ativação Condicional

- [ ] **F8.1.1** — `src/layer8_scale/monorepo_module_mapper/service.py` — Serviço `L8.01`: mapeia módulos/diretórios para linguagem/stack específica
  - **Agente:** backend | **Dependências:** F1.1.2 | **Critérios:** módulo não identificável → análise completa SÓ nesse módulo (custo extra só onde há incerteza), nunca ignora módulo | **Est:** 2h
- [ ] **F8.1.2** — `src/layer8_scale/scoped_activation_engine/service.py` — Serviço `L8.02`: ativa agentes Camada 2 por módulo, não por repositório inteiro
  - **Agente:** backend | **Dependências:** F8.1.1 | **Critérios:** mapa de ativação: módulo → lista de agentes, evita ativação indiscriminada em monorepo poliglota | **Est:** 2h
- [ ] **F8.1.3** — `src/layer8_scale/criticality_weighted_depth/service.py` — Serviço `L8.03`: módulos críticos recebem profundidade maior; não-críticos, análise leve
  - **Agente:** backend | **Dependências:** F8.1.2, F1.1.4 | **Critérios:** criticidade desconhecida → profundidade máxima, configurável por tenant | **Est:** 1.5h

### F8.2 — Ciclo de Vida de Ferramentas

- [ ] **F8.2.1** — `src/layer8_scale/tool_version_monitor/service.py` — Serviço `L8.04`: monitora releases/updates de cada ferramenta usada (GitHub API, RSS, etc.)
  - **Agente:** backend | **Dependências:** F3.1.1 | **Critérios:** sem update checado há >90 dias → alerta para o time, nunca assume `"está tudo bem"`, registry de tools em DynamoDB | **Est:** 2.5h
- [ ] **F8.2.2** — `src/layer8_scale/tool_update_pr_generator/service.py` — Serviço `L8.05`: abre PR automático de atualização, reusa pipeline de patch (sandbox, teste, PR)
  - **Agente:** backend | **Dependências:** F8.2.1, F6.2.1–F6.2.5 | **Critérios:** update quebra testes → PR fica com CI vermelho, time decide, nunca merge automático | **Est:** 2.5h
- [ ] **F8.2.3** — `src/layer8_scale/tool_ownership_registry/service.py` — Serviço `L8.06`: registro formal de dono por ferramenta dentro do time de Platform
  - **Agente:** governance | **Dependências:** F8.2.1 | **Critérios:** ferramenta sem dono → bloqueia entrada em produção, alerta mensal de ferramentas órfãs | **Est:** 1.5h

### F8.3 — Onboarding de Novo Agente

- [ ] **F8.3.1** — `src/layer8_scale/agent_onboarding_gate/service.py` — Serviço `L8.07`: ponto único de entrada para propor novo agente. Valida dependência técnica, fail-closed, dono explícito
  - **Agente:** governance | **Dependências:** F2.1.1 | **Critérios:** proposta sem dependência/fail-closed/dono → rejeitada, template de proposta versionado | **Est:** 2h
- [ ] **F8.3.2** — `src/layer8_scale/agent_policy_registration/service.py` — Serviço `L8.08`: registra agente no Policy Engine (L6.01)
  - **Agente:** governance | **Dependências:** F8.3.1, F2.1.1 | **Critérios:** sem política registrada → não opera nem em shadow, schema de registro versionado | **Est:** 1.5h
- [ ] **F8.3.3** — `src/layer8_scale/agent_shadow_mode_runner/service.py` — Serviço `L8.09`: roda agente em paralelo, sem influenciar severidade/patch/contenção
  - **Agente:** backend | **Dependências:** F8.3.2 | **Critérios:** tentativa de escrever em decisão real → bloqueada estruturalmente (read-only output), log completo para avaliação | **Est:** 2.5h
- [ ] **F8.3.4** — `src/layer8_scale/agent_shadow_evaluator/service.py` — Serviço `L8.10`: compara resultado do agente em shadow contra baseline em produção
  - **Agente:** backend | **Dependências:** F8.3.3 | **Critérios:** comparação por métricas objetivas (precision, recall, F1), período mínimo 30 dias, resultado ruim → não promove | **Est:** 2.5h
- [ ] **F8.3.5** — `src/layer8_scale/agent_production_promoter/service.py` — Serviço `L8.11`: move para produção somente após aprovação humana + revisão Camada 6
  - **Agente:** governance | **Dependências:** F8.3.4, F2.1.3 | **Critérios:** sem aprovação explícita → permanece em shadow indefinidamente, gera `AuditEvent` na promoção | **Est:** 2h

### F8.4 — Multi-Tenancy

- [ ] **F8.4.1** — `src/layer8_scale/tenant_context_tag/service.py` — Serviço `L8.12`: toda execução carrega `tenant_id`
  - **Agente:** backend | **Dependências:** F0.1.1 | **Critérios:** hoje: valor fixo `"ztk-default"`, propagado em todos os schemas, futuro: isolamento sem migração | **Est:** 1h
- [ ] **F8.4.2** — `src/layer8_scale/tenant_policy_override/service.py` — Serviço `L8.13`: permite política diferente por tenant (ex: nunca usar Bedrock para cliente X)
  - **Agente:** governance | **Dependências:** F8.4.1, F2.1.1 | **Critérios:** hoje: sem efeito (default), futuro: ativa por contrato, schema preparado | **Est:** 1.5h
- [ ] **F8.4.3** — `src/layer8_scale/tenant_cost_isolator/service.py` — Serviço `L8.14`: segrega métricas de custo e cache por tenant
  - **Agente:** backend | **Dependências:** F8.4.1, F7.5.1 | **Critérios:** hoje: partição única, métricas com `tenant_id` tag, futuro: budget independente | **Est:** 1.5h
- [ ] **F8.4.4** — `src/layer8_scale/tenant_data_isolation_guard/service.py` — Serviço `L8.15`: garante que dado/código de um tenant nunca vaza para outro
  - **Agente:** security-ops | **Dependências:** F8.4.1 | **Critérios:** hoje: trivial (1 tenant), valida que `tenant_id` nunca é alterado em trânsito, futuro: VPC separada | **Est:** 2h

### F8.5 — Testes Camada 8

- [ ] **F8.5.1** — `tests/unit/layer8_scale/` — Testes para ativação condicional (monorepo mock), tool version monitor, shadow mode, tenant context
  - **Agente:** qa | **Dependências:** F8.1.1–F8.4.4 | **Critérios:** cobertura >=85%, testes de shadow mode (tentativa de escrita bloqueada), testes de tenant isolation | **Est:** 3h

---

## FASE 9: INTERFACE DE EXCEÇÕES (Frontend + Backend)

### F9.1 — Backend API

- [ ] **F9.1.1** — `interface_excecoes/backend/src/api_gateway/` — API Gateway + Lambda handlers para: listar exceções pendentes, aprovar/rejeitar (four-eyes), timeline de auditoria, dashboard SLA, kill switch
  - **Agente:** backend | **Dependências:** F2.2.1, F2.4.1, F6.4.1 | **Critérios:** JWT auth (Cognito ou similar), rate limiting, input validation strict, nunca expõe stack trace | **Est:** 4h
- [ ] **F9.1.2** — `interface_excecoes/backend/src/services/exception_service.py` — Serviço de domínio para fila de exceções
  - **Agente:** backend | **Dependências:** F9.1.1 | **Critérios:** paginação, filtros (status, severidade, tenant), ordenação por urgência | **Est:** 2.5h
- [ ] **F9.1.3** — `interface_excecoes/backend/src/services/audit_timeline_service.py` — Serviço de timeline de auditoria por `finding_id`
  - **Agente:** backend | **Dependências:** F9.1.1, F2.3.1 | **Critérios:** agregação de eventos por `finding_id`, ordenação cronológica, links para S3 | **Est:** 2h

### F9.2 — Frontend Web

- [ ] **F9.2.1** — `interface_excecoes/frontend/src/pages/dashboard.tsx` — Dashboard principal: findings por severidade, tempo de resposta, fila HITL, SLA estourado
  - **Agente:** frontend | **Dependências:** F9.1.1 | **Critérios:** React/Next.js, SSR opcional, dados via API, refresh automático a cada 60s | **Est:** 3h
- [ ] **F9.2.2** — `interface_excecoes/frontend/src/pages/exceptions.tsx` — Página de fila de exceções pendentes (four-eyes)
  - **Agente:** frontend | **Dependências:** F9.2.1 | **Critérios:** listagem com filtros, botão aprovar/rejeitar com justificativa obrigatória (modal), confirmação dupla | **Est:** 3h
- [ ] **F9.2.3** — `interface_excecoes/frontend/src/pages/audit.tsx` — Timeline de auditoria por `finding_id`
  - **Agente:** frontend | **Dependências:** F9.2.1 | **Critérios:** timeline vertical com eventos, cores por stage, link para evidência bruta em S3 | **Est:** 2.5h
- [ ] **F9.2.4** — `interface_excecoes/frontend/src/components/kill_switch.tsx` — Componente de kill switch de emergência (autoridade SOC)
  - **Agente:** frontend | **Dependências:** F9.2.1 | **Critérios:** botão vermelho com confirmação dupla, valida role do usuário, feedback imediato, log de ação | **Est:** 2h
- [ ] **F9.2.5** — `interface_excecoes/frontend/src/components/sla_monitor.tsx` — Dashboard de SLA estourado
  - **Agente:** frontend | **Dependências:** F9.2.1 | **Critérios:** cards por categoria, alertas visuais, drill-down para finding | **Est:** 2h

### F9.3 — Testes Interface

- [ ] **F9.3.1** — `tests/e2e/interface_excecoes/` — Testes E2E: login → dashboard → exceção → aprovação → timeline → kill switch
  - **Agente:** qa | **Dependências:** F9.2.1–F9.2.5 | **Critérios:** Cypress/Playwright, 5 cenários principais, valida de estado final no backend | **Est:** 4h

---

## FASE 10: DOCUMENTAÇÃO E RUNBOOKS

### F10.1 — Documentação Técnica

- [ ] **F10.1.1** — `docs/architecture/ADR-003-prompt-injection-guard.md` — ADR: estratégia de detecção e mitigação de prompt injection no pipeline
  - **Agente:** strategist | **Dependências:** F1.1.3 | **Critérios:** análise de trade-offs (regex vs ML), decisão, consequências, riscos residuais | **Est:** 2h
- [ ] **F10.1.2** — `docs/architecture/ADR-004-sandbox-isolation.md` — ADR: escolha de runtime isolado (gVisor vs Firecracker vs Kata)
  - **Agente:** strategist | **Dependências:** F4.2.1 | **Critérios:** comparação técnica, decisão, consequências de segurança, performance | **Est:** 2h
- [ ] **F10.1.3** — `docs/architecture/ADR-005-cwe-template-library.md` — ADR: biblioteca de templates de contenção por CWE
  - **Agente:** strategist | **Dependências:** F6.3.1 | **Critérios:** formato de template, versionamento, validação, aprovação | **Est:** 1.5h
- [ ] **F10.1.4** — `docs/runbooks/containment-playbook.md` — Runbook declarativo de contenção: gatilhos, escopo, ação, rollback
  - **Agente:** strategist | **Dependências:** F6.3.1–F6.3.8 | **Critérios:** formato YAML exemplo, passo a passo, checklist de rollback, aprovação CAB | **Est:** 2h
- [ ] **F10.1.5** — `docs/runbooks/kill-switch-playbook.md` — Runbook de acionamento do kill switch
  - **Agente:** strategist | **Dependências:** F6.4.1 | **Critérios:** autoridade, passo a passo, notificações, pós-ação, auditoria | **Est:** 1.5h
- [ ] **F10.1.6** — `docs/runbooks/exception-four-eyes-playbook.md` — Runbook de exceção four-eyes
  - **Agente:** strategist | **Dependências:** F2.2.1–F2.2.4 | **Critérios:** formulário de solicitação, fluxo de aprovação, prazo, reversão, auditoria | **Est:** 1.5h
- [ ] **F10.1.7** — `docs/ssdlc/threat-model-ztk.md` — Threat Model STRIDE do sistema Z.T.K.
  - **Agente:** strategist | **Dependências:** F0.1–F8.5 | **Critérios:** diagrama DFD, threats por elemento, mitigações, riscos aceitos, revisão anual | **Est:** 4h

### F10.2 — Grafana Dashboards

- [ ] **F10.2.1** — `infra/grafana/dashboards/operacao.json` — Painel de Operação: findings por severidade, tempo de resposta, fila HITL
  - **Agente:** infra | **Dependências:** F0.2.10 | **Critérios:** datasource CloudWatch, alerts configuráveis, refresh 30s | **Est:** 2h
- [ ] **F10.2.2** — `infra/grafana/dashboards/seguranca.json` — Painel de Segurança: agentes ativos, falhas de sandbox, tentativas de prompt injection
  - **Agente:** infra | **Dependências:** F0.2.10 | **Critérios:** datasource CloudWatch + custom metrics, alerta em falha de sandbox | **Est:** 2h
- [ ] **F10.2.3** — `infra/grafana/dashboards/custo.json` — Painel de Custo: consumo Bedrock, GPU-hours, tokens por camada
  - **Agente:** infra | **Dependências:** F0.2.10 | **Critérios:** datasource Athena/CloudWatch, breakdown por tenant/tier/agente | **Est:** 2h
- [ ] **F10.2.4** — `infra/grafana/dashboards/compliance.json` — Painel de Compliance: SLA PCI, renovações de TTL, exceções pendentes
  - **Agente:** infra | **Dependências:** F0.2.10 | **Critérios:** datasource Athena/DynamoDB, alerta de não-conformidade, export PDF | **Est:** 2h

---

## FASE 11: TESTES DE SEGURANÇA E PENTEST INTERNO

### F11.1 — SAST/DAST do Próprio Z.T.K.

- [ ] **F11.1.1** — `tests/security/sast_ztk/` — Configuração Semgrep + Bandit para scan do próprio código Z.T.K.
  - **Agente:** security-ops | **Dependências:** F0.4.1 | **Critérios:** CI job dedicado, falha em finding CRITICAL/HIGH, report artifact | **Est:** 2h
- [ ] **F11.1.2** — `tests/security/dependency_scan/` — SCA do próprio Z.T.K. (pip audit, Snyk)
  - **Agente:** security-ops | **Dependências:** F0.4.1 | **Critérios:** scan semanal, alerta em CVE HIGH/CRITICAL, SBOM do próprio projeto | **Est:** 1.5h
- [ ] **F11.1.3** — `tests/security/secrets_scan/` — TruffleHog no histórico do repo Z.T.K.
  - **Agente:** security-ops | **Dependências:** F0.4.1 | **Critérios:** scan em todo histórico, alerta imediato, validação de segredo vivo | **Est:** 1.5h

### F11.2 — Pentest Interno (Agentes como Alvo)

- [ ] **F11.2.1** — `tests/security/pentest_prompt_injection/` — Testes de penetração: tentativas de prompt injection via código de entrada
  - **Agente:** security-ops | **Dependências:** F1.1.3 | **Critérios:** 10 payloads conhecidos, valida bloqueio por L1.03, nenhum chega a LLM downstream | **Est:** 3h
- [ ] **F11.2.2` — `tests/security/pentest_sandbox_escape/` — Tentativas de escape do sandbox de PoC
  - **Agente:** security-ops | **Dependências:** F4.2.1 | **Critérios:** 5 técnicas de escape (container, privilege escalation, network), valida bloqueio | **Est:** 3h
- [ ] **F11.2.3` — `tests/security/pentest_tenant_isolation/` — Validação de isolamento de dados entre tenants (preparação)
  - **Agente:** security-ops | **Dependências:** F8.4.4 | **Critérios:** hoje: valida que tenant_id não vaza, futuro: cross-tenant data access test | **Est:** 2h

---

## FASE 12: GOVERNANCE E REVISÃO

### F12.1 — Revisão Arquitetural

- [ ] **F12.1.1** — Revisão de ADRs pendentes: D001 (ECS vs EKS), D002 (modelo local), D003 (Grafana), D004 (frontend framework), D005 (Bedrock vs DeepSeek), D006 (on-premise connector)
  - **Agente:** strategist | **Dependências:** Todas as Fases 0–11 | **Critérios:** decisão documentada, stakeholder aprovador, ADR atualizado | **Est:** 4h
- [ ] **F12.1.2` — Revisão de compliance: validação que todos os requisitos PCI DSS 4.0, LGPD, BACEN estão mapeados a controles implementados
  - **Agente:** regulatory | **Dependências:** Todas as Fases 0–11 | **Critérios:** matriz de rastreabilidade req. ↔ controle, gaps identificados, plano de remediação | **Est:** 4h
- [ ] **F12.1.3` — Revisão de custo: projeção de custo mensal por ambiente (dev/staging/prod) com base em infra real implantada
  - **Agente:** po | **Dependências:** F0.2.1–F0.2.10, F7.2.4 | **Critérios:** planilha de custo, cenários de volume low/medium/high, recomendações de otimização | **Est:** 3h

### F12.2 — Handoff e Documentação Final

- [ ] **F12.2.1` — `docs/operacoes/runbook-deploy-producao.md` — Runbook completo de deploy em produção
  - **Agente:** pm | **Dependências:** Todas as Fases 0–11 | **Critérios:** passo a passo, rollback, checklist de validação, contatos de emergência | **Est:** 3h
- [ ] **F12.2.2` — `docs/operacoes/runbook-incidente.md` — Runbook de resposta a incidente no Z.T.K.
  - **Agente:** pm | **Dependências:** Todas as Fases 0–11 | **Critérios:** classificação de severidade, times envolvidos, ferramentas, comunicação, pós-incidente | **Est:** 3h

---

## RESUMO DE DEPENDÊNCIAS CRÍTICAS

```
F0 (Fundação) ─────────────────────────────────────────────┐
  ├─ F0.1 (Shared) → todas as camadas                      │
  ├─ F0.2 (Infra Base) → todas as camadas                  │
  ├─ F0.3 (OPA Policies) → F2.1, F5.2, F6.3, F7.5       │
  └─ F0.4 (CI/CD) → todas as camadas                       │
                                                           │
F1 (Camada 1) ─────────────────────────────────────────────┤
  └─ depende de F0                                         │
                                                           │
F2 (Camada 6 - Governança) ────────────────────────────────┤
  └─ depende de F0, F0.3                                   │
  ├─ consumido por F4, F5, F6, F7, F8                      │
                                                           │
F3 (Camada 2 - Especialistas) ───────────────────────────┤
  └─ depende de F0, F1                                     │
                                                           │
F4 (Camada 3 - Validação) ────────────────────────────────┤
  └─ depende de F0, F3, F2 (HITL para fuzzing)             │
                                                           │
F5 (Camada 4 - Consenso) ──────────────────────────────────┤
  └─ depende de F0, F4, F2 (pisos, HITL)                  │
                                                           │
F6 (Camada 5 - Remediação) ────────────────────────────────┤
  └─ depende de F0, F5, F2 (HITL, auditoria)              │
                                                           │
F7 (Camada 7 - Model Ensemble) ────────────────────────────┤
  └─ depende de F0, F1 (escopo), F6 (ensemble patch)      │
  ├─ consumido por F3.1.3 (correlator), F5.3, F6.2.1       │
                                                           │
F8 (Camada 8 - Escala) ────────────────────────────────────┤
  └─ depende de F0, F1, F3, F7                             │
                                                           │
F9 (Interface) ────────────────────────────────────────────┤
  └─ depende de F2, F6                                     │
                                                           │
F10 (Docs) → depende das fases respectivas                   │
F11 (Security Tests) → depende das fases respectivas         │
F12 (Governance Review) → depende de TUDO                    │
```

---

## PROXIMAS TASKS (Ordem de Prioridade)

### Imediato (esta sprint)
1. **M4.11** — Corrigir 10 testes falhando no copilot (logger kwargs + parse enum + double-count)
   - Agente: **@ztk-build** | Est: 2h | Dependencias: M4.10
2. **M4.12** — Criar pipeline CI/CD para mvp2/copilot/ (.github/workflows/copilot-ci.yml)
   - Agente: **@ztk-infra** | Est: 1.5h | Dependencias: M4.11

### Curto prazo (proxima sprint)
3. **F0.1.1** — `src/shared/schemas/finding.py` — Schema base Finding (inicio da Fase 0)
   - Agente: **@ztk-backend** | Est: 2h | Dependencias: nenhuma
4. **F0.1.6** — `src/shared/utils/idempotency.py` — Funcao pura generate_idempotency_key
   - Agente: **@ztk-backend** | Est: 1h | Dependencias: nenhuma

### Bloqueado (aguardando externos)
5. **M4.13** — Aurora PostgreSQL + pgvector → Future (sem previsao)
6. **M4.14** — Bedrock IAM/config → Aguardando time de plataforma
7. **G2, G5, G7, G9, G10** — Gates humanos MVP1 → Aguardando stakeholders externos
```