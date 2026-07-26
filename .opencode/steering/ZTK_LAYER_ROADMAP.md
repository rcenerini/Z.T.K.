# ZTK_LAYER_ROADMAP.md
## Roadmap de Implementacao por Camada — Projeto Z.T.K.

> **Versao:** 1.0 | **Data:** 2026-07-25
> **Escopo:** Milestones e entregaveis por camada do sistema multiagente Z.T.K.
> **Regra:** Nunca iniciar Camada N sem Camada N-1 ter schemas estaveis e tests passando.

---

## Visao Geral das Fases

```
F0 (Fundacao)          → Shared schemas, infra base, policies, CI/CD
F1 (Camada 1)          → Entrada & Triagem (deterministica, sem LLM)
F2 (Camada 6)          → Governanca transversal (Policy Engine, Auditoria, HITL)
F3 (Camada 2)          → Especialistas de Seguranca (30+ agentes SAST/SCA/Hardening)
F4 (Camada 3)          → Validacao (Reachability, PoC, Fuzzing, Score)
F5 (Camada 4)          → Consenso/Debate (CVSS+EPSS+SSVC, piso nao-negociavel, debate adversarial)
F6 (Camada 5)          → Remediacao (Trilha A: patch + Trilha B: contencao WAF)
F7 (Camada 7)          → Model Ensemble (roteamento LLM, vLLM local, Bedrock, custo)
F8 (Camada 8)          → Escala e Especializacao (ativação condicional, onboarding, multi-tenant)
F9 (Interface)          → Frontend/backend para excecoes, kill switch, timeline
F10 (Docs)             → ADRs, runbooks, threat model, Grafana dashboards
F11 (SecTests)         → SAST/DAST do proprio ZTK, pentest interno
F12 (Governance)       → Revisao arquitetural, compliance, handoff
```

---

## MILESTONE 0: Fundacao (Weeks 1-4)

**Objetivo:** Base tecnica estavel sobre a qual todo o sistema sera construido.

### Semana 1-2: Shared Schemas & Core Library
- Entregavel: `shared/schemas/finding.py`, `decision.py`, `audit_event.py`, `llm_request.py`, `containment.py`
- Entregavel: `shared/utils/` (idempotency, fail_closed, structlog, secrets, dynamodb, s3, sqs)
- Gates: `mypy --strict` passa, cobertura 85%+

### Semana 3: Infraestrutura Base (Terraform)
- Entregavel: VPC, DynamoDB, S3, SQS, Lambda module, ECS Fargate module, EC2 GPU module, IAM roles
- Gates: `terraform plan` passa, `checkov` zero HIGH, `opa test` 100%

### Semana 4: CI/CD, Policies, Testes
- Entregavel: `.github/workflows/ci.yml`, pre-commit hooks, OPA policies base
- Entregavel: Testes unitarios da fundacao (shared/schemas + shared/utils)
- Gates: `make quality-gates` passa verde

**Status: INICIO DO PROJETO** — nenhuma camada pode avancar sem M0 concluido.

---

## MILESTONE 1: Camada 1 — Entrada & Triagem (Weeks 5-6)

**Objetivo:** Receber codigo, classificar, proteger contra prompt injection, rotear.

- **L1.01:** Repo/Diff Ingestion (Lambda, Git CLI, read-only)
- **L1.02:** Language & Artifact Classifier (go-enry / linguist)
- **L1.03:** Prompt-Injection Guard (regex/heuristica + envelopamento)
- **L1.04:** Business Criticality Tagger (CMDB / CODEOWNERS)
- **L1.05:** Pipeline Router (motor de regras YAML)
- **L1.06:** Scope & Budget Planner
- **L1.07:** Dedup/Idempotency Key Generator
- **Orchestrator:** Step Functions ZTKLayer1Orchestrator
- **Tests:** Unit + Integration (moto)

**Gate de saida:** Evento EventBridge → handler → SQS com output validado e idempotente.

---

## MILESTONE 2: Camada 6 — Governanca Transversal (Weeks 7-10)

**Objetivo:** Policy Engine, Auditoria Unificada, HITL Gateway, Excecao Four-Eyes.

### Semana 7-8: Policy Engine Core
- **L6.01:** Policy Engine (OPA/Rego evaluation)
- **L6.02:** Policy Version Registry (Git webhook)
- **L6.03:** Policy Change Gate (dupla aprovacao)
- **L6.04:** Policy Test Runner (opa test em PR)

### Semana 9: Fluxo de Excecao + Auditoria
- **L6.05-L6.09:** Exception intake → four-eyes approval → applier → audit
- **L6.10-L6.12:** Audit collector → Sentinel forwarder → Retention guard

### Semana 10: HITL Gateway
- **L6.13-L6.17:** HITL queue → notifier (Teams/email) → Jira ticket → SLA monitor
- **Tests:** Unit + Integration + E2E (exception flow completo)

**Gate de saida:** Solicitacao de excecao → dupla aprovacao → aplicacao → auditoria → expiracao → reversao (E2E passando).

---

## MILESTONE 3: Camada 2 — Especialistas (Weeks 11-18)

**Objetivo:** Framework SAST + 30 agentes por linguagem/ferramenta/domínio.

### Semana 11-12: Framework SAST
- Executor, Parser SARIF/JSON, Correlator (LLM unico nesta subcamada)

### Semana 13-15: SAST por Linguagem (16 agentes)
- Python (Bandit, Semgrep), Java (SpotBugs, CodeQL), JS/TS (ESLint, Semgrep)
- Go (gosec, CodeQL), C/C++ (cppcheck, CodeQL), Rust (clippy), C# (Roslyn)
- PHP (Psalm), Ruby (Brakeman), Mobile (MobSF)

### Semana 16: Hardening (8 agentes)
- AppSec API, DB Config/Query, Infra Terraform/K8s, Container, OS CIS, Network

### Semana 17: Segredos + SCA + CVE (6 agentes)
- Gitleaks, TruffleHog, SBOM (Syft), CVE correlator (NVD, OSV, GHSA)

### Semana 18: Orquestracao + Tests
- Step Functions ZTKLayer2Orchestrator
- Unit + Integration + Contract tests

**Gate de saida:** Evento de codigo Python → Bandit → Parser → Finding validado com schema F0.1.1.

---

## MILESTONE 4: Camada 3 — Validacao (Weeks 19-24)

**Objetivo:** Reachability, PoC sandboxed, fuzzing sob HITL, motor de score.

### Semana 19-20: Reachability
- Estatica (CodeQL call-graph), Dinamica (tracing de testes), Config/DI resolver

### Semana 21-22: PoC Framework + 9 Classes CWE
- Sandbox Firecracker/gVisor isolado
- SQLi, Command Injection, SSRF, Deserialization, Auth Bypass
- Crypto weakness, Path Traversal, Memory UAF, Business Logic Race

### Semana 23: Fuzzing + Score
- Fuzzing gateway (HITL), harness builder, executor, crash triage
- Evidence aggregator + Scoring engine (deterministico, sem LLM)

### Semana 24: Orquestracao + Tests
- Step Functions ZTKLayer3Orchestrator
- Unit + Integration + Security tests (sandbox escape)

**Gate de saida:** Finding com CWE-89 → PoC SQLi em sandbox → score validado (≥8, 4-7, ≤0).

---

## MILESTONE 5: Camada 4 — Consenso/Debate (Weeks 25-28)

**Objetivo:** Scoring CVSS+EPSS+SSVC, pisos nao-negociaveis, debate adversarial.

### Semana 25-26: Scoring Deterministico + Pisos
- CVSS v4.0 calculator, EPSS correlator, SSVC decision tree
- Business severity adjuster, Severity floors (PCI→P1, LGPD→P1, Antifraude→P0)

### Semana 27: Debate Adversarial
- Prosecutor (enviesado para atacar), Defender (enviesado para defender)
- Judge (moderador com restricao de piso), Divergence detector, HITL escalation

### Semana 28: Orquestracao + Tests
- Step Functions ZTKLayer4Orchestrator
- Unit + Integration tests (todos os ramos SSVC, testes de pisos)

**Gate de saida:** Score 6 → debate → Judge → prioridade final P0-P4, com justificativa e piso respeitado.

---

## MILESTONE 6: Camada 5 — Remediacao (Weeks 29-34)

**Objetivo:** Trilha A (patch de codigo) + Trilha B (contencao WAF) em paralelo.

### Semana 29-30: Trilha A — Fix Definitivo
- Patch generator (LLM), sandbox validator (build+testes), regression guard
- PR publisher, merge guardrail (bloqueio automatico P0/P1)

### Semana 31-32: Trilha B — Contencao Runtime
- Template selector, confidence gate, dry-run simulator
- Deploy F5/Akamai/Azure WAF, TTL manager, audit logger

### Semana 33: Kill Switch + Escalação SLA
- Emergency kill switch (autoridade SOC), post-kill notifier
- SLA breach escalator (1ª→owner, 2ª→eng manager, 3ª→CISO, 4ª→C-level)

### Semana 34: Orquestracao + Tests
- Step Functions ZTKLayer5Orchestrator (Parallel Trilha A + B)
- Unit + Integration + E2E (remediation flow completo)

**Gate de saida:** Finding P1 → patch gerado + PR aberto + contencao aplicada → kill switch → auditoria completa.

---

## MILESTONE 7: Camada 7 — Model Ensemble (Weeks 35-38)

**Objetivo:** Roteamento LLM, vLLM local (PCI), Bedrock (nao-PCI), circuit breaker de custo.

### Semana 35-36: Roteamento + Infra Local
- Data scope classifier, model router, task tier classifier
- vLLM inference cluster, frontier/distilled models, GPU autoscaler

### Semana 37: Bedrock + Ensemble + Custo
- Bedrock frontier/distilled clients, guardrails
- Patch ensemble orchestrator, diff comparator
- Cost metering, budget circuit breaker, cache layer

### Semana 38: Orquestracao + Tests
- Step Functions ZTKLayer7Router
- Unit + Integration + Security tests (tentativa de forçar PCI→Bedrock)

**Gate de saida:** LLMRequest com data_scope=PCI → assignment=LOCAL, nunca Bedrock.

---

## MILESTONE 8: Camada 8 — Escala (Weeks 39-42)

**Objetivo:** Ativacao condicional, lifecycle de ferramentas, onboarding formal, multi-tenancy.

- Monorepo module mapper, scoped activation engine, criticality-weighted depth
- Tool version monitor, update PR generator, ownership registry
- Agent onboarding gate, policy registration, shadow mode runner/evaluator/promoter
- Tenant context tag, policy override, cost isolator, data isolation guard
- Tests: unit + integration

**Gate de saida:** Novo agente proposto → shadow mode 30 dias → avaliacao → aprovacao → producao.

---

## MILESTONE 9: Interface de Excecoes (Weeks 43-46)

**Objetivo:** Frontend React/Next.js + Backend API Gateway para gestao de excecoes.

- Backend: API Gateway + Lambda (JWT, rate limiting, exception service, audit timeline)
- Frontend: Dashboard, fila de excecoes, timeline de auditoria, kill switch component, SLA monitor
- E2E tests (Cypress/Playwright)

**Gate de saida:** Login → dashboard → aprovar excecao → timeline → kill switch (E2E passando).

---

## MILESTONE 10: Documentacao & Observabilidade (Weeks 47-48)

**Objetivo:** ADRs, runbooks, Grafana dashboards, threat model.

- ADRs: prompt-injection-guard, sandbox-isolation, CWE-template-library
- Runbooks: contenção, kill-switch, exception four-eyes
- Threat model STRIDE completo
- Grafana dashboards: Operacao, Seguranca, Custo, Compliance

---

## MILESTONE 11: Testes de Seguranca (Weeks 49-50)

**Objetivo:** SAST/DAST do proprio ZTK, pentest interno.

- SAST do proprio codigo (Semgrep + Bandit)
- Dependency scan (pip audit, Snyk)
- Secrets scan (TruffleHog no historico)
- Pentest: prompt injection, sandbox escape, tenant isolation

---

## MILESTONE 12: Governance Review (Week 51-52)

**Objetivo:** Revisao final, compliance, handoff.

- Revisao de ADRs pendentes (D001-D006)
- Matriz de rastreabilidade PCI DSS 4.0 / LGPD / BACEN
- Projeção de custo mensal por ambiente
- Runbook de deploy em producao
- Runbook de resposta a incidente

---

## Resumo de Timeline

| Milestone | Semanas | Camada | Foco |
|-----------|---------|--------|------|
| M0 | 1-4 | F0 | Fundacao (schemas, infra, CI/CD) |
| M1 | 5-6 | F1 | Entrada & Triagem |
| M2 | 7-10 | F2 | Governanca transversal |
| M3 | 11-18 | F3 | Especialistas (30+ agentes) |
| M4 | 19-24 | F4 | Validacao (PoC, fuzzing, score) |
| M5 | 25-28 | F5 | Consenso/Debate |
| M6 | 29-34 | F6 | Remediacao (patch + contencao) |
| M7 | 35-38 | F7 | Model Ensemble |
| M8 | 39-42 | F8 | Escala |
| M9 | 43-46 | F9 | Interface de Excecoes |
| M10 | 47-48 | F10 | Documentacao & Dashboards |
| M11 | 49-50 | F11 | Testes de Seguranca |
| M12 | 51-52 | F12 | Governance Review |

**Total estimado:** 52 semanas (~1 ano) para MVP completo das 8 camadas.
**Primeiro valor entregavel (M0+M1+M2):** Semana 10 — pipeline de ingestao + governanca operacional.
**Pipeline end-toend basico (M0-M5):** Semana 28 — do codigo ao achado confirmado com severidade.

---

## Proxima Task Imediata

Consulte `TASKS_ZTK.md` — a task **F0.1.1** (`shared/schemas/finding.py`) e a fundacao de todas as camadas. Inicie por ela.
