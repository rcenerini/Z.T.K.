# Squad Agêntica — SAGA-SAGV_V2 + Z.T.K.
## Modelo de Equipe Híbrida (Humanos + Agentes de IA) para Desenvolvimento

**Versão:** 1.0  
**Data:** 2026-07-23  
**Contexto:** Desenvolvimento do sistema multiagente de segurança de código (SAGA-SAGV_V2 como MVP1, Z.T.K. como MVP2) para ambiente de adquirência/PCI DSS.

---

## 1. Filosofia da Squad Agêntica

### 1.1 Princípio Central

> **"Agentes de IA executam o trabalho repetitivo, estruturado e paralelizável. Humanos decidem arquitetura, validam segurança, aprovam deploys e resolvem ambiguidade genuína."**

A squad agêntica não substitui humanos — ela **amplifica** uma equipe menor (8–12 pessoas) para entregar o que normalmente exigiria 20–25, ao delegar para agentes de IA as tarefas que são:
- Bem especificadas e determinísticas
- Paralelizáveis sem dependência de contexto humano contínuo
- Verificáveis por testes automatizados ou revisão estruturada

### 1.2 O Que Agentes de IA Fazem Bem Neste Projeto

| Categoria | Exemplos Concretos |
|-----------|-------------------|
| Geração de código boilerplate | Conectores Lambda (SAGA), agentes wrapper de ferramenta (Z.T.K. Camada 2) |
| Implementação de lógica determinística | Motor SSVC, scoring engine, árvores de decisão |
| Testes unitários e de integração | Matriz de cobertura do motor SSVC, testes por conector |
| IaC e configuração | Terraform/CDK para Lambda, SQS, DynamoDB, EKS |
| Documentação técnica | ADRs, runbooks, specs de API, diagramas |
| Code review assistido | Revisão de segurança, conformidade com padrões, detecção de anti-patterns |
| Refatoração e migração | Padronização de conectores, normalização de schemas |
| Políticas OPA/Rego | Tradução de regras de negócio em políticas formais |

### 1.3 O Que Fica Exclusivamente com Humanos

| Categoria | Razão |
|-----------|-------|
| Decisões de arquitetura de alto nível | Impacto irreversível, requer contexto de negócio |
| Validação de segurança ofensiva (PoC real) | Risco operacional, requer julgamento ético |
| Aprovação de deploy em produção | Compliance PCI DSS, responsabilidade nomeada |
| Negociação de SLA com time de risco | Decisão de negócio, não técnica |
| Revisão final de patches P0/P1 | O próprio sistema exige humano no loop |
| Exceções de compliance (four-eyes) | Requisito regulatório |
| Design de sandbox de PoC | Risco de escape, requer expertise ofensiva |
| Integração com vendors (F5/Akamai/Azure) | Requer credenciais, contratos, contexto político |

---

## 2. Composição da Squad Agêntica

### 2.1 Visão Geral — Humanos + Agentes

```
┌─────────────────────────────────────────────────────────────────┐
│                    SQUAD AGÊNTICA COMPLETA                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  HUMANOS (8–12 pessoas)              AGENTES DE IA (6–8 agentes) │
│  ┌─────────────────────┐            ┌──────────────────────────┐ │
│  │ Security Architect   │            │ 🤖 Agente Arquiteto      │ │
│  │ AppSec Lead          │            │ 🤖 Agente Engenheiro     │ │
│  │ Platform Lead        │            │ 🤖 Agente de Testes      │ │
│  │ ML Engineer          │            │ 🤖 Agente de IaC         │ │
│  │ Red Team Engineer    │            │ 🤖 Agente de Docs        │ │
│  │ Backend Engineers ×3 │            │ 🤖 Agente de Review      │ │
│  │ SRE                  │            │ 🤖 Agente de Políticas   │ │
│  │ Product Manager      │            │ 🤖 Agente de Observab.   │ │
│  │ Eng Manager          │            │                          │ │
│  └─────────────────────┘            └──────────────────────────┘ │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 Humanos — Papéis Reduzidos (8–12 pessoas)

| # | Papel | Responsabilidade na Squad Agêntica | Interação com Agentes |
|---|-------|-----------------------------------|----------------------|
| 1 | **Security Architect (Staff+)** | Visão holística, decisões cross-camada, alinhamento regulatório | Revisa output do Agente Arquiteto, valida ADRs gerados |
| 2 | **AppSec Lead** | Design dos agentes de segurança (Camada 2), rulesets, validação de PoC | Especifica para o Agente Engenheiro, revisa código de agentes |
| 3 | **Platform/Infra Lead** | EKS, GPU clusters, sandbox isolation, networking PCI | Revisa IaC gerada pelo Agente de IaC, aprova deploys |
| 4 | **ML/AI Engineer** | Ensemble de modelos, vLLM tuning, debate adversarial, RAG | Usa Agente Engenheiro para boilerplate, foca em lógica de roteamento |
| 5 | **Red Team / Offensive Security** | Camada 3: PoC real, fuzzing, validação de exploitabilidade | Trabalho majoritariamente manual — agentes auxiliam apenas em harness building |
| 6 | **Backend Engineer Sr. (SAGA Lead)** | Motor SSVC, conectores, Step Functions, audit trail | Especifica lógica, Agente Engenheiro implementa, humano revisa |
| 7 | **Backend Engineer (Z.T.K. Remediação)** | Trilha A (patch pipeline) + Trilha B (WAF multi-vendor) | Agente implementa integrações, humano valida dry-run e segurança |
| 8 | **Backend Engineer (Conectores/Integrações)** | APIs externas (Veracode, Orca, Tenable, Jira, Akamai) | Agente gera boilerplate de conector, humano ajusta auth e edge cases |
| 9 | **SRE / DevOps** | CI/CD, observabilidade, Sentinel, alerting | Agente de IaC gera pipelines, humano valida e opera |
| 10 | **Product Manager** | Roadmap, priorização, SLAs, interface com stakeholders | Usa Agente de Docs para gerar specs, humano decide prioridade |
| 11 | **Engineering Manager** | Coordenação, remoção de blockers, gestão de pessoas | Usa dashboards gerados pelo Agente de Observabilidade |

**Economia:** de 19–25 pessoas (squad tradicional) para 8–12 humanos + agentes = **~50% de redução de headcount**, com throughput equivalente ou superior em tarefas estruturadas.

### 2.3 Agentes de IA — Definição Detalhada

---

#### 🤖 AGENTE 1: Arquiteto de Sistema

| Atributo | Valor |
|----------|-------|
| **Ferramenta Principal** | Claude Code (Opus/Sonnet) em modo agêntico |
| **Alternativa** | Cursor com Claude Sonnet 5 |
| **Contexto Persistente** | Documentos de arquitetura (os 3 MDs fornecidos), ADRs, diagramas |
| **Responsabilidades** | Gerar ADRs (Architecture Decision Records), propor interfaces entre camadas, validar consistência de design, gerar diagramas (Mermaid/PlantUML) |
| **Gatilho** | Humano (Security Architect) solicita análise de impacto ou proposta de interface |
| **Output** | Markdown estruturado: ADR, diagrama, análise de trade-off |
| **Guardrail** | Nunca decide sozinho — sempre gera proposta para revisão humana |
| **Modelo Recomendado** | Claude Opus 4 (reasoning complexo) ou Claude Sonnet 5 (velocidade) |

**Workflow típico:**
```
Security Architect descreve problema/decisão
  → Agente Arquiteto gera ADR com opções + trade-offs + recomendação
  → Security Architect revisa, ajusta, aprova
  → ADR versionado no repo
```

---

#### 🤖 AGENTE 2: Engenheiro de Código

| Atributo | Valor |
|----------|-------|
| **Ferramenta Principal** | Claude Code (Sonnet 5) — modo agêntico com acesso ao repo |
| **Alternativas** | Cursor + Sonnet 5, Windsurf, Aider |
| **Contexto Persistente** | Repo completo, specs de API, padrões de código, testes existentes |
| **Responsabilidades** | Implementar componentes Lambda (SAGA), agentes wrapper (Z.T.K.), lógica de negócio determinística, integrações de API |
| **Gatilho** | Ticket no backlog com spec detalhada (gerada pelo PM ou Lead) |
| **Output** | PR com código + testes + documentação inline |
| **Guardrail** | Toda PR passa por review humano antes de merge; nunca deploya sozinho |
| **Modelo Recomendado** | Claude Sonnet 5 (melhor para código) |

**Tarefas ideais para este agente:**

| Tarefa | Complexidade | Tempo Humano | Tempo Agente |
|--------|-------------|--------------|--------------|
| Implementar conector Lambda (padrão KEV/EPSS) | Média | 2–3 dias | 2–4 horas |
| Motor de decisão SSVC (função pura) | Média | 3–4 dias | 4–6 horas |
| Agente wrapper SAST (ex: L2.01 Bandit) | Baixa-Média | 1–2 dias | 1–2 horas |
| Normalização de finding (schema mapping) | Baixa | 1 dia | 30–60 min |
| Audit trail (append-only S3) | Média | 2 dias | 2–3 horas |
| Integração Jira API (criar/atualizar ticket) | Média | 2 dias | 2–3 horas |
| Step Functions definition (ASL) | Média | 2–3 dias | 3–4 horas |

**Workflow típico:**
```
Lead escreve spec (1–2 parágrafos com inputs/outputs/constraints)
  → Agente Engenheiro implementa em branch dedicada
  → Agente de Testes gera/roda testes
  → Agente de Review faz primeira passada
  → Humano (Lead) faz review final
  → Merge
```

---

#### 🤖 AGENTE 3: Engenheiro de Testes

| Atributo | Valor |
|----------|-------|
| **Ferramenta Principal** | Claude Code + pytest/Jest runner |
| **Responsabilidades** | Gerar testes unitários, de integração e de contrato; manter a matriz de cobertura do motor SSVC; mutation testing |
| **Gatilho** | Automático após cada PR do Agente Engenheiro, ou sob demanda |
| **Output** | Suíte de testes + relatório de cobertura |
| **Guardrail** | Cobertura mínima configurável (ex: 90% para motor SSVC, 80% para conectores) |
| **Modelo Recomendado** | Claude Sonnet 5 |

**Foco especial neste projeto:**
- Matriz de 9 cenários do motor SSVC (obrigatória por spec)
- Testes de idempotência por conector
- Testes de fail-closed (simular falha de API externa → confirmar comportamento conservador)
- Testes de contrato entre camadas (schema de NormalizedFinding, ContextualizedFinding, Decision)

---

#### 🤖 AGENTE 4: Engenheiro de Infraestrutura (IaC)

| Atributo | Valor |
|----------|-------|
| **Ferramenta Principal** | Claude Code + Terraform/CDK |
| **Alternativa** | Pulumi AI, Cursor com contexto de IaC |
| **Responsabilidades** | Gerar módulos Terraform/CDK para Lambda, SQS, DynamoDB, EKS, VPC, IAM policies, S3 buckets com lifecycle |
| **Gatilho** | Novo componente precisa de infra, ou mudança de requisito de isolamento |
| **Output** | PR com módulos IaC + plan output + documentação |
| **Guardrail** | Nunca aplica (`terraform apply`) sozinho — apenas gera plan para revisão do Platform Lead/SRE |
| **Modelo Recomendado** | Claude Sonnet 5 |

**Tarefas típicas:**
- VPC com subnets PCI-isoladas vs não-PCI
- EKS cluster com node groups GPU (g5/p4d) + Karpenter
- Lambda functions com IAM least-privilege por conector
- SQS queues com DLQ por fonte
- S3 buckets com particionamento de audit trail
- Security Groups para sandboxes de PoC (zero egress)

---

#### 🤖 AGENTE 5: Documentador Técnico

| Atributo | Valor |
|----------|-------|
| **Ferramenta Principal** | Claude (Sonnet/Opus) com acesso ao repo |
| **Responsabilidades** | Gerar e manter: READMEs, runbooks de mitigação (YAML), specs de API (OpenAPI), diagramas de fluxo, changelog, onboarding docs |
| **Gatilho** | Pós-merge de feature significativa, ou sob demanda do PM |
| **Output** | Markdown/YAML versionado no repo |
| **Guardrail** | Docs de compliance (PCI, LGPD) passam por revisão do GRC humano |
| **Modelo Recomendado** | Claude Sonnet 5 (volume) ou Opus 4 (docs complexos de compliance) |

**Valor especial neste projeto:**
- Runbooks declarativos de mitigação (requisito do SAGA-SAGV_V2) — o agente gera o YAML, o CAB humano aprova
- Documentação de política OPA/Rego em linguagem acessível para auditores
- Evidência de auditoria formatada para PCI DSS req. 10

---

#### 🤖 AGENTE 6: Revisor de Código (Security-Focused)

| Atributo | Valor |
|----------|-------|
| **Ferramenta Principal** | Claude Code como reviewer em CI/CD (GitHub Actions / GitLab CI) |
| **Alternativa** | CodeRabbit, Sourcery, ou custom via API |
| **Responsabilidades** | Primeira passada de review em toda PR: conformidade com padrões, detecção de anti-patterns de segurança, consistência com arquitetura documentada |
| **Gatilho** | Automático em toda PR (CI pipeline) |
| **Output** | Comentários inline na PR + summary com severity |
| **Guardrail** | Não aprova/rejeita sozinho — apenas sinaliza; humano toma decisão final |
| **Modelo Recomendado** | Claude Sonnet 5 |

**Checklist automático do reviewer:**
- [ ] Nenhuma credencial hardcoded
- [ ] Fail-closed em caso de erro/timeout
- [ ] Idempotência em operações de escrita
- [ ] Schema de entrada/saída conforme contrato
- [ ] Sem chamada direta Lambda→Lambda (deveria ser Step Functions)
- [ ] Audit event emitido para toda decisão
- [ ] Testes cobrindo cenários de falha

---

#### 🤖 AGENTE 7: Engenheiro de Políticas (OPA/Rego)

| Atributo | Valor |
|----------|-------|
| **Ferramenta Principal** | Claude Code + OPA CLI (`opa test`, `opa eval`) |
| **Responsabilidades** | Traduzir regras de negócio (pisos de severidade, thresholds, roteamento) em políticas Rego testáveis |
| **Gatilho** | Nova regra de negócio definida pelo PM/GRC, ou mudança de threshold |
| **Output** | Arquivo .rego + testes + documentação da regra em linguagem natural |
| **Guardrail** | Toda política passa por dupla aprovação (1 técnico + 1 compliance) antes de merge — conforme L6.03 |
| **Modelo Recomendado** | Claude Sonnet 5 |

**Exemplo de tradução:**
```
ENTRADA (regra de negócio em português):
"Todo achado que toca dado de cartão (CHD) tem severidade mínima P1,
 independente do que o debate adversarial conclua."

SAÍDA (Rego):
package severity_floor

default floor = "P4"

floor = "P1" {
    input.finding.data_classification == "CHD"
}

floor = "P1" {
    input.finding.pci_scope == true
}

floor = "P0" {
    input.finding.domain == "antifraude"
}
```

---

#### 🤖 AGENTE 8: Monitor de Observabilidade e Métricas

| Atributo | Valor |
|----------|-------|
| **Ferramenta Principal** | Claude + dashboards (QuickSight/Grafana templates) |
| **Responsabilidades** | Gerar queries Athena, dashboards de governança, alertas CloudWatch, schemas de evento para Sentinel |
| **Gatilho** | Novo componente em produção, ou requisito de métrica do PM |
| **Output** | Queries SQL/KQL, dashboard definitions (JSON), alerta configs |
| **Guardrail** | Alertas críticos (P0/P1) revisados por SRE antes de ativação |
| **Modelo Recomendado** | Claude Sonnet 5 |

---

## 3. Ferramentas Recomendadas por Camada

### 3.1 Stack de Ferramentas para Agentes de IA

| Ferramenta | Uso Principal | Quando Usar | Modelo Subjacente |
|------------|--------------|-------------|-------------------|
| **Claude Code (CLI)** | Desenvolvimento agêntico principal | Implementação de componentes, refatoração, debugging | Sonnet 5 (default) / Opus 4 (complexo) |
| **Cursor IDE** | Desenvolvimento interativo com contexto de repo | Quando o humano quer pair-programming com o agente | Sonnet 5 / GPT-4o |
| **Windsurf** | Alternativa ao Cursor com melhor contexto de projeto | Projetos grandes com muitos arquivos interdependentes | Sonnet 5 |
| **Aider** | CLI leve para edições pontuais | Fixes rápidos, refatorações simples | Sonnet 5 / DeepSeek |
| **GitHub Copilot** | Autocompletar inline | Complemento durante coding manual | GPT-4o |
| **CodeRabbit** | Review automatizado em CI | Toda PR, como primeira camada de review | Proprietário |
| **Terraform AI (Pulumi AI)** | Geração de IaC | Módulos novos de infra | Sonnet 5 |
| **Claude API (Batch)** | Tarefas em massa | Gerar 30 agentes wrapper da Camada 2 em paralelo | Sonnet 5 (batch) |

### 3.2 Orquestração da Squad Agêntica

| Ferramenta | Função |
|------------|--------|
| **Linear / Jira** | Backlog e tracking de tasks (humanos + agentes) |
| **GitHub Projects** | Kanban visual do estado de PRs |
| **Claude Code com CLAUDE.md** | Contexto persistente por repo (padrões, constraints, arquitetura) |
| **Notion / Confluence** | Documentação de alto nível, ADRs, runbooks aprovados |
| **Slack + Claude Bot** | Comunicação rápida, queries sobre arquitetura |

### 3.3 Mapeamento Ferramenta × Camada do Projeto

| Camada SAGA/Z.T.K. | Ferramenta de Agente Primária | Humano Responsável |
|--------------------|-------------------------------|-------------------|
| Conectores (SAGA S1–S6) | Claude Code (Agente Engenheiro) | Backend Engineer (Conectores) |
| Normalização/Enriquecimento (S7–S9) | Claude Code | Backend Engineer Sr. |
| Motor SSVC (S10) | Claude Code + Agente de Testes | Backend Engineer Sr. (review intensivo) |
| Orquestração Jira/Akamai (S11–S13) | Claude Code | Backend Engineer (Remediação) |
| Audit Trail (S15) | Claude Code + Agente IaC | SRE |
| Z.T.K. Camada 1 (Triagem) | Claude Code | AppSec Lead |
| Z.T.K. Camada 2 (30 agentes SAST) | **Claude Batch API** (paralelismo) | AppSec Lead + Engineers |
| Z.T.K. Camada 3 (PoC/Fuzzing) | Mínimo de agente — majoritariamente humano | Red Team Engineer |
| Z.T.K. Camada 4 (Debate) | Claude Code (Agente Engenheiro) | ML Engineer |
| Z.T.K. Camada 5 (Remediação) | Claude Code | Backend Engineer (Remediação) |
| Z.T.K. Camada 6 (Governança) | Agente de Políticas + Agente IaC | Security Architect + SRE |
| Z.T.K. Camada 7 (Ensemble) | Claude Code | ML Engineer |
| Z.T.K. Camada 8 (Escala) | Agente Arquiteto + Agente IaC | Platform Lead |

---

## 4. Workflows de Desenvolvimento

### 4.1 Workflow Padrão — Feature Nova

```
┌──────────────────────────────────────────────────────────────────┐
│ FASE 1: ESPECIFICAÇÃO (Humano + Agente Arquiteto)                │
├──────────────────────────────────────────────────────────────────┤
│ 1. PM/Lead escreve user story + acceptance criteria              │
│ 2. Agente Arquiteto gera spec técnica (interfaces, schemas)      │
│ 3. Lead revisa e aprova spec                                     │
│ 4. Agente Documentador gera ADR se houver decisão de design      │
└──────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│ FASE 2: IMPLEMENTAÇÃO (Agente Engenheiro + Agente de Testes)     │
├──────────────────────────────────────────────────────────────────┤
│ 1. Agente Engenheiro implementa em branch (código + testes)      │
│ 2. Agente de Testes complementa cobertura + roda suíte           │
│ 3. Agente de IaC gera infra necessária (se aplicável)            │
│ 4. Agente abre PR com summary estruturado                        │
└──────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│ FASE 3: REVIEW (Agente Reviewer + Humano)                        │
├──────────────────────────────────────────────────────────────────┤
│ 1. Agente Reviewer faz primeira passada (checklist automático)   │
│ 2. Humano (Lead da área) faz review final                        │
│ 3. Se P0/P1 ou toca compliance → Security Architect também revisa│
│ 4. Merge após aprovação humana                                   │
└──────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│ FASE 4: DEPLOY & OBSERVABILIDADE (SRE + Agente Monitor)          │
├──────────────────────────────────────────────────────────────────┤
│ 1. CI/CD deploya em staging (automático)                         │
│ 2. Agente Monitor configura alertas e dashboard                  │
│ 3. SRE valida em staging                                         │
│ 4. Deploy em produção (aprovação humana obrigatória)             │
│ 5. Agente Documentador atualiza changelog e runbooks             │
└──────────────────────────────────────────────────────────────────┘
```

### 4.2 Workflow Especial — Batch de 30 Agentes SAST (Camada 2)

A Camada 2 do Z.T.K. tem 30 agentes que seguem o **mesmo padrão arquitetural** (wrapper de ferramenta → executa → parseia SARIF/JSON → emite finding normalizado). Isso é ideal para geração em batch:

```
┌──────────────────────────────────────────────────────────────────┐
│ FASE 1: TEMPLATE (Humano — 1 vez)                                │
├──────────────────────────────────────────────────────────────────┤
│ 1. AppSec Lead implementa manualmente 1 agente de referência     │
│    (ex: L2.01 SAST-Python-Bandit) com todos os padrões           │
│ 2. Documenta o "contrato" do agente wrapper:                     │
│    - Input: arquivo/diff + config                                │
│    - Execução: invoca ferramenta CLI                             │
│    - Output: NormalizedFinding[]                                 │
│    - Fail-closed: timeout/erro → status "não analisado"          │
└──────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│ FASE 2: GERAÇÃO EM BATCH (Agente Engenheiro via Batch API)       │
├──────────────────────────────────────────────────────────────────┤
│ 1. Para cada agente L2.02–L2.30:                                 │
│    - Prompt: "Implemente o agente {ID} seguindo exatamente o     │
│      padrão de L2.01, substituindo a ferramenta por {tool},      │
│      linguagem por {lang}, e ajustando o parser de output        │
│      conforme a documentação da ferramenta {tool_docs_url}"      │
│ 2. Execução paralela (Claude Batch API — até 29 em paralelo)     │
│ 3. Cada output gera uma branch + PR separada                     │
└──────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│ FASE 3: VALIDAÇÃO (Agente de Testes + Humano)                    │
├──────────────────────────────────────────────────────────────────┤
│ 1. Agente de Testes roda suíte padrão contra cada agente         │
│ 2. AppSec Lead revisa amostra (ex: 5 de 29) em detalhe          │
│ 3. Se padrão consistente → aprova batch                          │
│ 4. Se divergência → corrige template e regenera afetados         │
└──────────────────────────────────────────────────────────────────┘

Estimativa: 30 agentes em ~1 semana (vs. 6–8 semanas com equipe tradicional)
```

### 4.3 Workflow de Emergência — Hotfix de Segurança

```
Vulnerabilidade encontrada no próprio pipeline
  → Security Architect classifica severidade
  → Se P0/P1:
      → Agente Engenheiro gera fix imediato (branch hotfix)
      → Agente de Testes roda regressão
      → Security Architect + Platform Lead revisam (fast-track)
      → Deploy imediato (SRE)
  → Se P2+:
      → Segue workflow padrão (Fase 1–4)
```

---

## 5. Contexto Persistente e Memória dos Agentes

### 5.1 Arquivo CLAUDE.md (Raiz do Repo)

Todo agente baseado em Claude Code lê automaticamente o `CLAUDE.md` na raiz do repositório. Este arquivo deve conter:

```markdown
# CLAUDE.md — Contexto do Projeto SAGA-SAGV_V2 + Z.T.K.

## Princípios Invioláveis
1. LLM nunca é decisor primário de segurança — só interpreta saída de ferramenta
2. Fail-closed: dado ausente = comportamento conservador, nunca otimista
3. Toda decisão gera audit event correlacionável por finding_id
4. Nenhuma credencial em variável de ambiente — sempre Secrets Manager
5. Lambda que não precisa de VPC fica fora da VPC
6. Motor de decisão é função pura — sem chamada externa
7. Orquestração multi-step vive em Step Functions, não em código
8. Runbooks são configuração declarativa (YAML), não código
9. Idempotência em tudo que grava estado externo
10. Shadow mode é cidadão de primeira classe desde v1

## Padrões de Código
- Python 3.12+ para Lambdas
- Type hints obrigatórios (mypy strict)
- Pydantic v2 para schemas
- pytest para testes
- Estrutura: handler → service → repository (3 camadas por Lambda)

## Schemas Compartilhados
- NormalizedFinding: ver /schemas/normalized_finding.py
- ContextualizedFinding: ver /schemas/contextualized_finding.py
- Decision: ver /schemas/decision.py
- AuditEvent: ver /schemas/audit_event.py

## Convenções de Naming
- Lambda: {projeto}-{camada}-{componente} (ex: saga-ingest-kev)
- SQS: {projeto}-{camada}-{fonte}-queue (ex: saga-ingest-veracode-queue)
- DynamoDB: {projeto}-{entidade} (ex: saga-findings)
- S3: {projeto}-{propósito}-{account_id} (ex: saga-audit-trail-123456789)

## Arquitetura de Referência
- SAGA-SAGV_V2: ver /docs/SAGA-SAGV-V2_ZTK-Arquitetura-Conjunta.md
- Z.T.K. completo: ver /docs/ZTK-Arquitetura-Completa.md
- MDash referência: ver /docs/MDash-do-Raphael-Arquitetura-Completa.md
```

### 5.2 Specs por Componente (Contexto Localizado)

Cada componente/Lambda tem seu próprio `SPEC.md` na pasta, que o agente lê antes de implementar:

```
/src/saga/ingest/kev/
├── SPEC.md          ← Spec detalhada (inputs, outputs, fail-closed, idempotência)
├── handler.py       ← Entry point Lambda
├── service.py       ← Lógica de negócio
├── repository.py    ← Acesso a dados (DynamoDB, S3)
├── schemas.py       ← Pydantic models locais
└── tests/
    ├── test_service.py
    └── fixtures/
        └── sample_kev_response.json
```

---

## 6. Métricas de Eficiência da Squad Agêntica

### 6.1 KPIs de Produtividade

| Métrica | Meta | Como Medir |
|---------|------|-----------|
| **Cycle Time (spec → merge)** | < 3 dias para componente médio | GitHub/Linear timestamps |
| **% de código gerado por agente** | 60–70% do total de linhas | Git blame + tag de autor |
| **% de PRs com zero rework após review** | > 50% | Contagem de review rounds |
| **Cobertura de testes** | > 85% (motor SSVC: 100%) | Coverage reports |
| **Tempo de review humano por PR** | < 30 min (média) | Timestamps de review |
| **Throughput semanal** | 8–12 componentes/semana (fase de pico) | Contagem de merges |

### 6.2 KPIs de Qualidade

| Métrica | Meta | Como Medir |
|---------|------|-----------|
| **Bugs em produção por sprint** | < 2 (P3+) | Incident tracker |
| **Falsos positivos do Agente Reviewer** | < 20% dos comentários | Sampling mensal |
| **Conformidade com padrões (lint/type check)** | 100% (CI bloqueia) | CI pipeline |
| **Drift de IaC (plan ≠ state)** | 0 | Terraform plan scheduled |

### 6.3 KPIs de Custo

| Métrica | Meta | Como Medir |
|---------|------|-----------|
| **Custo mensal de API de agentes** | < R$ 15.000/mês (fase de pico) | Billing Claude/OpenAI |
| **Custo por componente implementado** | < R$ 500 | Custo total / componentes entregues |
| **ROI vs. headcount adicional** | > 3x | (Custo de 10 devs adicionais) / (custo de agentes + overhead) |

---

## 7. Riscos e Mitigações da Abordagem Agêntica

| Risco | Impacto | Mitigação |
|-------|---------|-----------|
| Agente gera código com vulnerabilidade | Alto (irônico para um projeto de segurança) | Agente Reviewer + review humano obrigatório + SAST no próprio CI |
| Alucinação em spec/arquitetura | Médio | Agente Arquiteto sempre gera proposta, nunca decide; humano valida |
| Dependência excessiva de API comercial | Médio | Budget cap + fallback para modelo local (o próprio Z.T.K. resolve isso) |
| Inconsistência entre agentes (cada um gera de um jeito) | Médio | CLAUDE.md + templates + Agente Reviewer como guardrail de consistência |
| Contexto perdido entre sessões | Baixo-Médio | CLAUDE.md persistente + SPEC.md por componente + ADRs versionados |
| Custo de API escala descontrolado | Médio | Circuit breaker de custo (meta mensal), batch API para volume, cache de prompts |
| Humano vira "aprovador de rubber stamp" | Alto | Rotação de reviewers, métricas de tempo de review, sampling de qualidade |

---

## 8. Cronograma com Squad Agêntica

### Fase 1 — MVP1 (SAGA-SAGV_V2): 8–10 semanas (vs. 12–16 sem agentes)

| Semana | Foco | Agentes Ativos | Humanos Ativos |
|--------|------|----------------|----------------|
| 1–2 | Setup: repo, CI/CD, IaC base, CLAUDE.md, schemas | Agente IaC, Agente Docs | Platform Lead, SRE, Backend Sr. |
| 3–4 | Conectores (S1–S6) + Normalização (S7) | Agente Engenheiro (batch), Agente Testes | Backend Engineer (Conectores) |
| 5–6 | Motor SSVC (S10) + Enriquecimento (S8–S9) | Agente Engenheiro, Agente Testes | Backend Sr. (review intensivo) |
| 7–8 | Orquestração (S11–S13) + Audit Trail (S15) | Agente Engenheiro, Agente IaC | Backend (Remediação), SRE |
| 9–10 | Integração fim-a-fim, shadow mode, staging | Agente Monitor, Agente Docs | Todos (validação) |

### Fase 2 — Z.T.K. Camadas 1–3: 10–12 semanas

| Semana | Foco | Agentes Ativos | Humanos Ativos |
|--------|------|----------------|----------------|
| 1–2 | Camada 1 (7 agentes de triagem) | Agente Engenheiro | AppSec Lead, Backend Sr. |
| 3–5 | Camada 2 (30 agentes SAST/Hardening) — **batch** | Agente Engenheiro (Batch API), Agente Testes | AppSec Lead (template + review amostral) |
| 6–8 | Camada 3.1–3.3 (Reachability + PoC) | Agente Engenheiro (infra de sandbox) | **Red Team** (lógica de exploit — humano) |
| 9–10 | Camada 3.4 (Score Engine) + integração C1→C3 | Agente Engenheiro, Agente Testes | Backend Sr. |
| 11–12 | Validação fim-a-fim, shadow mode | Agente Monitor | Todos |

### Fase 3 — Z.T.K. Camadas 4–8 + Integração: 10–14 semanas

| Semana | Foco | Agentes Ativos | Humanos Ativos |
|--------|------|----------------|----------------|
| 1–3 | Camada 4 (Debate adversarial) | Agente Engenheiro | ML Engineer (prompt design) |
| 4–6 | Camada 5 (Remediação dual-track) | Agente Engenheiro, Agente IaC | Backend (Remediação), Platform Lead |
| 7–9 | Camada 6 (Governança) + Camada 7 (Ensemble) | Agente Políticas, Agente IaC | Security Architect, ML Engineer |
| 10–11 | Camada 8 (Escala) + Multi-tenancy prep | Agente Arquiteto, Agente IaC | Platform Lead |
| 12–14 | Integração SAGA↔Z.T.K., produção | Agente Monitor, Agente Docs | Todos |

**Total estimado: 28–36 semanas** (vs. 40–52 semanas com squad tradicional de 20+ pessoas)

---

## 9. Modelo de Custo Estimado

### 9.1 Custo Mensal de Agentes de IA

| Item | Estimativa Mensal |
|------|------------------|
| Claude API (Sonnet 5 — desenvolvimento principal) | R$ 5.000–8.000 |
| Claude API (Opus 4 — arquitetura/complexo) | R$ 1.000–2.000 |
| Claude Batch API (geração em massa, Camada 2) | R$ 2.000–3.000 (pico, 1–2 meses) |
| Cursor/Windsurf licenças (3–4 devs) | R$ 800–1.200 |
| CodeRabbit (review automatizado) | R$ 500–800 |
| GitHub Copilot (complementar) | R$ 400–600 |
| **Total mensal (fase de pico)** | **R$ 10.000–16.000** |
| **Total mensal (steady-state)** | **R$ 5.000–8.000** |

### 9.2 Comparativo de Custo Total (12 meses)

| Modelo | Headcount | Custo Anual Estimado (CLT + encargos) | Custo de Agentes | Total |
|--------|-----------|---------------------------------------|-------------------|-------|
| Squad Tradicional (20–25 pessoas) | 22 | R$ 6.600.000–8.250.000 | R$ 0 | **R$ 6.6M–8.2M** |
| Squad Agêntica (8–12 pessoas + agentes) | 10 | R$ 3.000.000–3.960.000 | R$ 120.000–192.000 | **R$ 3.1M–4.2M** |
| **Economia estimada** | | | | **~R$ 3.5M–4.0M/ano** |

*Premissas: salário médio de R$ 25.000/mês por dev sênior (CLT com encargos ~1.8x).*

---

## 10. Checklist de Implementação

### Para começar amanhã:

- [ ] Criar repositório com estrutura de pastas por camada
- [ ] Escrever `CLAUDE.md` com princípios e padrões (seção 5.1 deste doc)
- [ ] Definir schemas Pydantic compartilhados (NormalizedFinding, Decision, AuditEvent)
- [ ] Implementar manualmente 1 conector de referência (KEV — mais simples)
- [ ] Configurar CI com linting, type check, testes e Agente Reviewer
- [ ] Configurar Claude Code com acesso ao repo
- [ ] Escrever SPEC.md para os próximos 5 componentes prioritários
- [ ] Iniciar geração agêntica dos conectores restantes

### Para a primeira semana:

- [ ] Todos os 6 conectores implementados e testados
- [ ] Motor SSVC implementado com 100% da matriz de testes
- [ ] IaC base (VPC, Lambda, SQS, DynamoDB) deployada em staging
- [ ] Pipeline CI/CD completo (build → test → review → staging)
- [ ] Primeiro fluxo fim-a-fim rodando em shadow mode

---

## Apêndice A — Prompt Templates para Agentes

### A.1 Template para Agente Engenheiro — Novo Conector

```
Implemente o conector Lambda para {FONTE} seguindo exatamente o padrão
estabelecido em /src/saga/ingest/kev/ (conector de referência).

Requisitos:
1. Handler: recebe evento EventBridge/SQS, invoca service
2. Service: consulta API {FONTE} com paginação, compara com último estado
   em DynamoDB, publica apenas novos/alterados via SQS
3. Repository: DynamoDB para estado, S3 para snapshot bruto canônico
4. Schemas: Pydantic models para response da API {FONTE}
5. Fail-closed: API indisponível → preserva último estado válido, nunca
   para o pipeline
6. Idempotência: event_id = sha256("{fonte}|upsert|{id}|{record_hash}")
7. Testes: mínimo 5 cenários (happy path, API down, resposta vazia,
   dado duplicado, dado novo)

API docs da fonte: {URL_DOCS}
Schema de NormalizedFinding: /schemas/normalized_finding.py
Padrão de audit event: /schemas/audit_event.py
```

### A.2 Template para Agente Engenheiro — Agente SAST (Camada 2)

```
Implemente o agente {ID} ({NOME}) para o Z.T.K. seguindo o padrão de
/src/ztk/layer2/sast_python_bandit/ (agente de referência).

Especificações:
- Linguagem alvo: {LINGUAGEM}
- Ferramenta: {FERRAMENTA}
- Foco principal: {FOCO}
- Fail-closed: timeout/falha → status "não analisado", nunca "aprovado"

O agente deve:
1. Receber arquivo/diff como input
2. Invocar {FERRAMENTA} via subprocess com timeout configurável
3. Parsear output ({FORMATO}: SARIF/JSON/texto) em NormalizedFinding[]
4. Emitir findings normalizados + audit event
5. Nunca interpretar o código-fonte diretamente — apenas a saída da ferramenta

Docs da ferramenta: {URL_DOCS}
Formato de output: {FORMATO}
Schema de NormalizedFinding: /schemas/normalized_finding.py
```

### A.3 Template para Agente de Políticas — Nova Regra OPA/Rego

```
Traduza a seguinte regra de negócio em política OPA/Rego testável:

REGRA: "{DESCRIÇÃO_EM_PORTUGUÊS}"

Requisitos:
1. Package name: {PACKAGE}
2. Input schema: ver /schemas/{SCHEMA_RELEVANTE}.py
3. Output: decisão booleana ou valor enumerado
4. Testes: mínimo 3 cenários (regra aplica, regra não aplica, input incompleto)
5. Documentação inline explicando a regra em linguagem natural
6. Fail-closed: input incompleto → comportamento mais conservador

Referência de estilo: /policies/severity_floors.rego
```

---

## Apêndice B — Matriz de Decisão: Agente vs. Humano

| Critério | → Agente de IA | → Humano |
|----------|----------------|----------|
| Tarefa tem spec clara e determinística? | ✅ Sim | |
| Tarefa é repetitiva/paralelizável? | ✅ Sim | |
| Erro é facilmente detectável por teste? | ✅ Sim | |
| Tarefa requer julgamento ético/legal? | | ✅ Sim |
| Decisão é irreversível em produção? | | ✅ Sim |
| Tarefa requer acesso a credenciais reais? | | ✅ Sim |
| Tarefa requer negociação com stakeholder? | | ✅ Sim |
| Tarefa requer criatividade/inovação arquitetural? | | ✅ Sim (com assist. de agente) |
| Tarefa requer contexto de negócio não documentado? | | ✅ Sim |
| Tarefa é verificável por CI/CD automatizado? | ✅ Sim | |

---

*Documento gerado como referência para a organização da squad agêntica do projeto SAGA-SAGV_V2 + Z.T.K. Deve ser revisado e adaptado conforme o contexto organizacional específico.*