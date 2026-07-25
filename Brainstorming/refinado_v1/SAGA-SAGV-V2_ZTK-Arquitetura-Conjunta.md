# Arquitetura de Segurança Cielo: SAGA-SAGV_V2 (MVP1) + Z.T.K. (MVP2)

**Documento técnico-executivo consolidado**

---

## Sumário Executivo

Este documento consolida dois projetos irmãos que compartilham a mesma filosofia de engenharia — **decisão de segurança é sempre determinística; LLM nunca decide, só interpreta ou copilota** — mas que atacam metades diferentes do mesmo problema:

- **SAGA-SAGV_V2 (MVP1):** um motor de **priorização e resposta** a vulnerabilidades já conhecidas, vindas de scanners comerciais (Veracode, Orca, Tenable) e feeds públicos (CISA KEV, FIRST EPSS). Não escaneia nada por conta própria — orquestra o que já existe, decide com uma árvore SSVC auditável, e aciona ticket (Jira) ou mitigação de borda (Akamai).
- **Z.T.K. (MVP2 — evolução):** uma plataforma de **detecção e autocorreção próprias**, com mais de 100 agentes especializados (SAST por linguagem/ferramenta, validação de exploit via PoC/fuzzing, debate adversarial de severidade, geração de patch e contenção automática em WAF/firewall).

A ordem MVP1 → MVP2 não é arbitrária: o SAGA-SAGV_V2 entrega valor imediato orquestrando ferramentas que a Cielo já possui (Veracode, Orca, Tenable), com investimento de engenharia relativamente baixo. O Z.T.K. é o passo seguinte — um investimento maior, que constrói capacidade de detecção e remediação próprias em vez de depender apenas de scanners de terceiros. Ao final, os dois se conectam: o Z.T.K. se torna **mais uma fonte de conector** dentro do SAGA-SAGV_V2, e ambos compartilham a mesma camada de contenção de borda.

---

# Parte 1 — MVP1: SAGA-SAGV_V2

## 1.1 Objetivo

Automatizar o ciclo de **priorização, mitigação e remediação** de vulnerabilidades já identificadas por ferramentas existentes, substituindo a prática de usar CVSS isolado como critério de priorização por um modelo de risco real — SSVC (Stakeholder-Specific Vulnerability Categorization), alinhado à diretriz CISA BOD 26-04.

Resumo em uma frase: transformar achados brutos de 4 ferramentas em uma decisão automática e auditável (`TRACK` / `TRACK*` / `ATTEND` / `ACT`), com SLA correspondente, mitigação automática para os casos críticos, e trilha de evidência nativa para auditoria PCI DSS 4.0 / BACEN.

## 1.2 Stack de Referência

| Camada | Ferramenta/Componente |
|---|---|
| SAST/SCA em esteira | Veracode |
| Repositórios/CI | GitHub Enterprise |
| Exposição e vulnerabilidades cloud | Orca Security |
| Exposição e vulnerabilidades on-premises | Tenable (Vulnerability Management / tenable.sc) |
| Exploração confirmada | Feed CISA KEV (público, sem autenticação) |
| Probabilidade de exploração | FIRST EPSS API (público) |
| Contexto de negócio (CMDB) | Jira Assets (módulo CMDB do Jira Service Management) |
| Orquestração/tickets | Jira (`/rest/api/3/issue`) |
| Mitigação automática (borda/WAF) | Akamai — Network Lists API (bloqueio de IP) + Application Security API (regras/políticas) |
| Motor de decisão | Função interna determinística — **sem LLM** |
| Copiloto de análise (tier `ATTEND`, fase 4) | Claude Haiku 4.5 (rotina) → escala para Claude Sonnet 5 em ambiguidade |
| Base de conhecimento do copiloto (RAG, fase 4) | Aurora PostgreSQL Serverless v2 + `pgvector` |
| Feedback/recalibração (fase 4, periódico) | Claude Sonnet 5 via Batch API |

**Infraestrutura:** AWS, serverless-first. Motor de regras como serviço leve (Lambda), não plataforma SOAR. Em aberto: ferramenta de IaC (Terraform vs. CDK vs. SAM) e firewall/NAC on-premises complementar ao Akamai.

## 1.3 Arquitetura — Fluxo de Dados

```
Fontes externas (Veracode, GitHub, Orca, Tenable, KEV, EPSS)
  → Conectores (1 Lambda handler por fonte, fila SQS dedicada)
  → Normalização (Lambda, disparada por evento SQS) → NormalizedFinding
  → Enriquecimento
      /exposure (Lambda) → is_publicly_exposed
      /business_context (Lambda, consulta Jira Assets) → business_criticality
  → ContextualizedFinding (DynamoDB, SK=CONTEXT) → evento finding.contextualized
  → Motor de Decisão (Lambda pura, RF4) → Decision
  → Orquestração (Lambda) → cria/atualiza chamado no Jira
  → Mitigação (se ACT_3): runbooks declarativos → Akamai (Network Lists / App Security API)
  → Forensics Trigger (Lambda, se ACT_3): abertura de incidente
  → Continuous Reassessment (reage a EventBridge Scheduler KEV/EPSS + DynamoDB Streams)
  → Governance Dashboard (QuickSight/Athena sobre o data lake de auditoria)
```

Cada pasta de nível superior do repositório corresponde a uma ou mais Lambdas **deployáveis e testáveis de forma independente** — a falha de uma função não pode travar as demais (isolamento por fila SQS dedicada por fonte).

## 1.4 Motor de Decisão (SSVC Adaptado)

O documento mais importante do projeto. Pseudocódigo determinístico — **sem chamada a LLM nesta etapa** — para que qualquer linguagem implemente exatamente a mesma árvore.

**Entrada** — campos que participam da árvore:
- `exposure.is_publicly_exposed`
- `exploitation.in_kev_catalog`
- `exploitation.is_exploit_automatable`
- `technical_impact` (`none | partial | total`)
- `business_context.business_criticality` (`critical | high | medium | low`)

**Saída** — `Decision` com `decision` em `{TRACK, TRACK_STAR, ATTEND, ACT_3, ACT_14}` e `sla_days` correspondente.

### Tabela de SLA por Decisão

| Decisão | `sla_days` | Toque humano |
|---|---|---|
| `TRACK` | null (sem SLA) | Nenhum |
| `TRACK_STAR` | null (monitorar) | Nenhum, exceto reclassificação por evento |
| `ATTEND` | 14–60 (faixa a definir com o time de risco) | Leve (validação + priorização) |
| `ACT_14` | 14 | Sim — priorização máxima na fila de engenharia |
| `ACT_3` | 3 | Sim — mitigação automática + triagem forense + escalação executiva |

### Árvore de Decisão (Resumo dos Nós)

1. **Exposição** — se não exposto publicamente → `TRACK`.
2. **Status KEV** — se não está no catálogo KEV, avalia automação do exploit e impacto técnico → `TRACK_STAR` ou `ATTEND` conforme combinação.
3. **KEV confirmado** — se não é (impacto total **E** automatizável) → `ATTEND`.
4. **Todas as condições de alto risco presentes** (exposto + KEV + automatizável + impacto total) → decide por **criticidade de negócio**: `ACT_3` (crítico) ou `ACT_14` (não crítico).

### Matriz de Cobertura de Teste (Obrigatória)

| # | exposed | kev | automatable | impact_total | business_critical | Resultado |
|---|---|---|---|---|---|---|
| 1 | false | — | — | — | — | `TRACK` |
| 2 | true | false | false | false | — | `TRACK_STAR` |
| 3 | true | false | false | true | — | `ATTEND` |
| 4 | true | false | true | true | — | `ATTEND` |
| 5 | true | false | true | false | — | `ATTEND` |
| 6 | true | true | false | true | — | `ATTEND` |
| 7 | true | true | true | false | — | `ATTEND` |
| 8 | true | true | true | true | true | `ACT_3` |
| 9 | true | true | true | true | false | `ACT_14` |

### Regras de Implementação

- `ATTEND_SLA_DAYS` é constante configurável, não hardcoded — a faixa exata é decisão de risco, não de engenharia.
- O motor **nunca lança exceção por dado ausente** — `business_criticality` ausente aplica fallback conservador (`critical`) **antes** da chamada, não dentro da função de decisão.
- Toda decisão grava `rationale` completo (lista de strings) — sustenta a auditoria (RF9). Nunca omitido "para simplificar o log".
- Mudança na árvore exige, nesta ordem: (1) atualizar o documento de especificação, (2) atualizar a matriz de teste, (3) só então alterar código.
- **Campos que NÃO influenciam a árvore** (apenas evidência auditável): `epss_score`, `epss_percentile`, `technical_exploit_source`, `pci_scope`, `environment`, `data_classification`, `owner`, `context_source`, `exposure_source/confidence`, `asset_type`, `scanners`, `severities_native`.

## 1.5 Trilha de Auditoria (Execution Audit Trail)

Camada determinística de auditoria **append-only**, alimentando um data lake S3 consultável via Athena/QuickSight. Não altera decisão, orquestração ou mitigação — é observador puro.

**Estágios auditados:** `rawfinding` → `normalized` → `enriched` → `decision` → `orchestration` → `mitigation`.

**Particionamento S3:**
```
s3://{AUDIT_BUCKET}/audit/stage={stage}/dt=YYYY-MM-DD/finding_id={id}/audit_id={hash}.json
```

- **Append-only real:** `If-None-Match: *` + verificação `head_object`.
- **Idempotência:** mesma trinca `finding_id + stage + payload_hash` → skip sem falha.
- **`audit_id`:** `sha256(finding_id|stage|payload_hash)`, sem serialização JSON no hash.

## 1.6 Padrão de Conector — Exemplo FIRST EPSS

Todo conector segue o mesmo modelo normativo de resiliência (referência: `LAMBDA_INGEST_KEV_SPEC.md`):

- Consulta a API pública com paginação/filtro opcional.
- Preserva o **snapshot bruto canônico** como evidência de auditoria em S3 (inclusive quarentena para snapshot inválido).
- Compara o catálogo corrente com o **último estado aceito** (DynamoDB) — publica só o que é **novo ou alterado**.
- **Nunca lança exceção não tratada** que pare o restante do pipeline — falha de uma fonte não derruba as demais.
- Degrada preservando o **último estado válido** quando a origem está indisponível.
- Idempotência por `event_id = sha256("epss|upsert|{cve_id}|{record_hash}")`.

## 1.7 Camada de IA — O Que Usa LLM e o Que Não Usa

| Atividade | Modelo | Racional |
|---|---|---|
| Motor de decisão (RF4) | **Nenhum** — regra determinística | Decisão de segurança nunca é LLM |
| Copiloto de Análise — rotina (`ATTEND`) | Claude Haiku 4.5 | Classificação/resumo de baixo custo, volume já reduzido (10–30% dos achados) |
| Copiloto de Análise — sinal ambíguo/conflitante | Claude Sonnet 5 | Escalação seletiva, não em massa |
| Feedback/Recalibração (periódico) | Claude Sonnet 5 + Batch API | Não é time-sensitive, desconto de custo |
| Construção do projeto (Claude Code) | Sonnet 5 padrão / Opus 4.8 pontual | Não faz parte do runtime em produção |

O copiloto é **read-only** — consome a saída do motor para ajudar o analista a interpretar itens `ATTEND`; nunca participa da decisão determinística.

## 1.8 Convenções de Engenharia (Regras Estruturais)

- **Nenhuma credencial de terceiro em variável de ambiente de Lambda em produção** — lida do AWS Secrets Manager em runtime, com IAM restrito ao segredo específico.
- **Lambda que não precisa alcançar ambiente on-premises fica fora da VPC** — evita NAT Gateway desnecessário.
- **O motor de decisão é uma função pura** — não chama API externa diretamente, recebe `EnrichedFinding`/`ContextualizedFinding`, devolve `Decision`.
- **Orquestração de múltiplas etapas vive no Step Functions, não em código** — Lambda chamando Lambda diretamente para "encadear" fluxo é sinal de que a lógica deveria estar na state machine.
- **Runbooks de mitigação são configuração declarativa versionada** (YAML/JSON: gatilho, escopo, ação, rollback), lida em runtime — nunca branch de código por runbook. É o que permite ao CAB revisar e aprovar o runbook como artefato.
- **Idempotência em tudo que grava estado externo** — criação de ticket, execução de runbook e registro de decisão são seguros para reexecução com o mesmo `finding_id`.
- **Modo shadow é cidadão de primeira classe** — o parâmetro `mode: shadow | production` existe desde a primeira versão do motor, não é adicionado depois.

## 1.9 Não-Escopo (v1)

- Não substitui o scanner/ferramenta de origem — apenas consome os achados via API.
- Não decide sozinho sobre exceções de risco aceito — permanece humano, apenas registrado.
- **Não executa patch/deploy de correção** — apenas mitigação compensatória (runbooks) e abertura/roteamento de chamado.
- Copiloto LLM de análise é auxiliar de leitura, não decisor.

> Este último ponto — a ausência de correção de código — é exatamente a lacuna estrutural que o **Z.T.K. (MVP2)** preenche.

## 1.10 Lista Completa de Componentes (Lambdas/Serviços) por Camada

Diferente do Z.T.K., o SAGA-SAGV_V2 não é desenhado como um sistema multiagente — é um pipeline serverless de Lambdas determinísticas, cada uma testável e deployável de forma independente. Ainda assim, cada componente cumpre o mesmo papel funcional de um "agente": recebe um dado de entrada, aplica uma responsabilidade única e determinística, e devolve/publica uma saída rastreável.

| ID | Componente | Camada | Função | Tecnologia/Dependência |
|---|---|---|---|---|
| S1 | Connector-Veracode | 1. Ingestão | Ingesta achados de SAST/SCA da esteira | Lambda + API Veracode |
| S2 | Connector-GitHub | 1. Ingestão | Ingesta metadados de repositório/PR | Lambda + GitHub Enterprise API |
| S3 | Connector-Orca | 1. Ingestão | Ingesta exposição/vulnerabilidade cloud | Lambda + API Orca Security |
| S4 | Connector-Tenable | 1. Ingestão | Ingesta exposição/vulnerabilidade on-premises | Lambda + API Tenable (VM/tenable.sc) |
| S5 | Connector-KEV | 1. Ingestão | Ingesta catálogo de exploração confirmada | Lambda + Feed público CISA KEV |
| S6 | Connector-EPSS | 1. Ingestão | Ingesta probabilidade de exploração | Lambda + API pública FIRST EPSS |
| S7 | Normalization | 2. Normalização | Converte achado bruto em `NormalizedFinding` | Lambda, disparada por evento SQS |
| S8 | Enrichment-Exposure | 3. Enriquecimento | Determina `is_publicly_exposed` | Lambda |
| S9 | Enrichment-BusinessContext | 3. Enriquecimento | Determina `business_criticality` | Lambda + consulta Jira Assets (CMDB) |
| S10 | Decision-Engine | 4. Motor de Decisão | Aplica a árvore SSVC determinística (RF4) | Lambda pura — sem chamada externa |
| S11 | Orchestration-Jira | 5. Orquestração/Mitigação | Cria/atualiza chamado conforme decisão | Lambda + Jira API (`/rest/api/3/issue`) |
| S12 | Mitigation-Akamai-Runbook | 5. Orquestração/Mitigação | Executa runbook declarativo de mitigação | Lambda + Akamai (Network Lists/App Security API) |
| S13 | Forensics-Trigger | 5. Orquestração/Mitigação | Abre incidente forense para `ACT_3` | Lambda |
| S14 | Continuous-Reassessment | 6. Reavaliação Contínua | Reage a mudança de KEV/EPSS e reclassifica | Lambda + EventBridge Scheduler + DynamoDB Streams |
| S15 | Audit-Trail | 7. Governança/Auditoria | Grava evidência append-only de todos os estágios | Lambda + S3 (particionado) + Athena/QuickSight |
| S16 | Governance-Dashboard | 7. Governança/Auditoria | Visualização executiva de métricas e conformidade | QuickSight/Athena (não é Lambda de runtime) |
| S17 | Copilot-Routine | 8. Copiloto de IA (Fase 4) | Resume/classifica achados `ATTEND` de rotina | Claude Haiku 4.5, read-only |
| S18 | Copilot-Escalation | 8. Copiloto de IA (Fase 4) | Analisa achados `ATTEND` ambíguos/conflitantes | Claude Sonnet 5, read-only |
| S19 | Copilot-Feedback-Recalibration | 8. Copiloto de IA (Fase 4) | Recalibração periódica não time-sensitive | Claude Sonnet 5 + Batch API |

**Total: 19 componentes em 8 camadas.** Note que apenas S17–S19 (Fase 4) tocam LLM — as demais 16 Lambdas (Camadas 1–7) são 100% determinísticas, reforçando o princípio central do projeto.

| Camada | Nº de Componentes | IDs |
|---|---|---|
| 1 — Ingestão (Conectores) | 6 | S1–S6 |
| 2 — Normalização | 1 | S7 |
| 3 — Enriquecimento | 2 | S8–S9 |
| 4 — Motor de Decisão | 1 | S10 |
| 5 — Orquestração/Mitigação | 3 | S11–S13 |
| 6 — Reavaliação Contínua | 1 | S14 |
| 7 — Governança/Auditoria | 2 | S15–S16 |
| 8 — Copiloto de IA (Fase 4) | 3 | S17–S19 |
| **Total** | **19** | — |

---

# Parte 2 — MVP2 / Evolução: Z.T.K.

## 2.1 Objetivo

Enquanto o SAGA-SAGV_V2 organiza a resposta a vulnerabilidades já conhecidas, o **Z.T.K.** (inspirado no MDASH da Microsoft) constrói **capacidade própria de detecção e autocorreção**: agentes que fazem SAST por linguagem/ferramenta, validam exploitabilidade real via PoC e fuzzing, debatem severidade de forma adversarial, geram patch de código, e aplicam contenção automática em WAF/firewall — tudo em ambiente de alta exigência regulatória (adquirência, PCI DSS, LGPD, antifraude).

O mesmo princípio central do SAGA-SAGV_V2 se mantém, levado a um sistema mais complexo:

> **"Sempre que existir uma ferramenta determinística capaz de resolver a tarefa, o LLM não decide — ele apenas interpreta a saída da ferramenta. LLM só atua onde há ambiguidade genuína que uma regra não cobre, e mesmo assim sua saída permanece rastreável e contestável."**

## 2.2 As 8 Camadas, em Uma Frase Cada

| Camada | Nome | Responsabilidade |
|---|---|---|
| 1 | Entrada & Triagem | Recebe código, classifica linguagem/criticidade, protege contra prompt injection |
| 2 | Especialistas de Segurança (Estáticos) | SAST, Segredos, Dependências e Hardening (AppSec/DB/Infra/OS/Network) — 30+ agentes, um por linguagem/ferramenta |
| 3 | Validação | Reachability, PoC agressivo por classe de CWE e fuzzing sob aprovação humana |
| 4 | Consenso/Debate | Severidade via debate adversarial (Prosecutor/Defender/Judge), com piso não-negociável para PCI/LGPD/Antifraude |
| 5 | Remediação | Trilha A (patch de código, PR, nunca merge automático em P0/P1) + Trilha B (contenção automática em WAF/firewall) em paralelo |
| 6 | Governança | Policy Engine único (OPA/Rego), auditoria unificada (Sentinel), HITL centralizado, exceção com dupla aprovação executiva |
| 7 | Model Ensemble | Roteia LLM entre modelo local (AWS EC2/EKS, escopo PCI) e AWS Bedrock (escopo não-PCI), com ensemble no patch generator |
| 8 | Escala e Especialização | Ativação condicional, ciclo de vida de ferramentas, onboarding formal, preparação para multi-tenancy |

**Números de referência:** ~26 arquétipos de agente, 100+ instâncias concretas quando shardados por linguagem/ferramenta/domínio — mesma ordem de grandeza do MDASH real da Microsoft.

## 2.3 Diferenciais Estruturais em Relação ao MVP1

| Dimensão | SAGA-SAGV_V2 (MVP1) | Z.T.K. (MVP2) |
|---|---|---|
| Origem do achado | Ferramentas de terceiros (Veracode, Orca, Tenable) | Agentes próprios (Bandit, Semgrep, CodeQL, gosec, etc.) |
| Prova de exploitabilidade | Proxy estatístico (EPSS/KEV) | PoC real, sandboxed, agressivo por classe de CWE |
| Modelo de julgamento de severidade | Árvore SSVC de nós fixos | Debate adversarial (Prosecutor/Defender/Judge) |
| Correção de código | **Fora de escopo** — apenas mitigação compensatória | Gera patch, valida em sandbox, abre PR |
| Contenção de borda | Runbook Akamai (Network Lists/App Security) | WAF multi-vendor (F5, Akamai, Azure), com dry-run e TTL |
| Governança de exceção | CAB aprova runbook como artefato antes do deploy | Four-eyes (Gerente Executivo + Superintendente) por achado específico |
| Modelo de custo de LLM | Haiku/Sonnet, roteamento por ambiguidade | Ensemble local (EC2/EKS) vs Bedrock, roteamento por escopo de dado + tier de tarefa |

## 2.4 Lista Completa de Agentes por Camada (133 Agentes)

Diferente do SAGA-SAGV_V2, o Z.T.K. é desenhado desde a origem como sistema multiagente — cada agente tem responsabilidade única, dependência técnica explícita e comportamento fail-closed definido. A contagem abaixo reflete os arquétipos já detalhados na arquitetura completa das 8 camadas:

| Camada | Nome | Nº de Agentes | Faixa de IDs |
|---|---|---|---|
| 1 | Entrada & Triagem | 7 | L1.01–L1.07 |
| 2 | Especialistas de Segurança (SAST + Segredos + Deps + Hardening) | 30 | L2.01–L2.30 |
| 3 | Validação (Reachability + PoC + Fuzzing + Score) | 18 | L3.01–L3.18 |
| 4 | Consenso/Debate (Scoring + Piso + Debate + Divergência) | 14 | L4.01–L4.14 |
| 5 | Remediação (Trilha A + Trilha B + Kill Switch + Escalação) | 17 | L5.01–L5.17 |
| 6 | Governança (Policy Engine + Exceção + Auditoria + HITL) | 17 | L6.01–L6.17 |
| 7 | Model Ensemble (Roteamento + Local + Bedrock + Custo) | 15 | L7.01–L7.15 |
| 8 | Escala e Especialização (Ativação + Ferramentas + Onboarding + Multi-tenant) | 15 | L8.01–L8.15 |
| **Total** | | **133** | — |

**Detalhamento por subcamada (onde a concentração de agentes vive):**

| Camada | Subcamada | Nº de Agentes |
|---|---|---|
| 2 | SAST por linguagem × ferramenta (L2.01–L2.16) | 16 |
| 2 | Hardening por domínio — AppSec/DB/Infra/OS/Network (L2.17–L2.24) | 8 |
| 2 | Segredos (L2.25–L2.26) | 2 |
| 2 | SBOM/Dependências (L2.27) | 1 |
| 2 | Correlação de CVE — NVD/OSV/GHSA (L2.28–L2.30) | 3 |
| 3 | Reachability estática + dinâmica + config/DI (L3.01–L3.03) | 3 |
| 3 | PoC/Exploit por classe de CWE (L3.04–L3.12) | 9 |
| 3 | Fuzzing sob HITL (L3.13–L3.16) | 4 |
| 3 | Score de evidência (L3.17–L3.18) | 2 |
| 5 | Trilha A — fix de código (L5.02–L5.06) | 5 |
| 5 | Trilha B — contenção WAF (L5.07–L5.14) | 8 |
| 5 | Kill switch + escalação de SLA (L5.15–L5.17) | 3 |

**Nota de concentração:** assim como no MDASH real da Microsoft, a maior massa de agentes vive na especialização técnica (Camada 2, com 30 agentes) e na remediação por trilha (Camada 5, com 17 agentes) — não nas camadas de raciocínio de alto nível (Camada 4, debate, com apenas 14). O documento `MDash-do-Raphael-Arquitetura-Completa.md` traz a tabela individual de todos os 133 agentes, com dependência técnica e comportamento fail-closed linha a linha.

## 2.5 Fluxo Consolidado (Camadas 1–5)

```
Repo/PR chega (L1.01) → classifica linguagem + guard de prompt injection (L1.02-03)
  → tagging de criticidade (L1.04) → roteamento de pipeline (L1.05)
  → agentes especialistas da Camada 2 (SAST + Segredos + SCA + CVE + Hardening)
  → reachability estática + dinâmica (L3.01-03) → PoC agressivo por CWE (L3.04-12)
  → score de evidência (L3.17-18)
  → scoring técnico CVSS+EPSS+SSVC (L4.01-04) → piso não-negociável (L4.05-08)
  → debate adversarial (L4.09-11) → prioridade final P0-P4 (L4.14)
  → L5.01 dispara em paralelo:
      Trilha A: patch → sandbox → PR (nunca merge automático em P0/P1)
      Trilha B: template validado → dry-run → deploy WAF (TTL alinhado a SLA PCI)
```

---

# Parte 3 — Visão Conjunta: SAGA-SAGV_V2 + Z.T.K.

## 3.1 Ponto de Integração

O Z.T.K. entra no SAGA-SAGV_V2 como **mais uma fonte de conector**, no mesmo nível de Veracode, Orca e Tenable — mas com um diferencial importante: o achado que ele entrega já vem com **evidência de exploit real** (PoC confirmado, não proxy estatístico) e, frequentemente, com um **patch candidato anexado**. Isso fortalece exatamente os nós 3–6 da árvore SSVC (`is_exploit_automatable`, `technical_impact`) para achados de código-fonte.

Em troca, o SAGA-SAGV_V2 entrega ao achado do Z.T.K. o que ele não modela sozinho: `business_criticality` via CMDB (Jira Assets) e `exposure` via Orca/Tenable — contexto de ativo real.

Na saída, os dois convergem no mesmo controle de borda: **F5 / Akamai / Azure WAF** — Z.T.K. contém vulnerabilidade recém-descoberta em código antes do merge; SAGA-SAGV_V2 contém CVE conhecido crítico em ativo já exposto. Mesma infraestrutura de contenção, gatilhos diferentes, sem duplicar integração.

```
Z.T.K. (achado + PoC confirmado + patch candidato)
  ──────────────────► Conectores externos (SAGA-SAGV_V2)
                              │
                    Motor de decisão SSVC
                              │
              ┌───────────────┴───────────────┐
     Orquestração (Jira)              Mitigação (Akamai/F5/Azure)
                                                │
                                    ◄───────────┘
                          Contenção de borda (Z.T.K. Trilha B)
                          compartilha o mesmo plano de borda
```

## 3.2 Ganhos de Segurança e Cibersegurança

- **Cobertura em duas frentes complementares:** o Z.T.K. reduz o tempo entre "vulnerabilidade introduzida" e "vulnerabilidade corrigida" (shift-left, antes do merge); o SAGA-SAGV_V2 reduz o tempo entre "vulnerabilidade conhecida publicamente" e "resposta organizada" (shift-right, em produção).
- **Evidência de exploit real substituindo proxy estatístico** para achados de código — o PoC do Z.T.K. é uma confirmação, não uma inferência de probabilidade.
- **Eliminação do CVSS isolado como critério único de priorização** em ambos os projetos — SSVC (SAGA-SAGV_V2) e o motor de score multi-evidência + debate adversarial (Z.T.K.) substituem a prática que a Cielo está deixando para trás.
- **Fail-closed consistente ponta a ponta:** dado ausente nunca vira suposição otimista em nenhum dos dois sistemas — vira "crítico" ou "desconhecido" por padrão.
- **Redução de janela de exposição:** contenção automática de borda (ambos os projetos) compra tempo entre detecção e correção definitiva, em vez de deixar o risco ativo enquanto o time de engenharia revisa com calma.
- **Governança de exceção nomeada e auditável:** CAB (SAGA-SAGV_V2) e four-eyes executivo (Z.T.K.) garantem que nenhuma decisão de rebaixar risco crítico aconteça sem responsabilidade nomeada.
- **Trilha de auditoria nativa e nunca opcional** em ambos — sustenta resposta a incidente e auditoria externa sem reconstrução manual de evidência.

## 3.3 Ganhos de ROI

- **Reuso de infraestrutura de borda:** um único cliente Akamai/F5/Azure serve os dois fluxos de contenção, evitando duplicar integração, credenciais e manutenção.
- **Redução de ruído/fadiga de alerta:** SSVC (MVP1) e o motor de score com eliminação de falso positivo (MVP2) reduzem o volume de achados que chegam a um humano, concentrando esforço de engenharia apenas no que é `ACT_3`/`ACT_14`/P0/P1 real.
- **Custo de LLM controlado por desenho, não por sorte:** roteamento por ambiguidade (não por volume) em ambos os projetos, com modelo barato (Haiku, Bedrock distilled) absorvendo o volume de rotina e modelo caro reservado para o resíduo genuinamente ambíguo — circuit breaker de custo evita surpresa de fatura.
- **Menor tempo de remediação = menor custo de exposição:** cada dia que uma vulnerabilidade crítica fica aberta é custo de risco acumulado (potencial multa, incidente, retrabalho); a automação de patch (Z.T.K.) e mitigação (ambos) comprime esse tempo de forma mensurável via SLA por decisão.
- **Aproveitamento do investimento já feito em scanners comerciais** (Veracode/Orca/Tenable) em vez de substituí-los — o MVP1 monetiza ferramentas que a Cielo já paga, adiando o investimento maior (MVP2) até que o valor do MVP1 esteja provado.
- **Shadow mode como redutor de risco de implantação:** nenhum agente ou motor entra em produção decidindo sozinho — reduz custo de incidente causado pelo próprio sistema de segurança.

## 3.4 Ganhos de Redução de Risco

- **Redução de risco de decisão humana inconsistente:** a mesma árvore/motor decide da mesma forma todas as vezes, eliminando variação de julgamento entre analistas diferentes.
- **Redução de risco de vulnerabilidade "esquecida" em contenção temporária:** escalação de SLA estourado (Z.T.K.) e reavaliação contínua via EventBridge Scheduler (SAGA-SAGV_V2, reagindo a mudança de KEV/EPSS) garantem que nada fique "invisível" atrás de uma mitigação que parece ter resolvido o problema.
- **Redução de risco de prompt injection / manipulação do próprio pipeline de segurança:** guard dedicado (Z.T.K. L1.03) e ausência total de LLM na decisão (ambos os projetos) eliminam a superfície de ataque mais nova e menos compreendida em scanners baseados em IA.
- **Redução de risco de fraude transacional:** piso de severidade não-negociável para Antifraude (Z.T.K., P0 fixo) cobre uma classe de vulnerabilidade — race conditions em fluxo de autorização — tipicamente fora do radar de SAST tradicional e de scanners comerciais genéricos.
- **Redução de risco de concentração em fornecedor único:** Z.T.K. reduz dependência de scanners comerciais para detecção; SAGA-SAGV_V2 mantém neutralidade de resposta (Jira + Akamai) independentemente de qual scanner gerou o achado.
- **Redução de risco de regressão introduzida pela própria correção:** guard de regressão (Z.T.K. L5.04) e teste de rollback obrigatório para runbook (SAGA-SAGV_V2) garantem que a "cura" não vire um novo incidente.

## 3.5 Visão Regulatória

| Requisito regulatório | Como SAGA-SAGV_V2 atende | Como Z.T.K. atende |
|---|---|---|
| **PCI DSS 4.0 — Req. 6 (desenvolvimento seguro)** | Prioriza vulnerabilidade de código via Veracode com SLA formal | Detecta e corrige vulnerabilidade de código na origem, antes do merge |
| **PCI DSS 4.0 — Req. 6.3.3 / 6.4.1 (patch e mitigação compensatória)** | Mitigação via Akamai como controle compensatório documentado | Trilha B (WAF) é controle compensatório explícito, com TTL alinhado ao mesmo requisito |
| **PCI DSS 4.0 — Req. 10 (log e trilha de auditoria)** | Audit Trail append-only em S3/Athena, retenção formal | Auditoria unificada alimentando Microsoft Sentinel, mesma exigência de retenção (1 ano / 3 meses prontamente disponíveis) |
| **LGPD (Art. 5º — dado pessoal sensível)** | `business_criticality`/`data_classification` via CMDB influenciam priorização | Piso de severidade não-negociável (P1) para qualquer achado tocando dado pessoal sensível |
| **BACEN (Res. 4.658, 4.893, 85, 3909)** | Decisão determinística e auditável, alinhada a requisitos de gestão de risco cibernético | Governança formal (Policy Engine, four-eyes, HITL) alinhada aos mesmos normativos |
| **CISA BOD 26-04 (base do modelo SSVC)** | Implementação direta do modelo SSVC como motor de decisão central | Scoring técnico incorpora SSVC como uma das três fontes (junto de CVSS/EPSS) |
| **Exigência de decisão explicável/contestável (ambos)** | `rationale` obrigatório em toda `Decision`, nunca omitido | Justificativa escrita obrigatória do Judge em todo debate adversarial |
| **Segregação de função / dupla aprovação** | CAB aprova runbook como artefato antes do deploy | Four-eyes (Gerente Executivo + Superintendente) para exceção pontual a piso de compliance |

**Leitura regulatória conjunta:** nenhum dos dois sistemas depende de "confiar no modelo de IA" para sustentar uma auditoria — a decisão de risco em si é sempre determinística e documentada, com o LLM restrito a um papel auxiliar (copiloto de leitura no MVP1, intérprete/debatedor com saída contestável no MVP2). Isso é o argumento estrutural que sustenta ambos os projetos perante um auditor PCI DSS ou BACEN: a IA acelera o processo, mas nunca é o processo em si.
