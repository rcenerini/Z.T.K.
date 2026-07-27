# SAGA-SAGV — Escopo de Evolução
## Da Implementação V2 ao Roadmap de Maturidade em Gestão de Vulnerabilidades com IA

> **Data:** 2026-07-21 (atualizado com análise NRM_134)
> **Fontes base:**
> - `SAGA-SAGV_V2/vuln-mgmt-project` — projeto em execução (PRD, ARCHITECTURE, DECISION_ENGINE_SPEC, INTEGRATIONS, TASKS)
> - `SAGA-SAGV_V3/relatorio_vulnerabilidades.md` — pesquisa de estado da arte global
> - `SAGA-SAGV_V3/mapeamento_projetos_gestao_vulnerabilidades.md` — mapeamento de projetos por horizonte
> - `vma-veracode/_Agents-GVul/skills/avaliacao-classificacao-vulnerabilidades/SKILL.md` — **modelo de pesos atual (NRM_134)**
> - `vma-veracode/_Agents-GVul/skills/inventario-identificacao-vulnerabilidades/SKILL.md` — inventário e identificação NRM_134
> - `vma-veracode/_Agents-GVul/skills/reclassificacao-findings-sem-cve/SKILL.md` — reclassificação de findings sem CVE

---

## Sumário Executivo

O projeto SAGA-SAGV V2 representa a **primeira geração** de defesa à velocidade de máquina para gestão de vulnerabilidades na organizacao. Ele resolve os problemas corretos — triagem manual inviável, CVSS puro sem contexto, ausência de rastreabilidade para PCI-DSS/BACEN — com as ferramentas corretas, sem introduzir riscos de IA generativa antes da fundação estar estável.

Este documento descreve:
1. O **modelo de pesos atual (NRM_134)** da empresa e o gap em relação ao motor V2
2. O **estado atual** do V2: o que cada componente faz, seu status de implementação e dependências
3. Os **gaps identificados** à luz do estado da arte (V3) e do processo existente
4. O **roadmap de evolução** em três horizontes temporais, com critérios de entrada e métricas de sucesso

A conclusão central é que **o V2 está correto na direção, mas substituiu parcialmente o modelo de pesos NRM_134 por uma árvore binária que ignora 3 dos 8 fatores de risco já estabelecidos pela empresa**. A evolução correta não é reformular a arquitetura — é **incorporar as fórmulas NRM_134 como camada de score dentro do pipeline V2**, garantindo continuidade e transição gradual.

> [!IMPORTANT]
> O motor V2 atual classifica alguns casos **mais lentamente** do que o processo manual NRM_134 (ex.: Q13-Q16 em 24h na NRM vs ACT-3 em 3 dias no V2). Isso é um risco de regressão operacional e regulatória que precisa ser corrigido antes da promoção a produção.

---

## Parte 0 — O Modelo de Pesos Atual: NRM_134

> Esta seção documenta o processo vigente que o V2 deve **preservar e automatizar**, não substituir abruptamente.

### 0.1 Fórmulas oficiais de risco

O processo NRM_134 calcula dois scores independentes e os combina em uma matriz de quadrantes:

```
Impacto      = (BIA × 1.0) + (PCI × 1.0) + (Exposição × 1.0) + (Arquitetura × 1.5)
Probabilidade = (CVSS × 1.0) + (ThreatIntel × 1.1) + (Exploit × 1.1) + (CamadaAfetada × 0.8)

Score máximo por eixo: 400 (limitado)
```

### 0.2 Escalas de cada fator

**Fatores de Impacto:**

| Fator | Peso | Valores e scores |
|---|---|---|
| **BIA** (criticidade do ativo) | × 1.0 | Crise=100, Alto=50, Médio=25, Baixo=10 |
| **PCI** (escopo cartão) | × 1.0 | Sim=100, Não=10 |
| **Exposição** | × 1.0 | Exposto=100, Não exposto=10 |
| **Arquitetura** | × **1.5** ← maior peso | App/Web=100, API=80, Mobile=60, Infra=50, Workflow=40, Enduser=20, Mainframe=10 |

**Fatores de Probabilidade:**

| Fator | Peso | Valores e scores |
|---|---|---|
| **CVSS** (faixa) | × 1.0 | Crítico=100, Alto=80, Médio=40, Baixo=10 |
| **ThreatIntel** (KEV/listagem) | × 1.1 | Listada=100, Não listada=10 |
| **Exploit** (disponibilidade) | × 1.1 | Possui exploit=100, Não possui=10 |
| **Camada afetada** | × 0.8 | Aplicação=100, Middleware=80, Banco=50, SO=30, Appliance=20, Hardening=10 |

### 0.3 Matriz de quadrantes e SLAs

```
         PROBABILIDADE →
         1-Baixa  2-Média  3-Alta  4-Muito Alta
I  4-Crítico  Q4      Q8      Q12     Q16  ← 24h
M  3-Alto     Q3      Q7      Q11     Q15  ← 24h (Q13-Q16)
P  2-Médio    Q2      Q6      Q10     Q14  ← 7 dias (Q9-Q12)
A  1-Baixo    Q1      Q5      Q9      Q13  ← 30 dias (Q5-Q8)
C                                          ← 90 dias (Q1-Q4)
T
↓
```

| Faixa de quadrante | Classificação | SLA NRM_134 | SLA V2 atual | Delta |
|---|---|---|---|---|
| Q13–Q16 | Muito Alta / Crítico | **24 horas** | ACT-3 = 3 dias | ⚠️ V2 é 3× mais lento |
| Q9–Q12 | Alta | **7 dias** | ACT-14 = 14 dias | ⚠️ V2 é 2× mais lento |
| Q5–Q8 | Média | **30 dias** | ATTEND = 14–60 dias | ✅ compatível |
| Q1–Q4 | Baixa | **90 dias** | TRACK* / TRACK | ✅ compatível |

### 0.4 Gap entre NRM_134 e Motor V2

| Fator NRM_134 | Dimensão | Peso | No Motor V2 | Status |
|---|---|---|---|---|
| BIA / Criticidade | Impacto | × 1.0 | ✅ Nó 6 — colapsado em binário (critical+high vs resto) | ⚠️ Parcial — perde gradação |
| PCI | Impacto | × 1.0 | ❌ Capturado em `decision_inputs` mas **não influencia a decisão** | 🔴 Gap |
| Exposição | Impacto | × 1.0 | ✅ Nó 1 — booleano | ⚠️ Parcial — sem gradação |
| Arquitetura | Impacto | × **1.5** | ❌ Capturado como `asset_type` mas **não influencia a decisão** | 🔴 Gap (maior peso!) |
| CVSS | Probabilidade | × 1.0 | ❌ Substituído por KEV+EPSS | ✅ Substituição intencional e superior |
| ThreatIntel / KEV | Probabilidade | × 1.1 | ✅ Nó 2 — binário | ⚠️ Parcial — sem gradação |
| Exploit | Probabilidade | × 1.1 | ✅ Nó 3 — `is_exploit_automatable` | ✅ Coberto |
| Camada afetada | Probabilidade | × 0.8 | ❌ Não existe no modelo V2 | 🔴 Gap — não mapeado |

**Resumo:** 3 fatores com gap crítico (PCI, Arquitetura, Camada afetada), 3 fatores parcialmente cobertos (BIA, Exposição, ThreatIntel) e 2 adequadamente cobertos (Exploit, substituição do CVSS por EPSS).

### 0.5 Fluxo de identificação e reclassificação existente

Além das fórmulas de score, o processo NRM_134 inclui dois fluxos complementares relevantes para o V2:

**Inventário e Identificação** (skill `inventario-identificacao-vulnerabilidades`):
- Fontes aceitas: scan autenticado/não autenticado, pentest interno/externo, boletim de inteligência, evento SOC correlacionado
- Alto/crítico originado por scan → **abertura automática diária** de ticket no ITSM
- Campos mínimos obrigatórios: ativo, tipo, evidências, data, fonte, responsável e status
- Rastreabilidade obrigatória por ativo com plano de correção no ITSM

**Reclassificação de Findings sem CVE** (skill `reclassificacao-findings-sem-cve`):
- Classes de saída: `hardening`, `gestao_vulnerabilidade`, `falso_positivo_descartado`
- Critério de distinção: se há evidência de exploração ativa ou impacto mensurável → `gestao_vulnerabilidade`; risco exclusivamente preventivo → `hardening`
- Regra de telemetria: cookies/telemetria só descartados se não houver segredo, PII/PCI, sessão autenticada ou potencial de abuso
- Saída estruturada com `classe`, `justificativa`, `requer_motor_risco`, `salvaguardas`, `acao_recomendada`

> [!NOTE]
> O fluxo de reclassificação de findings sem CVE **não tem equivalente no V2**. O V2 assume que todo achado tem CVE ou CWE. Findings de hardening, configuração defensiva e baseline precisam de tratamento diferenciado que o modelo atual não contempla.

---

## Parte 1 — O que está sendo construído no V2

### 1.1 Visão do Pipeline Completo

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         FONTES DE INGESTÃO                              │
│  Veracode    GitHub     Orca Security   Tenable    CISA KEV  FIRST EPSS │
│  (SAST/SCA)  (metadados) (cloud/CNAPP) (on-prem)  (feed)    (feed)     │
└──────┬──────────┬──────────┬──────────────┬──────────┬──────────┬───────┘
       │          │          │              │          │          │
       ▼          ▼          ▼              ▼          └──────────┘
┌─────────────────────────────────┐                        │
│  Normalização + Deduplicação    │◄───────────────────────┘
│  chave: (cve_id + asset_id      │
│  + environment)                 │
└────────────────┬────────────────┘
                 ▼
┌────────────────────────────────────┐
│  Enriquecimento de Exposição (T1.7)│
│  is_publicly_exposed               │
│  (Orca cloud + Tenable ASM)        │
└────────────────┬───────────────────┘
                 ▼
┌────────────────────────────────────┐
│  Contexto de Ativo (T1.8)          │
│  • CMDB Jira Assets:               │
│    business_criticality, owner,    │
│    pci_scope, environment          │
│  • KEV + EPSS v4:                  │
│    in_kev_catalog,                 │
│    is_exploit_automatable          │
└────────────────┬───────────────────┘
                 ▼
┌────────────────────────────────────┐
│  MOTOR DE DECISÃO SSVC (RF4)       │
│  Determinístico — sem ML/LLM       │
│  Saída: TRACK / TRACK* /           │
│         ATTEND / ACT-14 / ACT-3    │
└──────┬────────────┬─────────────────┘
       │            │
       ▼            ▼
┌─────────────┐ ┌───────────────────────────────────────┐
│ Orquestração│ │ Mitigação Automática (ACT-3 / ACT-14) │
│ Ticketing   │ │ → Akamai WAF (Network Lists + AppSec) │
│ Jira        │ │ → GitHub, Jira, Slack, ServiceNow,    │
└─────────────┘ │   Veracode, Orca, Tenable             │
                └───────────────────┬───────────────────┘
                                    ▼
                       ┌────────────────────────┐
                       │ Remediação Automática   │
                       │ • GitHub PR (Dependabot)│
                       │ • Veracode auto-fix     │
                       │ • Tenable hardening     │
                       │ • Orca policy fix       │
                       │ • ServiceNow workflow   │
                       └────────────┬────────────┘
                                    ▼
                    ┌───────────────────────────────┐
                    │ Rollback Determinístico (RF13) │
                    │ 9 ações de reversão            │
                    └───────────────┬───────────────┘
                                    ▼
                    ┌───────────────────────────────┐
                    │ Auto-Healing (RF14)            │
                    │ 18 ações (forward + rollback)  │
                    └───────────────┬───────────────┘
                                    ▼
          ┌─────────────────────────────────────────────────┐
          │  Painel de Governança / Auditoria               │
          │  QuickSight + Athena + S3 Parquet               │
          │  PCI-DSS 4.0 (Req 6.3.1 / 11.3) + BACEN        │
          └─────────────────────────────────────────────────┘
```

---

### 1.2 Evolução do Pipeline com os Pesos NRM_134

> Esta seção mostra o pipeline **evoluído** que incorpora as fórmulas de peso da NRM_134 ao motor SSVC, implementando o item A0 do Horizonte A. O pipeline existente (1.1) não muda estruturalmente — o que muda é o que entra no motor de decisão.

#### Fluxo Completo com Camada de Score NRM_134

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         FONTES DE INGESTÃO (sem alteração)              │
│  Veracode    GitHub     Orca Security   Tenable    CISA KEV  FIRST EPSS │
└──────┬──────────┬──────────┬──────────────┬──────────┬──────────┬───────┘
       │          │          │              │          │          │
       ▼          ▼          ▼              ▼          └──────────┘
┌─────────────────────────────────┐                        │
│  Normalização + Dedupe          │◄───────────────────────┘
│  + PRÉ-CLASSIFICADOR SEM CVE   │  ← NOVO
│  hardening / gestao_vuln /      │
│  falso_positivo_descartado      │
└────────────────┬────────────────┘
                 │ apenas gestao_vulnerabilidade
                 ▼
┌────────────────────────────────────┐
│  Enriquecimento de Exposição       │
│  is_publicly_exposed               │
│  exposure_confidence (high/med/low)│
└────────────────┬───────────────────┘
                 ▼
┌──────────────────────────────────────────────────────────────┐
│  Contexto de Ativo  +  CÁLCULO DE SCORE NRM_134  ← NOVO      │
│                                                               │
│  Campos existentes (CMDB + KEV + EPSS) →                     │
│                                                               │
│  Impacto = (BIA×1.0) + (PCI×1.0) + (Exp×1.0) + (Arq×1.5)  │
│  • BIA   ← business_criticality: crise=100/alto=50/med=25    │
│  • PCI   ← pci_scope: sim=100 / não=10                       │
│  • Exp   ← is_publicly_exposed: exposto=100 / não=10         │
│  • Arq   ← asset_type: web=100/API=80/mobile=60/infra=50    │
│                                                               │
│  Prob  = (CVSS×1.0)+(KEV×1.1)+(Exploit×1.1)+(Camada×0.8)   │
│  • CVSS   ← severity_native: crit=100/alto=80/med=40         │
│  • KEV    ← in_kev_catalog: sim=100 / não=10                 │
│  • Exploit← is_exploit_automatable: sim=100 / não=10         │
│  • Camada ← asset_type+technical_impact: app=100/mw=80/db=50 │
│                                                               │
│  → Quadrante Q1–Q16 + SLA NRM_134 calculados e gravados      │
│    no ContextualizedFinding.nrm134{}                          │
└────────────────────────────┬─────────────────────────────────┘
                             ▼
┌──────────────────────────────────────────────────────────────┐
│   MOTOR DE DECISÃO SSVC + PESOS NRM_134  (evoluído)          │
│                                                               │
│  NÓ 1 — Exposição pública?                                   │
│    NÃO → TRACK (monitoramento passivo)                        │
│    SIM →                                                      │
│      NÓ 2 — CVE no catálogo KEV?                             │
│        NÃO →                                                  │
│          NÓ 3 — Exploit automatizável?                       │
│            NÃO →                                              │
│              NÓ 4 — Impacto técnico total?                   │
│                NÃO → TRACK*                                   │
│                SIM → ATTEND                                   │
│            SIM → ATTEND                                       │
│        SIM →                                                  │
│          NÓ 5 — Impacto total E automatizável?               │
│            NÃO → ATTEND                                       │
│            SIM →                                              │
│  ┌─────────────────────────────────────────────────────┐     │
│  │ NÓ 5b ← NOVO — Quadrante NRM_134 = Q13–Q16?        │     │
│  │   SIM → ACT-URGENTE (24h) ← alinhado à NRM_134     │     │
│  │   NÃO →                                             │     │
│  │     NÓ 6 — Ativo crítico de negócio?               │     │
│  │       SIM → ACT-3 (3 dias)                          │     │
│  │       NÃO → ACT-14 (14 dias)                        │     │
│  └─────────────────────────────────────────────────────┘     │
│                                                               │
│  DecisionRecord grava: decisão SSVC + nrm134_quadrante +     │
│  nrm134_sla_horas + nrm134_vs_ssvc_delta (shadow M1)         │
└──────┬────────────────┬─────────────────────────────────────┘
       │                │
       ▼                ▼
  (pipeline de ação — igual ao V2 atual, sem alteração)
```

#### Tabela de SLAs — NRM_134 integrada ao SSVC

| Decisão | Gatilho | SLA | Alinhamento NRM_134 |
|---|---|---|---|
| `TRACK` | Não exposto | Sem SLA | Q1–Q4 (Baixa) |
| `TRACK*` | Exposto, sem exploit, sem impacto total | Sem SLA | Q1–Q4 (Baixa) |
| `ATTEND` | Exposto, com exploit OU impacto total, sem KEV crítico | 14–60 dias | Q5–Q8 (Média) |
| `ACT-14` | KEV + exploit + impacto, negócio não crítico | 14 dias | Q9–Q12 (Alta) |
| `ACT-3` | KEV + exploit + impacto, negócio crítico | 3 dias | Q9–Q12 (Alta) |
| **`ACT-URGENTE`** ← NOVO | Qualquer caminho + Q13–Q16 (score NRM_134) | **24 horas** | **Q13–Q16 (Crítico)** |

#### Mapeamento de campos V2 → fatores NRM_134

**Eixo de Impacto** (score máx. 400 — cap aplicado)

| Fator NRM_134 | Campo V2 existente | Escala aplicada | Peso |
|---|---|---|---|
| BIA | `business_context.business_criticality` | critical=100, high=50, medium=25, low=10 | ×1.0 |
| PCI | `business_context.pci_scope` | true=100, false=10 | ×1.0 |
| Exposição | `exposure.is_publicly_exposed` | true=100, false=10 | ×1.0 |
| Arquitetura | `asset.asset_type` | web/app=100, API=80, mobile=60, infra=50, workflow=40, enduser=20, mainframe=10 | **×1.5** |

**Eixo de Probabilidade** (score máx. 400 — cap aplicado)

| Fator NRM_134 | Campo V2 existente | Escala aplicada | Peso |
|---|---|---|---|
| CVSS | `source_findings[].severity_native` | critical=100, high=80, medium=40, low=10 | ×1.0 |
| ThreatIntel / KEV | `exploitation.in_kev_catalog` | true=100, false=10 | ×1.1 |
| Exploit | `exploitation.is_exploit_automatable` | true=100, false=10 | ×1.1 |
| Camada afetada | `asset.asset_type` + `technical_impact` | application=100, middleware=80, banco=50, SO=30, appliance=20, hardening=10 | ×0.8 |

**Determinação do quadrante Q1–Q16:**

```
Impacto_normalizado      = min(Impacto, 400) / 100        → faixa 1-4
Probabilidade_normalizada = min(Probabilidade, 400) / 100  → faixa 1-4

Quadrante = ((ceil(Impacto_normalizado) - 1) × 4) + ceil(Probabilidade_normalizada)

Exemplo:
  Impacto = 325 → normalizado = 3.25 → ceil = 4 (Crítico)
  Prob    = 287 → normalizado = 2.87 → ceil = 3 (Alta)
  Quadrante = (4-1)×4 + 3 = 15 → Q15 → SLA 24h
```

**SLA por faixa de quadrante (NRM_134 oficial):**

```
Q13–Q16  →  24 horas     → ACT-URGENTE (novo)
Q9–Q12   →   7 dias      → ACT-14 (alinhado) OU ACT-3 (via nó 6)
Q5–Q8    →  30 dias      → ATTEND
Q1–Q4    →  90 dias      → TRACK* / TRACK
```

#### Campos adicionados ao ContextualizedFinding (não-breaking)

```json
{
  "...campos existentes...": "...",
  "nrm134": {
    "impacto_score": 325,
    "probabilidade_score": 287,
    "quadrante": "Q15",
    "classificacao": "Muito Alta / Crítico",
    "sla_horas": 24,
    "fatores_impacto": {
      "bia": 100,         "bia_label": "Crise",
      "pci": 100,         "pci_sim": true,
      "exposicao": 100,
      "arquitetura": 80,  "arquitetura_tipo": "API"
    },
    "fatores_probabilidade": {
      "cvss_faixa": "Alto",   "cvss_score": 80,
      "threat_intel": 100,    "threat_intel_kev": true,
      "exploit": 100,         "exploit_disponivel": true,
      "camada_afetada": "Aplicação", "camada_score": 100
    }
  }
}
```

#### Campos adicionados ao DecisionRecord (modo shadow M1 — não-breaking)

```json
{
  "decision": "ACT_3",
  "sla_days": 3,
  "rationale": ["exposed=true", "kev=true", "..."],
  "nrm134_quadrante": "Q15",
  "nrm134_classificacao": "Muito Alta / Crítico",
  "nrm134_sla_horas": 24,
  "nrm134_vs_ssvc_delta": "nrm134_mais_restritivo"
}
```

Valores possíveis de `nrm134_vs_ssvc_delta`:
- `"ssvc_mais_restritivo"` — V2 fecha mais rápido que a NRM_134 (esperado para maioria dos casos)
- `"nrm134_mais_restritivo"` — NRM_134 exige SLA menor (sinaliza candidato a ACT-URGENTE)
- `"alinhados"` — ambos chegam à mesma faixa de SLA

---

### 1.3 Status de Implementação por Componente

| # | Componente | O que faz | Status | Bloqueio |
|---|---|---|---|---|
| 1 | **Conector Veracode** | SAST/SCA via HMAC, Lambda + SQS | ⚙️ em dev | 🔒 acesso API |
| 2 | **Conector GitHub** | Metadados via webhook (push/PR events) | ⚙️ em dev | 🔒 acesso API |
| 3 | **Conector Orca Security** | Cloud/CNAPP via Query DSL API | ⚙️ em dev | 🔒 acesso API |
| 4 | **Conector Tenable** | On-prem via exportação assíncrona em chunks | ⚙️ em dev | 🔒 acesso API + VPN |
| 5 | **Conector CISA KEV** | Feed público, diff incremental, sem autenticação | ✅ especificado | — |
| 6 | **Conector FIRST EPSS** | Feed público, consulta por lista de CVEs | ⚙️ em dev | — |
| 7 | **Normalização + Dedupe** | Unifica 4 fontes; chave `(cve+asset+env)` | ⚙️ em dev | — |
| 8 | **Enriquecimento Exposição** | `is_publicly_exposed` = Orca ∪ Tenable (conservador) | ⚙️ em dev | — |
| 9 | **Contexto de Ativo** | CMDB + KEV + EPSS → `ContextualizedFinding` | ⚙️ em dev | 🔒 schema Jira Assets |
| 10 | **Motor de Decisão SSVC** | Árvore determinística → TRACK/TRACK*/ATTEND/ACT | ⚙️ em dev | 🔒 ATTEND_SLA_DAYS |
| 11 | **Orquestração/Ticketing** | Cria/atualiza Jira idempotente por `finding_id` | ⚙️ em dev | 🔒 Jira Cloud vs DC |
| 12 | **Mitigação Automática** | Akamai WAF (runbook CAB) + 7 plataformas | ⏳ backlog | 🔒 aprovação CAB |
| 13 | **Remediação GitHub PR** | Abre PRs de correção via Dependabot/CodeQL | ⚙️ em dev | — |
| 14 | **Rollback Determinístico** | 9 ações de reversão com idempotência | ⚙️ em dev | — |
| 15 | **Auto-Healing** | 18 ações (forward + rollback) + circuit breaker | ⚙️ em dev | — |
| 16 | **Reavaliação Contínua** | Reclassifica por evento (KEV/EPSS/exposição/CMDB) | ⏳ backlog M4 | — |
| 17 | **Painel de Governança** | QuickSight + Athena, filtros PCI/BACEN | ⏳ backlog M3 | 🔒 compliance |
| 18 | **Copiloto de Análise** | LLM para ATTEND — propõe contexto, humano decide | ⏳ backlog M4 | — |

---

### 1.4 Motor de Decisão SSVC — A Lógica Central (Versão Base)

O motor de decisão é o componente mais crítico do V2. Implementa uma árvore determinística de 6 nós, sem chamada a modelo de ML ou LLM:

```
ENTRADA: ContextualizedFinding
  ├── exposure.is_publicly_exposed (bool)
  ├── exploitation.in_kev_catalog (bool)
  ├── exploitation.is_exploit_automatable (bool)
  ├── technical_impact (none | partial | total)
  └── business_context.business_criticality (critical | high | medium | low)

NÓ 1 — Exposição pública?
  ├── NÃO → TRACK (sem SLA, zero toque humano, monitoramento passivo)
  └── SIM →
      NÓ 2 — CVE no catálogo KEV da CISA?
        ├── NÃO →
        │   NÓ 3 — Exploit automatizável de ponta a ponta?
        │     ├── NÃO →
        │     │   NÓ 4 — Impacto técnico total (controle completo do ativo)?
        │     │     ├── NÃO → TRACK* (monitorar, reavaliar por evento)
        │     │     └── SIM → ATTEND (14–60 dias, triagem humana leve)
        │     └── SIM → ATTEND
        └── SIM →
            NÓ 5 — Impacto total E automatizável?
              ├── NÃO → ATTEND
              └── SIM →
                  NÓ 6 — Ativo crítico de negócio (critical | high)?
                    ├── SIM → ACT-3 (3 dias + mitigação automática + forense)
                    └── NÃO → ACT-14 (14 dias + prioridade máxima)
```

**Tabela de SLAs e ações por categoria:**

| Decisão | SLA | Toque humano | Ação automática disparada |
|---|---|---|---|
| `TRACK` | Sem SLA | Zero | Monitoramento passivo (Orca tag) |
| `TRACK*` | Sem SLA | Exceção apenas | Alerta Slack + Orca tag |
| `ATTEND` | 14–60 dias | Leve: validação + priorização | Ticket Jira + alerta Slack |
| `ACT-14` | 14 dias | Priorização máxima na fila | GitHub issue + Jira + Slack + ServiceNow + Orca + Tenable |
| `ACT-3` | 3 dias | IR/SOC notificado | Tudo do ACT-14 + Akamai WAF + Veracode exception + incidente SOC + escalação executiva |

**Toda decisão persiste em `DecisionRecord` append-only com:**
- `rationale` completo (lista de strings — obrigatório em produção)
- `decision_inputs` (snapshot auditável de todos os campos consultados)
- `mode` (shadow | production) — shadow roda em paralelo ao processo manual sem disparar ações

---

### 1.5 Integrações por Plataforma

#### Fontes de dados (ingestão)

| Plataforma | Autenticação | Padrão de extração |
|---|---|---|
| **Veracode** | HMAC (API ID + Key) via biblioteca oficial PyPI | Findings/Results API + Annotations API |
| **GitHub** | GitHub App ou PAT com escopo restrito | Webhooks (push, PR, workflow_run) — evento, não polling |
| **Orca Security** | API Token | `POST /api/serving-layer/query` com filtros de risco |
| **Tenable** | Access Key + Secret Key | Exportação assíncrona em chunks (`POST /vulns/export`) via `pyTenable` |
| **CISA KEV** | Nenhuma (feed público) | Download JSON + diff contra snapshot anterior |
| **FIRST EPSS** | Nenhuma (API pública) | Consulta por lista de CVEs (`/data/v1/epss`) |

#### Destinos de ação (mitigação e remediação)

| Plataforma | Ação de mitigação | Ação de remediação | Rollback |
|---|---|---|---|
| **GitHub** | Abrir issue com labels SSVC | Abrir PR de correção | Fechar issue / Fechar PR + remover branch |
| **Jira** | Criar ticket com SLA SSVC | — | Transicionar para cancelado |
| **Slack** | Notificar canal de segurança | — | Deletar mensagem |
| **ServiceNow** | Criar incidente com prioridade SSVC | Acionar workflow de correção | Cancelar incidente / workflow |
| **Veracode** | Criar policy exception (HMAC) | Auto-fix SAST/SCA | Reverter auto-fix |
| **Orca** | Aplicar tag de risco | Policy fix | Reverter policy/tag fix |
| **Tenable** | Marcar asset / workflow | Hardening via API | Reverter job de hardening |
| **Akamai** | Network Lists (bloqueio IP) + AppSec API (regra WAF) | — | Ativar versão anterior da config |

---

### 1.6 Infraestrutura AWS (serverless-first)

| Componente | Serviço AWS | Decisão de arquitetura |
|---|---|---|
| Conectores de ingestão | Lambda + EventBridge Scheduler | Um por fonte; falha isolada por design |
| Buffer ingestão→normalização | SQS (uma fila por fonte) | Retry/backoff + DLQ por fonte |
| Staging raw findings | S3 (partições fonte/data) | Evidência auditável do raw payload |
| Estado dos findings | DynamoDB (PK+SK, GSI por CVE+asset) | Append-only para `DecisionRecord` |
| Orquestração do pipeline | Step Functions | Retry e error handling nativos por etapa |
| Log de decisões | DynamoDB Streams → Kinesis Firehose → S3 Parquet | Escrita rápida + data lake sem competição de capacidade |
| Motor de Decisão | Lambda pura sem estado | Modo shadow/prod via Parameter Store |
| Painel de Governança | QuickSight + Athena | Sobre S3 do data lake |
| Segredos | AWS Secrets Manager | Nunca em variável de ambiente commitada |
| CI/CD | GitHub Actions + OIDC → role AWS | Sem chave de longa duração |
| Camada RAG (Fase M4) | Aurora PostgreSQL Serverless v2 + pgvector | Consumidor adicional do mesmo DynamoDB Stream |

---

### 1.7 Marcos de Sincronização e Gates Humanos

O progresso não é por calendário fixo — depende de **gates humanos** (decisões de pessoas/áreas da organizacao):

| Gate | O que bloqueia | Ação necessária |
|---|---|---|
| 🔒 G1 | Dimensionamento de volume | Levantar achados mensais reais por fonte (últimos 3–6 meses) |
| 🔒 G2 | Contexto de negócio (CMDB) | Confirmar/criar atributos `business_criticality`, `asset_owner`, `pci_scope` no schema do Jira Assets |
| 🔒 G3 | Ticketing | Confirmar Jira Cloud vs Data Center + `JIRA_PROJECT_KEY` |
| 🔒 G4 | Promoção ATTEND para produção | Definir `ATTEND_SLA_DAYS` com time de risco/segurança |
| 🔒 G5 | Mitigação automática | Validar com CAB o processo de aprovação de runbook único (não por execução) |
| 🔒 G6 | Todos os conectores | Conceder acesso de API a Veracode, Orca, Tenable, Jira e Akamai; cadastrar credenciais no Secrets Manager |
| 🔒 G7 | Deploy real | Provisionar conta AWS, papéis IAM, VPN/Direct Connect para Tenable on-prem |
| 🔒 G8 | IaC | Escolher Terraform vs CDK vs SAM com time de plataforma |
| 🔒 G9 | Promoção M2 (TRACK/TRACK*) | Validação do time de segurança após período de shadow |
| 🔒 G10 | Promoção M3 (ATTEND/ACT) | Aprovação formal do time de segurança |
| 🔒 G11 | Fechamento M3 governança | Compliance/auditoria valida painel PCI-DSS 4.0 + BACEN |
| 🔒 G12 | Mitigação on-prem | Identificar firewall/NAC on-prem complementar ao Akamai |

**Marcos de sincronização:**

- **M0 — Fundação:** G1–G8 resolvidos; IaC criado; acessos de API concedidos
- **M1 — Shadow ativo:** pipeline completo rodando em shadow, comparando com NRM_134 sem disparar ações
- **M2 — Produção parcial:** TRACK/TRACK* em produção; NRM_134 deixa de cobrir essa fatia
- **M3 — Produção completa:** todas as categorias em produção; mitigação ACT-3 ativa; painel de governança validado; NRM_134 descontinuado
- **M4 — Maturidade:** reavaliação contínua, copiloto de análise e recalibração em produção

---

## Parte 2 — Gaps Identificados pelo Estado da Arte

### Gap 1 — Ausência de proteção contra envenenamento de agentes 🔴 CRÍTICO

**O que o V3 documenta:** atores maliciosos submetem relatórios de bugs artificialmente construídos a sistemas de tracking (Jira, GitHub Issues). Quando agentes de remediação consomem esses dados, injetam backdoors no código da organização ou exfiltram credenciais disfarçadas de logs de debug. O incidente da Hugging Face (julho/2026) confirmou esse vetor em produção — não é teórico.

**O que o V2 não cobre:** o `RemediationOrchestrator` consume `MitigationRecord` persistido como fonte de verdade (correto), mas não há garantia de que os dados de entrada que geraram o `MitigationRecord` foram sanitizados. Um relatório de bug malicioso no GitHub Issues pode envenenar o pipeline upstream.

**Impacto para a organizacao:** uma adquirência que processa transações financeiras tem superfície de ataque de altíssimo valor — o risco de um agente injetar código malicioso em um repositório de produção de pagamentos é inaceitável.

---

### Gap 2 — Motor de decisão sem capacidade de aprendizado 🟡 IMPORTANTE

**O que o V3 documenta:** com o volume de achados gerados por IA crescendo exponencialmente (caso cURL: taxa de confirmação de bugs caiu de >15% para <5% em 2025), a triagem puramente humana colapsou. Sistemas como o MDASH da Microsoft usam debate multi-agente para reduzir falsos positivos em mais de dois terços.

**O que o V2 não cobre:** o motor determinístico é correto para a v1, mas tem um teto de escala humano. A fila `ATTEND` cresce proporcionalmente ao volume de achados — sem uma camada de IA que filtre falsos positivos antes de chegarem ao analista, o gargalo migra para o ser humano.

**Impacto:** à medida que o volume de achados cresce (tendência documentada no V3: +263% de CVEs entre 2020–2025), o processo se torna insustentável mesmo com SSVC automatizando TRACK/TRACK*.

---

### Gap 3 — Sem estratégia para IR com payloads de ataque real 🟡 IMPORTANTE

**O que o V3 documenta:** APIs de LLM comerciais recusam analisar telemetria de ataque real (logs de C2, payloads de malware) por interpretá-los como pedidos maliciosos. No incidente da Hugging Face, a equipe de IR ficou paralisada com 17.000 registos de eventos e nenhum LLM comercial capaz de analisá-los. A solução foi hospedar um modelo de pesos abertos on-premise.

**O que o V2 não cobre:** o Copiloto de Análise planejado para M4 baseia-se em APIs comerciais (Amazon Bedrock/Titan ou Voyage AI). Para análise forense de incidentes graves, essas APIs falharão exatamente quando mais são necessárias.

**Impacto:** sem um modelo local, incidentes graves que exijam análise de payloads de ataque demandarão análise manual inteiramente humana — o gargalo mais lento em cenários de resposta rápida.

---

## Parte 3 — Roadmap de Evolução

### Horizonte A — Imediato (sem alterar escopo v1, paralelo ao M3)

#### A0 — Integração Preservativa do Modelo NRM_134 ao Motor V2 🔴 PRIORITÁRIO

**Problema que resolve:** o motor V2 ignora 3 fatores de risco já estabelecidos pela empresa (PCI, Arquitetura, Camada afetada) e classifica casos críticos mais lentamente do que o processo manual (ACT-3 em 3 dias vs NRM_134 Q13-Q16 em 24h)

**Princípio:** **evoluir, não substituir** — incorporar as fórmulas NRM_134 como camada de score dentro do pipeline V2, sem reformular a arquitetura. A árvore SSVC permanece como estrutura; os nós passam a usar scores calculados pelas fórmulas NRM_134.

**O que implementar — 3 passos em sequência:**

**Passo 1: Enriquecimento NRM_134 no contexto de ativo (T1.8)**

Adicionar ao `ContextualizedFinding` dois novos campos calculados pelas fórmulas NRM_134:

```json
{
  "nrm134": {
    "impacto_score": 325,
    "probabilidade_score": 287,
    "quadrante": "Q14",
    "classificacao": "Alta",
    "sla_horas": 168,
    "fatores_impacto": {
      "bia": 100,
      "bia_label": "Crise",
      "pci": 100,
      "pci_sim": true,
      "exposicao": 100,
      "arquitetura": 80,
      "arquitetura_tipo": "API"
    },
    "fatores_probabilidade": {
      "cvss_faixa": "Alto",
      "cvss_score": 80,
      "threat_intel": 100,
      "threat_intel_kev": true,
      "exploit": 100,
      "exploit_disponivel": true,
      "camada_afetada": "Aplicação",
      "camada_score": 100
    }
  }
}
```

Mapeamento de campos existentes para fatores NRM_134:

| Fator NRM_134 | Campo V2 de origem | Mapeamento |
|---|---|---|
| BIA | `business_context.business_criticality` | critical→100, high→50, medium→25, low→10 |
| PCI | `business_context.pci_scope` | true→100, false→10 |
| Exposição | `exposure.is_publicly_exposed` | true→100, false→10 |
| Arquitetura | `asset.asset_type` | app/web→100, API→80, mobile→60, infra→50 |
| CVSS | `source_findings[].severity_native` | critical→100, high→80, medium→40, low→10 |
| ThreatIntel | `exploitation.in_kev_catalog` | true→100, false→10 |
| Exploit | `exploitation.is_exploit_automatable` | true→100, false→10 |
| Camada afetada | `asset.asset_type` + `technical_impact` | Aplicação→100, Middleware→80, Banco→50, SO→30 |

**Passo 2: Nó de urgência NRM_134 no motor de decisão**

Adicionar um nó de verificação **antes** do nó 6 (criticidade de negócio) que consulta o quadrante NRM_134 calculado e pode escalar o SLA:

```
... (fluxo SSVC existente até nó 5) ...

NÓ 5b — Score NRM_134 indica Q13-Q16 (urgência máxima)?
  SIM → ACT-URGENTE (24h) independente do nó 6
  NÃO →
      NÓ 6 — Ativo crítico de negócio (critical | high)?
        SIM → ACT-3 (3 dias)
        NÃO → ACT-14 (14 dias)
```

Essa adição **não quebra** a árvore SSVC existente — é um nó adicional que resolve o gap de SLA entre a NRM_134 (24h) e o V2 (3 dias) para os casos de maior urgência.

**Passo 3: Modo shadow comparativo**

Durante M1 (shadow), registrar no `DecisionRecord` tanto a decisão SSVC quanto o quadrante NRM_134 calculado:

```json
{
  "decision": "ACT_3",
  "nrm134_quadrante": "Q14",
  "nrm134_classificacao": "Alta",
  "nrm134_sla_horas": 168,
  "nrm134_vs_ssvc_delta": "ssvc_mais_restritivo"
}
```

Isso permite comparar quantitativamente as decisões do motor V2 com o processo manual NRM_134 durante o período de shadow, antes de qualquer promoção a produção.

**Passo 4: Reclassificação de findings sem CVE**

Implementar a lógica da skill `reclassificacao-findings-sem-cve` como pré-processamento na etapa de Normalização:
- Findings sem CVE passam por classificação: `hardening` / `gestao_vulnerabilidade` / `falso_positivo_descartado`
- Apenas `gestao_vulnerabilidade` segue para o motor SSVC
- `hardening` recebe tratamento separado (backlog de configuração defensiva, não pipeline de vulnerabilidade)
- `falso_positivo_descartado` é registrado com justificativa auditável e não gera ticket

**Esforço:** médio — requer:
- Novo campo `nrm134` no `ContextualizedFinding` (extensão não-breaking do DATA_MODEL)
- Novo nó 5b no `DECISION_ENGINE_SPEC.md` (requer atualização do spec + testes)
- Novo módulo `normalization/finding_classifier.py` para reclassificação sem CVE

**Gate necessário:** validação com o time de risco/segurança para confirmar o mapeamento de `asset_type` para os valores de Arquitetura e Camada afetada da NRM_134 — esses mapeamentos dependem de decisão de negócio, não de engenharia.

**Métricas de sucesso (shadow M1):**
- % de casos onde V2+NRM_134 e processo manual chegam à mesma categoria de SLA
- Identificação de casos onde o V2 seria mais lento que a NRM_134 (delta negativo)
- Identificação de casos onde o V2 seria mais rígido que necessário (redução de ruído)

**Importante — o que NÃO mudar:**
- A arquitetura do pipeline (Lambda, DynamoDB, EventBridge) não muda
- O `DecisionRecord` append-only não muda — apenas recebe campos adicionais
- A árvore SSVC não é substituída — é estendida com o nó 5b e alimentada com scores NRM_134
- O modo shadow e todos os gates humanos existentes continuam valendo

#### A1 — Sanitização de Input Anti-Envenenamento

**Problema que resolve:** vetor de prompt injection indireta via sistemas de tracking (Gap 1)

**O que implementar:**

1. **Filtro de sanitização no pipeline de ingestão:** toda mensagem proveniente de GitHub Issues, Jira ou outros sistemas bidirecionais passa por validação de schema estrita antes de alimentar qualquer agente ou o motor de decisão
2. **Separação de contexto:** dados de observação (achados das ferramentas de scan) nunca se misturam com dados de instrução (runbooks, configurações de playbook). Conexão unidirecional obrigatória
3. **Blindagem dos sistemas de tracking:** relatórios de bug que alimentam agentes de IA passam por sanitização de campos livres (descrição, comentários) antes do processamento

**Esforço:** baixo — interceptação no pipeline de ingestão, sem alterar o motor de decisão.

**Controles obrigatórios a partir de M2:**
- RBAC rígido: agentes de IA com credenciais mínimas — sem acesso amplo a segredos, chaves ou produção
- Auditoria por segundo modelo antes de qualquer merge automatizado
- Human-in-the-loop obrigatório em toda ação que altere código de produção
- Trilha de auditoria completa de toda decisão proposta por IA

#### A2 — Ativar Reachability Analysis no Veracode SCA

**Problema que resolve:** falsos positivos de SCA — bibliotecas vulneráveis presentes no disco mas cujo código nunca é invocado

**O que implementar:**

- Ativar tree-shaking source-to-sink no Veracode SCA (nativo, depende do nível de licença)
- Achados em código morto ou não alcançável têm prioridade rebaixada automaticamente antes de entrar no pipeline de decisão

**Esforço:** baixo — configuração do Veracode SCA + pipeline CI/CD

**Métrica de sucesso:** redução de falsos positivos de SCA sem aumento de risco real (validado por amostragem)

---

### Horizonte B — Médio Prazo (6–18 meses após M3)

#### B1 — Triagem Assistida por IA para ATTEND

**Problema que resolve:** volume de achados ATTEND excede capacidade de análise humana; Gap 2

**O que é:**

Agente de IA (LLM comercial via API ou modelo aberto self-hosted) que recebe achados classificados como `ATTEND` e propõe:
- Severidade ajustada com justificativa em linguagem natural
- Classificação SSVC preliminar com base no histórico de achados similares
- Resumo do contexto histórico do ativo e do CVE (via camada RAG — T4.2/T4.2b)
- Recomendação de ação com grau de confiança explícito

**Regra inviolável:** toda proposta passa por analista humano antes de virar SLA. O agente **propõe**, o humano **decide**. Nenhuma classificação é promovida automaticamente.

**Infraestrutura:** reutiliza o Copiloto de Análise (T4.2) e a camada RAG (Aurora PostgreSQL + pgvector) já planejados para M4 — não é um sistema separado.

**Dependências:**
- M3 precisa estar fechado (base estável de `DecisionRecord`)
- Camada RAG com embeddings de decisões históricas e descrições de CVE

**Métricas de sucesso:**
- % de propostas aceitas sem alteração pelo analista (meta: >70% em 6 meses)
- Redução do tempo médio de triagem por achado ATTEND
- Redução do volume de achados ATTEND chegando à fila humana sem pré-triagem

#### B2 — Combinações Tóxicas Expandidas (Orca Graph + Tenable + PCI)

**Problema que resolve:** achados de severidade média que se tornam críticos quando combinados com contexto de nuvem

**O que é:**

Detector automático de cenários de combinação tóxica:
- Workload exposto à internet + permissões IAM excessivas + acesso a dados de cartão (PCI/CDE)
- Container com CVE médio + privilégios de admin + sem isolamento de rede
- Serviço de pagamento sem patch + porta exposta + credencial comprometida no KEV

Quando uma combinação tóxica é detectada, o achado é escalonado automaticamente para `ACT-3` independentemente da classificação SSVC isolada dos componentes.

**Infraestrutura:** Orca graph/context engine via API + tag `pci_scope` (já implementada em T1.8) + dados de exposição do Tenable

**Métrica de sucesso:** número de combinações tóxicas identificadas antes de se tornarem incidente; tempo de remediação vs. achados isolados

---

### Horizonte C — Longo Prazo (18+ meses após M3)

#### C1 — APR Supervisionado — Reparação Semântica de Código

**Problema que resolve:** MTTR de correção de dependências vulneráveis com breaking changes — o `RemediationOrchestrator` atual abre PRs de bump de versão simples (via Dependabot); não raciocina sobre compatibilidade

**O que é:**

Expansão do `RemediationOrchestrator` para um agente de APR (Automated Program Repair) que:
1. Analisa o histórico do repositório e identifica breaking changes da nova versão
2. Reescreve chamadas a métodos depreciados para compatibilidade com a versão segura
3. Compila e executa a suíte de testes em ambiente isolado de CI/CD
4. Abre um PR auditável com descrição completa da correção e resultado dos testes
5. **Nunca aplica sozinho** — PR fica retido para revisão humana obrigatória

**Começa restrito:** dependências de baixo risco com breaking changes conhecidos e bem documentados.

**Diferença do atual:**

| Capacidade | `github_pr` atual | APR supervisionado |
|---|---|---|
| Bump de versão simples | ✅ Sim | ✅ Sim |
| Reescrita de código para compatibilidade | ❌ Não | ✅ Sim |
| Raciocínio sobre breaking changes | ❌ Não | ✅ Sim |
| Execução de testes em ambiente isolado | ❌ Não | ✅ Sim |

**Infraestrutura:** LLM especializado + pipeline CI/CD + repositórios versionados. Complementa (não substitui) o Veracode SCA.

**Métricas de sucesso:**
- % de PRs gerados por IA aceitos sem retrabalho humano significativo (meta: >60%)
- Redução de MTTR nas classes de vulnerabilidade cobertas

#### C2 — Debate Agêntico para Pré-Validação

**Problema que resolve:** mesmo com triagem assistida (B1), falsos positivos ainda consomem tempo de analista

**O que é:**

Expansão do agente de triagem para dois agentes com papéis opostos:
- **Agente Auditor:** propõe classificação e severidade para o achado
- **Agente Debatedor:** tenta refutar via análise de fluxo de dados e contexto histórico

Apenas achados que sobrevivem ao debate chegam à fila humana. O padrão é inspirado no MDASH da Microsoft — capaz de reduzir falsos positivos em mais de dois terços.

**Infraestrutura:** dois modelos de famílias e fornecedores distintos (para evitar viés correlacionado) sobre a infraestrutura do B1.

**Regra de segurança:** a discordância entre modelos é um sinal de alerta — achados que um modelo classifica como alto risco e o outro refuta completamente são escalados para revisão humana obrigatória, não descartados silenciosamente.

**Métricas de sucesso:**
- Redução mensurável de falsos positivos chegando à fila humana
- Sem aumento de falsos negativos (auditado por amostragem periódica)

#### C3 — Modelo Local para Resposta a Incidentes

**Problema que resolve:** o "paradoxo dos guardrails" — APIs de LLM comerciais recusam analisar payloads de ataque real (Gap 3)

**O que é:**

Modelo de pesos abertos hospedado internamente, isolado da rede, dedicado exclusivamente à análise forense em incidentes graves:
- Análise de logs de C2, payloads de ataque, telemetria de malware sem restrições dos guardrails de APIs comerciais
- Reconstrução de linha do tempo de ataque a partir de grandes volumes de eventos
- Mapeamento de exfiltrações e movimentação lateral em tempo útil

**Uso:** restrito à equipe de IR, com controles de acesso rígidos. **Não integra ao fluxo de detecção do dia a dia** — é ferramenta de exceção para incidentes graves, análoga ao Projeto 11 do mapeamento V3.

**Plataformas candidatas:** Llama, Mistral, DeepSeek ou equivalente em GPU on-premise ou cloud isolada da organizacao.

**Métricas de sucesso:**
- Disponibilidade comprovada em simulações de incidente (tabletop exercises)
- Tempo de reconstrução de linha do tempo de ataque vs. análise puramente manual

---

## Parte 4 — Visão Consolidada por Dimensão

### 4.1 Mapa de evolução completo

| Dimensão | V2 Hoje (M0→M3) | Horizonte A (imediato) | Horizonte B (6–18m) | Horizonte C (18m+) |
|---|---|---|---|---|
| **Fonte de decisão** | Motor SSVC determinístico (5 nós, sem ML) | = | + IA propõe ATTEND, humano decide | + Debate agêntico pré-filtra |
| **Priorização** | KEV + EPSS v4 + criticidade de negócio | + Reachability SCA | + Combinações tóxicas | = |
| **Remediação** | GitHub PR (bump de versão, Dependabot) | = | = | + APR semântico (reescrita código) |
| **Análise forense** | Auditoria append-only, painel QuickSight | = | = | + Modelo local on-premise |
| **Proteção do pipeline** | Idempotência + Rollback + Auto-Healing | + Sanitização anti-envenenamento | = | = |
| **Human-in-the-loop** | CAB pré-aprova runbooks; IR notificado em ACT-3 | + Sanitização de inputs | Obrigatório em toda proposta IA | Obrigatório em todo PR gerado por APR |
| **IA generativa** | Nenhuma no core decisório | Nenhuma | Copiloto ATTEND (propõe) | Debate + APR + IR local |
| **Auditoria regulatória** | PCI-DSS 4.0 (Req 6.3.1/11.3) + BACEN | = | + Trilha de toda proposta IA | = |
| **Proteção contra ataques de IA** | Idempotência + rollback (parcial) | Sanitização de input (completa) | RBAC agente + auditoria segunda IA | = |

---

### 4.2 Cobertura dos 11 Projetos do Mapeamento V3

| # | Projeto V3 | Cobertura no V2 | Horizonte de evolução |
|---|---|---|---|
| 1 | Correlação de achados | ✅ Normalização + Dedupe (T1.6) | — |
| 2 | Overlay EPSS v4 | ✅ Enriquecimento T1.8 (RF3.4) | Monitorar atualização modelo FIRST |
| 3 | Tagueamento PCI/CDE | ✅ `pci_scope` em `business_context` (T1.8) | Depende do schema Jira Assets (G2) |
| 4 | Dashboard executivo | ✅ QuickSight + Athena (T3.3) | Validação compliance (G11) |
| 5 | Adoção formal SSVC | ✅ Motor de decisão central (T1.9) | BOD 26-04 já formaliza globalmente |
| 6 | Reachability analysis | ⚠️ Veracode SCA presente, reachability não ativada explicitamente | **Horizonte A** (A2) |
| 7 | Combinações tóxicas (cloud) | ⚠️ Orca + Tenable + PCI tag presentes; combinação não implementada | **Horizonte B** (B2) |
| 8 | Triagem assistida por IA | ⏳ Copiloto planejado para M4 (T4.2) | **Horizonte B** (B1) |
| 9 | APR supervisionado | ⚠️ PRs simples via Dependabot; sem reescrita semântica | **Horizonte C** (C1) |
| 10 | Debate agêntico | ⏳ Não planejado | **Horizonte C** (C2) |
| 11 | Modelo local para IR | ⏳ Não planejado | **Horizonte C** (C3) |
| — | **Anti-envenenamento** | 🔴 Não contemplado explicitamente | **Horizonte A — IMEDIATO** (A1) |

---

### 4.3 Critérios de Entrada para Cada Horizonte

**Para iniciar Horizonte A:**
- Não depende de nenhum marco anterior — pode começar em paralelo ao M0/M1
- Prioridade: A1 (sanitização) deve ser a primeira entrega de qualquer agente do pipeline que consuma dados de sistemas bidirecionais

**Para iniciar Horizonte B:**
- M3 fechado com sucesso (produção completa + governança validada)
- Base de `DecisionRecord` com pelo menos 90 dias de dados reais
- Ao menos um ciclo de auditoria PCI-DSS concluído com o painel do V2

**Para iniciar Horizonte C:**
- M4 operacional (Reavaliação Contínua + Copiloto de Análise em produção)
- Métricas do B1 (triagem assistida) validadas por pelo menos 6 meses
- Decisão de investimento em infraestrutura GPU (para C3) aprovada pela liderança

---

## Parte 5 — Governança de Risco para IA no Pipeline

Todo projeto de Horizonte B e C que envolva agentes de IA atuando sobre código ou infraestrutura **carrega os riscos documentados no V3**: envenenamento de relatórios/prompts e injeção de backdoors via submissões maliciosas disfarçadas de bugs legítimos. Para uma adquirência, isso não é risco abstrato — são agentes com potencial de tocar código que processa transações financeiras.

### Controles obrigatórios a partir do Horizonte B:

| Controle | Descrição | Por quê é obrigatório |
|---|---|---|
| **RBAC rígido** | Agentes de IA com credenciais mínimas — sem acesso amplo a segredos, chaves ou produção | Evita que comprometimento de um agente dê acesso a toda a infraestrutura |
| **Auditoria por segundo modelo** | Nenhum agente de IA decide sozinho sobre ação que afete código de produção | Reduz risco de alucinação ou envenenamento de prompt |
| **Sanitização de tracking** | Todos os reports de bug que alimentam agentes passam por sanitização de campos livres | Bloqueia o vetor principal de prompt injection indireta |
| **Human-in-the-loop obrigatório** | Toda ação que altere código de produção exige revisão humana — sem exceção | Inviolável enquanto APR não atingir >95% de precisão auditada |
| **Trilha de auditoria completa** | Toda decisão proposta ou tomada por IA registrada com timestamp e fonte do modelo | Sustenta evidência perante PCI-DSS e BACEN |
| **Modelo secundário para IR** | Análise forense de incidentes graves usa modelo local, não API comercial | Evita o paradoxo dos guardrails em cenários críticos |

---

## Resumo Executivo para Liderança

O SAGA-SAGV V2 endereça corretamente os problemas imediatos: **alert fatigue**, **MTTR alto**, **ausência de contexto de risco de negócio** e **exposição regulatória** (PCI-DSS, BACEN). A escolha de um motor de decisão determinístico sem IA generativa é tecnicamente defensável para a v1 — garante auditabilidade e previsibilidade em ambiente de alta exigência regulatória.

O estudo V3 mostra que o mercado global está convergindo para exatamente a mesma direção que o V2 tomou (SSVC, EPSS, KEV, correlação de fontes), validando a estratégia. O gap principal não é de direção, mas de **ritmo**: o volume de vulnerabilidades geradas por IA cresce mais rápido do que a capacidade de triagem humana — e o V2 precisará de uma camada de IA generativa (Horizonte B) para manter a eficácia conforme o volume escala.

**A prioridade máxima que não pode esperar:** implementar sanitização de input anti-envenenamento de agentes (Horizonte A, item A1) — o vetor está confirmado em produção e o V2 atual não o contempla explicitamente.

---

*Documento produzido em: 2026-07-21 | Atualizado com análise NRM_134*
*Referências V2: PRD.md, ARCHITECTURE.md, DECISION_ENGINE_SPEC.md, INTEGRATIONS.md, TASKS.md, DATA_MODEL.md, decision_engine/rules/*
*Referências V3: relatorio_vulnerabilidades.md, mapeamento_projetos_gestao_vulnerabilidades.md*
*Referências NRM_134: avaliacao-classificacao-vulnerabilidades/SKILL.md, inventario-identificacao-vulnerabilidades/SKILL.md, reclassificacao-findings-sem-cve/SKILL.md*
