# Comparativo — Modelos de Classificação e Priorização de Vulnerabilidades

> Comparação entre o modelo **realmente implementado hoje** — regra NRM_134 + motor Python
> que a executa, descrito em `_Agents-GVul/skills/avaliacao-classificacao-vulnerabilidades/SKILL.md`
> — e o modelo SSVC adaptado proposto (pasta `vuln-mgmt-cielo`), com foco em **como cada um
> contextualiza e pondera vulnerabilidades para classificação/priorização**.
>
> Nota de escopo: os arquivos `saga_*.agent.md` (orquestração multi-agente) foram
> **excluídos** desta comparação — são uma camada de automação em discussão, ainda não em
> execução. A fonte canônica do que roda em produção hoje é a `SKILL.md`.

## 1. Modelo em produção — NRM_134 (motor Python, `SKILL.md`)

**Filosofia:** modelo aditivo-ponderado (scoring), com matriz Impacto × Probabilidade em 16 quadrantes.

**Impacto** = `(BIA×1) + (PCI×1) + (Exposição×1) + (Arquitetura×1.5)`
**Probabilidade** = `(CVSS×1) + (ThreatIntel×1.1) + (Exploit×1.1) + (CamadaAfetada×0.8)`

### Fatores de entrada e escalas

| Fator | Eixo | Peso | Escala |
|---|---|---|---|
| BIA | Impacto | 1 | Crise 100 / Alto 50 / Médio 25 / Baixo 10 |
| PCI | Impacto | 1 | Sim 100 / Não 10 |
| Exposição | Impacto | 1 | Exposto 100 / Não exposto 10 |
| Arquitetura | Impacto | 1.5 | App/Web 100, API 80, Mobile 60, Infra 50, Workflow 40, Enduser 20, Mainframe 10 |
| CVSS (faixa) | Probabilidade | 1 | Crítico 100 / Alto 80 / Médio 40 / Baixo 10 |
| ThreatIntel | Probabilidade | 1.1 | Listada 100 / Não listada 10 |
| Exploit | Probabilidade | 1.1 | Possui 100 / Não possui 10 |
| Camada afetada | Probabilidade | 0.8 | Aplicação 100, Middleware 80, Banco 50, SO 30, Appliance 20, Hardening 10 |

### Matriz e SLA (regra vigente, conforme `SKILL.md`)

- Score acima de 400 é limitado ao eixo 400 (cap).
- Quadrante Q1–Q16 determinado pela posição na matriz Impacto × Probabilidade (eixo X = probabilidade 1–4, eixo Y = impacto 1–4).
- **SLA por quadrante:**
  - Q13–Q16 (Muito Alta/Crítico): **24 horas**
  - Q9–Q12 (Alta): **7 dias**
  - Q5–Q8 (Média): **30 dias**
  - Q1–Q4 (Baixa): **90 dias**

### Processo

1. Validar completude dos 8 fatores de entrada.
2. Calcular impacto e probabilidade.
3. Determinar quadrante e prioridade.
4. Definir SLA.
5. Registrar resultado no ITSM com justificativa objetiva e evidências.
6. Encaminhar para tratativa/correção.

### Exceção operacional

Quando não houver CVSS fornecido por ferramenta automatizada, usar a severidade da
ferramenta como referência inicial para priorização e registrar essa exceção no ticket.

## 2. Modelo SSVC adaptado (`vuln-mgmt-cielo`)

**Filosofia:** árvore de decisão determinística (não scoring aditivo), inspirada no SSVC
(Stakeholder-Specific Vulnerability Categorization) do CERT/CISA.

Entradas — apenas **5 sinais booleanos/categóricos**, hierárquicos (cada nó só é avaliado
se o anterior não decidiu):

1. `is_publicly_exposed` (exposição pública)
2. `in_kev_catalog` (está no catálogo KEV da CISA — exploração confirmada em campo)
3. `is_exploit_automatable` (proxy: EPSS > limiar + exploit público conhecido)
4. `technical_impact` (none/partial/total)
5. `business_criticality` (critical/high/medium/low, com **fallback conservador = "critical"** se ausente)

Saída: `TRACK` (sem SLA) → `TRACK*` (monitorar, sem SLA) → `ATTEND` (14–60 dias, a
calibrar) → `ACT_14` (14 dias) → `ACT_3` (3 dias + mitigação automática + IR/SOC).

Não há pesos numéricos nem soma — é lógica condicional pura (if/else em cascata), o que
elimina ambiguidade de "quanto vale cada fator" e produz decisões binárias auditáveis
(`rationale` como lista de strings).

## 3. Comparação direta

| Dimensão | NRM_134 (motor Python em produção) | SSVC adaptado (cielo) |
|---|---|---|
| **Mecanismo** | Scoring aditivo ponderado + matriz 4×4 | Árvore de decisão determinística |
| **Nº de fatores** | 8 (BIA, PCI, Exposição, Arquitetura, CVSS, ThreatIntel, Exploit, Camada) | 5 (exposição, KEV, automatable, impacto técnico, criticidade negócio) |
| **Pesos** | Explícitos e numéricos (1, 1.5, 1.1, 0.8...) — mas arbitrários, sem justificativa documentada do porquê desses valores específicos | Implícitos na ordem da árvore — cada nó é um "gate", não uma soma; a hierarquia em si é a política de risco |
| **Exploração real** | "Exploit possui/não possui" — genérico, sem fonte de dados obrigatória especificada | KEV da CISA (fonte pública, verificável) + EPSS como proxy de automação — dados vivos, não estático |
| **Reavaliação contínua** | Não desenhado na regra (reclassificação é manual, "após mudança de contexto") | RF5: reclassificação automática por evento (novo KEV, mudança de EPSS, mudança de exposição) |
| **Dado ausente** | Regra de fallback só para CVSS ausente (usa severidade da ferramenta); demais fatores sem regra explícita | Regra explícita para todo o bloco de negócio: fallback sempre conservador (`business_criticality = critical` se CMDB não tem dado) — nunca subestima |
| **Auditoria** | Registro no ITSM com "justificativa objetiva" (texto livre, não estruturado) | `rationale` estruturado (lista de decisões nó-a-nó), log append-only, versionado — desenhado para PCI DSS 4.0 / BACEN |
| **Ação automática** | Nenhuma — motor só classifica e encaminha para tratativa | `ACT_3` dispara runbook de mitigação automática pré-aprovado pelo CAB + abre triagem forense, sem esperar humano |
| **Testabilidade** | Não há matriz de casos de teste formal documentada na regra | Matriz de 9 casos de teste obrigatórios cobrindo todas as combinações relevantes da árvore |
| **Criticidade de negócio** | Fator aditivo (BIA) com peso 1, junto com PCI e exposição — dilui-se na soma total | Fator de **desempate final** — só decide entre `ACT_3` vs `ACT_14`, depois que exposição+KEV+automação+impacto total já colocaram o achado no pior grupo. Evita que um ativo crítico sem exploração real vire "urgência" só pelo peso do BIA |
| **Saturação de score** | Cap explícito em 400 por eixo — mas sem tratamento de como isso afeta o posicionamento em quadrantes de borda | Não aplicável (não há soma, não há saturação) |

## 4. Avanços conceituais do modelo SSVC em relação ao NRM_134

1. **Sinal de exploração real como gate, não como componente de soma** — no NRM_134,
   "Exploit" e "ThreatIntel" somam pontos e podem ser compensados por outros fatores (ex.:
   Arquitetura com peso 1.5). No SSVC, KEV é um nó decisório: sem KEV nem exploit
   automatizável, o pior caso possível é `ATTEND`, nunca `ACT`. Isso resolve exatamente o
   problema citado no PRD (CVE rotulado "Moderado" pelo fabricante mas com exploração ativa
   confirmada).
2. **Reavaliação orientada a evento**, não a ciclo — o NRM_134, na regra vigente, não define
   gatilho de reclassificação automática por mudança de sinal (KEV, EPSS, exposição).
3. **Fallback conservador obrigatório e documentado** para dado ausente de contexto de
   negócio — o NRM_134 só tem esse tipo de regra para CVSS ausente.
4. **Rastreabilidade estruturada por nó de decisão** (`rationale` como lista), mais
   auditável que "justificativa objetiva" em texto livre.
5. **Separação decisão vs. ação**: o SSVC já prevê runbook automático para `ACT_3`, algo
   ausente na regra NRM_134 atual (que só chega até "encaminhar para tratativa/correção").

## 5. Ponto de atenção

O `ATTEND_SLA_DAYS` do modelo SSVC ainda está em aberto (faixa 14–60 dias, "a calibrar com
o time de risco na Fase 0") — é o único parâmetro do novo modelo que ainda não tem valor
definitivo, e vale ser fechado antes de qualquer comparação quantitativa de SLA entre os
dois modelos (ex.: quanto tempo um achado leva, em média, entre um modelo e outro).