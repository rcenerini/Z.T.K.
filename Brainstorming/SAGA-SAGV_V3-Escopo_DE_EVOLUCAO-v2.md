# SAGA-SAGV — Escopo de Evolução
## Da Implementação V2 ao Roadmap de Maturidade em Gestão de Vulnerabilidades com IA

> **Data:** 2026-07-21 (atualizado com análise NRM_134 e Convergência Agêntica MDASH)
> **Fontes base:**
> - `SAGA-SAGV_V2/vuln-mgmt-project` — projeto em execução (PRD, ARCHITECTURE, DECISION_ENGINE_SPEC, INTEGRATIONS, TASKS)
> - `SAGA-SAGV_V3/relatorio_vulnerabilidades.md` — pesquisa de estado da arte global
> - `SAGA-SAGV_V3/mapeamento_projetos_gestao_vulnerabilidades.md` — mapeamento de projetos por horizonte
> - `vma-veracode/_Agents-GVul/skills/avaliacao-classificacao-vulnerabilidades/SKILL.md` — modelo de pesos atual (NRM_134)
> - `vma-veracode/_Agents-GVul/skills/inventario-identificacao-vulnerabilidades/SKILL.md` — inventário e identificação NRM_134
> - `vma-veracode/_Agents-GVul/skills/reclassificacao-findings-sem-cve/SKILL.md` — reclassificação de findings sem CVE

---

## Sumário Executivo

O projeto SAGA-SAGV V2 representa a **primeira geração** de defesa à velocidade de máquina para gestão de vulnerabilidades na organização. Ele resolve os problemas corretos — triagem manual inviável, CVSS puro sem contexto, ausência de rastreabilidade regulatória — com as ferramentas corretas, sem introduzir riscos de IA generativa antes da fundação estar estável.

Este documento descreve:
1. O **modelo de pesos atual (NRM_134)** e o gap em relação ao motor V2.
2. O **estado atual** do V2: o que cada componente faz, seu status e dependências.
3. Os **gaps identificados** à luz do estado da arte (V3), com destaque explícito para as capacidades de orquestração multi-agente.
4. O **roadmap de evolução** e a **Avaliação de Paralelização Agêntica**, detalhando como antecipar os conceitos do **Projeto MDASH da Microsoft** (debate multi-agente) de forma segura em paralelo ao pipeline determinístico do V2.

A conclusão central é que **o V2 está correto na direção**, mas a arquitetura de cibersegurança — que atua de forma transversal nas iniciativas de negócio e não apenas na proteção de dados — deve evoluir para incorporar as fórmulas NRM_134 como camada de score e antecipar o modo de observação (Shadow Mode) dos agentes autônomos.

---

## Parte 0 — O Modelo de Pesos Atual: NRM_134
*(Mantido conforme processo vigente de cálculo de Risco e SLA via quadrantes Q1-Q16)*
> O motor V2 atual substituiu parcialmente o modelo de pesos NRM_134 por uma árvore binária que ignora 3 dos 8 fatores de risco. A evolução imediata (Horizonte A0) propõe a reintegração dessas métricas.

---

## Parte 1 — O que está sendo construído no V2
*(A arquitetura de ingestão, normalização, enriquecimento e motor SSVC se mantém conforme a especificação original, servindo como a "Paved Road" segura sobre a qual a IA será orquestrada).*

---

## Parte 2 — Gaps Identificados pelo Estado da Arte

### Gap 1 — Ausência de proteção contra envenenamento de agentes 🔴 CRÍTICO
*(Risco de injeção de backdoors via reports de bugs maliciosos. Impacto direto na esteira de pagamentos e transações financeiras).*

### Gap 2 — Motor de decisão sem capacidade de aprendizado 🟡 IMPORTANTE 
**[🎯 MARCO DE CONVERGÊNCIA: CONCEITO MDASH]**

**O que o V3 documenta:** O volume de achados gerados por ferramentas como Veracode e Orca está crescendo exponencialmente. A triagem puramente humana ou baseada apenas em árvores de decisão estáticas (SSVC) atingirá um teto operacional. **Sistemas de vanguarda como o MDASH da Microsoft utilizam a orquestração de múltiplos agentes (agentes auditores e debatedores) para filtrar falsos positivos com alta precisão, comprovando riscos reais.**

**O que o V2 não cobre:** O motor determinístico SSVC escala a tomada de decisão para os extremos (TRACK ou ACT), mas a fila intermediária (ATTEND) se tornará um gargalo se não houver um componente agêntico validando a explorabilidade e o contexto.

---

## Parte 3 — Roadmap de Evolução (Com Marcos MDASH)

### Horizonte A — Imediato (sem alterar escopo v1, paralelo ao M3)
* **A0 — Integração Preservativa do Modelo NRM_134 ao Motor V2** 🔴 PRIORITÁRIO
* **A1 — Sanitização de Input Anti-Envenenamento** (Pré-requisito para orquestração de IA).
* **A2 — Ativar Reachability Analysis no Veracode SCA.**

### Horizonte B — Médio Prazo (6–18 meses após M3)
* **B1 — Triagem Assistida por IA para ATTEND** (Copiloto propondo decisões baseadas em contexto e RAG).
* **B2 — Combinações Tóxicas Expandidas (Orca Graph + Tenable + PCI).**

### Horizonte C — Longo Prazo (18+ meses após M3)
* **C1 — APR Supervisionado — Reparação Semântica de Código.**
* **C2 — Debate Agêntico para Pré-Validação [🎯 ADOÇÃO DIRETA: ARQUITETURA MDASH]**
  **O que é:** Expansão da triagem para orquestrar dezenas de LLMs especializados operando em papéis opostos, exatamente como concebido pelo sistema MDASH:
  - **Agentes Auditores:** Analisam os achados de SAST/SCA/CNAPP e propõem hipóteses de exploração.
  - **Agentes Debatedores:** Analisam a arquitetura de negócio e tentam refutar a alcançabilidade da falha.
  A discordância entre modelos aciona a revisão humana. Apenas achados comprovados chegam ao analista de cibersegurança.

---

## Parte 4 — Avaliação de Paralelização: Antecipando o V3 no V2

Dado o estágio de maturidade técnica das automações CI/CD e a clareza da taxonomia de risco baseada no framework CTEM contida na organização, **é altamente viável antecipar a lógica do MDASH (Horizonte C) para o ecossistema V2 atual (Horizonte A/M1)** através de uma estratégia de paralelismo não obstrutivo.

### A Estratégia "Shadow Agent" (Paralelização Segura)

Em vez de aguardar 18 meses para introduzir o debate agêntico, podemos conectar o ecossistema MDASH ao V2 imediatamente, utilizando a seguinte topologia de arquitetura:

1. **Bifurcação no Tópico de Eventos (Event-Driven Architecture):**
   Após a etapa de **Enriquecimento e Contexto de Ativo (Nó T1.8)**, onde os dados da Veracode, Orca e CMDB já foram consolidados no objeto `ContextualizedFinding`, criamos uma bifurcação (fan-out) no stream (ex: via AWS SNS/EventBridge).
   
2. **Execução Simultânea:**
   * **Caminho A (Produção/Bloqueante):** O Motor de Decisão SSVC recebe o JSON, processa as regras determinísticas (incluindo NRM_134) e despacha a decisão oficial para as filas de ação (Jira, GitHub PRs, Akamai WAF).
   * **Caminho B (Shadow Mode MDASH):** Os mesmos dados de vulnerabilidade alimentam um cluster inicial de **Agentes Debatedores**. Estes agentes tentam avaliar o achado, correlacionar com outras falhas e emitir um `ProposedAgenticDecisionRecord`.

3. **Validação Contínua (CTEM Alignment):**
   Os resultados gerados pela IA não afetam a produção, mas são gravados em um repositório analítico paralelo (Data Lake/Athena). O time de arquitetura de cibersegurança passa a utilizar esses dados para:
   * **Benchmarking:** Comparar a decisão do motor SSVC (humana/determinística) contra a decisão da IA (MDASH).
   * **Fine-Tuning:** Corrigir alucinações e refinar os *prompts* e *skills* dos agentes (como os arquivos de skill `reclassificacao-findings-sem-cve`).

### Vantagens da Antecipação Agêntica

* **Treinamento no Contexto Real:** O ecossistema de IAs começará a aprender imediatamente sobre a topologia de pagamentos corporativos, arquitetura transversal e regras de negócio específicas da empresa, acelerando o tempo de maturidade para a autonomia.
* **Redução Antecipada de Falsos Positivos:** Analistas que lidam com a fila `ATTEND` do SSVC poderão consultar, sob demanda, o log gerado pelos agentes em *Shadow Mode*, ganhando agilidade na triagem mesmo antes da IA ter poder de bloqueio (Enforcement).
* **Evolução Gradual e Zero Atrito:** Não exige refatoração da "Paved Road" já construída. Se a orquestração de IA falhar ou gerar ruído, a esteira principal V2 continua operando normalmente através de sua base determinística.
