# Mapeamento de Projetos: Gestão de Vulnerabilidades à Velocidade de Máquina

**Proposta interna para liderança de segurança (CISO/board)**
**Baseado em:** `relatorio_vulnerabilidades.md`
**Stack de detecção atual:** Veracode (SAST/DAST/SCA), Orca Security (CNAPP), Tenable (Vulnerability Management)

---

## Sumário Executivo

O relatório em anexo documenta uma mudança de paradigma: a triagem manual de vulnerabilidades colapsou sob o volume gerado por IA (caso cURL, sobrecarga da NVD), enquanto surgem novos modelos de identificação agêntica (MDASH da Microsoft, CRS do DARPA AIxCC), categorização probabilística (EPSS v4, SSVC) e resolução autônoma supervisionada (APR).

Hoje operamos três ferramentas de detecção de classe mundial — Veracode, Orca e Tenable — mas cada uma opera em silo, gerando achados que ainda dependem de triagem manual baseada em CVSS puro. Isso produz exatamente os sintomas descritos no relatório: **volume excessivo de achados, MTTR alto, ausência de contexto de risco de negócio e exposição regulatória** (PCI-DSS, Bacen).

Esta proposta mapeia **11 projetos organizados em 3 horizontes temporais**, todos ancorados no stack já licenciado — sem necessidade de substituir ferramentas — mais uma camada de governança específica para os riscos de automação com IA que o próprio relatório documenta (envenenamento de agentes, backdoors via prompt injection).

| Horizonte | Foco | Investimento relativo | Projetos |
|---|---|---|---|
| Curto prazo (0–6m) | Correlação e priorização com contexto | Baixo | 4 |
| Médio prazo (6–18m) | Automação de decisão e redução de falso positivo | Médio | 4 |
| Longo prazo (18m+) | Resolução autônoma supervisionada | Alto | 3 |
| Transversal | Governança de agentes de IA | Baixo (mas contínuo) | 1 seção |

---

## Horizonte 1 — Curto Prazo (0–6 meses)

### Projeto 1: Camada de Correlação de Achados
- **Problema que resolve:** alert fatigue — hoje a equipe triagem em 3 telas separadas (Veracode, Orca, Tenable) sem visão unificada.
- **O que é:** registro único de risco que ingere via API os achados das três ferramentas, deduplica ativos comuns (ex.: mesma aplicação aparece no SAST do Veracode e no scan de workload do Orca) e normaliza severidades.
- **Ferramentas envolvidas:** Veracode API, Orca API, Tenable.io API + camada de dados própria (pode começar em uma planilha estruturada ou banco simples antes de uma ferramenta dedicada).
- **Esforço:** baixo — integrações via API já documentadas pelos três fornecedores.
- **Métrica de sucesso:** redução do tempo de triagem inicial; eliminação de achados duplicados reportados como incidentes distintos.

### Projeto 2: Overlay de EPSS v4 sobre CVSS
- **Problema que resolve:** ~40% dos CVEs são classificados Alto/Crítico pelo CVSS — sem discriminação, a equipe não sabe o que atacar primeiro.
- **O que é:** consumir a API pública do FIRST (EPSS v4) e enriquecer cada achado de Tenable/Veracode com a probabilidade de exploração em 30 dias. Conforme demonstrado no relatório, isso permite atingir 74,6% de cobertura de proteção corrigindo apenas 6% do catálogo (vs. 50% do catálogo pelo CVSS puro) — ganho de eficiência de ~8x.
- **Ferramentas envolvidas:** API FIRST/EPSS (gratuita) + camada de correlação do Projeto 1.
- **Esforço:** baixo.
- **Métrica de sucesso:** % de esforço de remediação redirecionado para achados com EPSS alto; redução de horas-analista por vulnerabilidade real mitigada.

### Projeto 3: Tagueamento de Escopo PCI-DSS (CDE)
- **Problema que resolve:** falta de contexto de risco de negócio — um CVSS 9.8 num ambiente de teste pesa igual a um CVSS 9.8 numa aplicação que processa dados de cartão.
- **O que é:** classificar ativos (repositórios no Veracode, workloads no Orca, hosts no Tenable) conforme pertencem ou não ao Cardholder Data Environment (CDE). Essa tag vira um multiplicador de prioridade em todos os projetos seguintes.
- **Ferramentas envolvidas:** metadados/tags nativas das três plataformas + CMDB de ativos, se existir.
- **Esforço:** baixo-médio — trabalho principal é de mapeamento/inventário, não técnico.
- **Métrica de sucesso:** 100% dos ativos em escopo PCI identificados e tagueados; auditor externo consegue rastrear a decisão de priorização até o escopo regulatório.

### Projeto 4: Dashboard Executivo de Risco
- **Problema que resolve:** falta de visibilidade de liderança sobre MTTR real e exposição regulatória.
- **O que é:** painel único (para CISO/board) mostrando MTTR por severidade ajustada (EPSS + PCI scope), SLA de patch cumprido vs. estourado, e tendência de exposição ao longo do tempo — substitui relatórios manuais.
- **Ferramentas envolvidas:** consolida saída dos Projetos 1–3.
- **Esforço:** baixo — é a "vitrine" dos três projetos anteriores.
- **Métrica de sucesso:** adoção do dashboard como fonte única de verdade em reuniões de risco.

---

## Horizonte 2 — Médio Prazo (6–18 meses)

### Projeto 5: Adoção formal de SSVC
- **Problema que resolve:** decisões de patch ainda binárias e reativas ("CVSS ≥ 7 corrige tudo"), sem ligação a contexto de missão.
- **O que é:** implementar as árvores de decisão SSVC (Exploração, Impacto Técnico, Automação, Contexto de Missão) da CISA/Carnegie Mellon, produzindo classificações acionáveis (Act/Attend/Track/Track*) em vez de números abstratos. Espelha o movimento regulatório que a própria CISA já formalizou via BOD 26-04.
- **Ferramentas envolvidas:** framework de decisão sobre os dados já correlacionados (Projetos 1–3); requer trabalho de parametrização com stakeholders de negócio.
- **Esforço:** médio — exige workshops com áreas de negócio para calibrar "contexto de missão".
- **Métrica de sucesso:** % de achados classificados via SSVC vs. CVSS puro; redução de disputas internas sobre prioridade de patch.

### Projeto 6: Reachability Analysis no Pipeline CI/CD
- **Problema que resolve:** SCA tradicional (Veracode) sinaliza qualquer biblioteca vulnerável presente no disco, mesmo que o código nunca a invoque — gerando esforço de correção desnecessário.
- **O que é:** ativar/expandir os recursos de reachability do Veracode SCA (source-to-sink, tree-shaking) integrados ao pipeline, rebaixando automaticamente a prioridade de achados em código morto ou não alcançável.
- **Ferramentas envolvidas:** Veracode SCA (capacidades nativas de reachability, se licenciadas) + pipeline CI/CD.
- **Esforço:** médio — depende do nível de licença Veracode e de instrumentação do pipeline.
- **Métrica de sucesso:** redução de falsos positivos de SCA sem aumento de risco real (validado por amostragem).

### Projeto 7: Motor de "Combinações Tóxicas" em Nuvem
- **Problema que resolve:** um achado de severidade média isolado pode ser crítico quando combinado com exposição de rede e privilégios excessivos — algo que nenhuma ferramenta isolada enxerga.
- **O que é:** usar o grafo de contexto do Orca CNAPP (exposição, IAM, dados sensíveis) cruzado com achados de rede do Tenable e a tag de escopo PCI (Projeto 3) para detectar automaticamente cenários do tipo *workload exposto à internet + IAM excessivo + acesso a dados de cartão* e escalar para "fix now".
- **Ferramentas envolvidas:** Orca Security (graph/context engine nativo) + Tenable + dados do Projeto 3.
- **Esforço:** médio-alto — depende de quanto do graph engine do Orca é exposto via API para consumo externo.
- **Métrica de sucesso:** número de combinações tóxicas identificadas antes de se tornarem incidente; tempo de remediação desses casos vs. achados isolados.

### Projeto 8: Triagem Assistida por IA com Humano no Circuito
- **Problema que resolve:** volume de achados ainda excede capacidade de análise humana mesmo após os Projetos 1–7.
- **O que é:** piloto controlado de agente de IA (modelo comercial ou aberto, hospedado internamente) que cruza os três feeds e propõe severidade ajustada e classificação SSVC preliminar — inspirado no modelo de "debate agêntico" do MDASH da Microsoft, mas em escala reduzida e **sem autonomia de ação**: toda proposta é revisada por analista humano antes de virar SLA.
- **Ferramentas envolvidas:** LLM (comercial via API ou modelo aberto self-hosted) + dados correlacionados dos projetos anteriores.
- **Esforço:** médio-alto — primeiro piloto de IA generativa no fluxo, exige validação cuidadosa e governança (ver seção transversal).
- **Métrica de sucesso:** % de propostas do agente aceitas sem alteração pelo analista humano; redução de tempo de triagem por achado.

---

## Horizonte 3 — Longo Prazo (18+ meses)

### Projeto 9: Piloto de APR (Automated Program Repair) Supervisionado
- **Problema que resolve:** MTTR de correção de dependências vulneráveis (semanas/meses) — o gargalo real já não é identificar, é corrigir.
- **O que é:** agente de IA que, para uma classe restrita de vulnerabilidades (ex.: bumps de versão de dependências com breaking changes conhecidos), gera o patch completo — incluindo ajustes de código para compatibilidade — roda a suíte de testes em ambiente isolado e abre um Pull Request auditável. **Nunca aplica sozinho**: PR fica retido sob revisão humana obrigatória (human-in-the-loop), como praticado pela maioria das implementações corporativas descritas no relatório.
- **Ferramentas envolvidas:** LLM especializado + pipeline CI/CD + repositórios versionados; complementa (não substitui) o SCA do Veracode.
- **Esforço:** alto — requer ambiente de teste isolado robusto e critérios claros de escopo (começar com dependências de baixo risco).
- **Métrica de sucesso:** % de PRs gerados por IA aceitos sem retrabalho humano significativo; redução de MTTR nas classes de vulnerabilidade cobertas.

### Projeto 10: Camada de Debate Agêntico para Pré-Validação
- **Problema que resolve:** mesmo com triagem assistida (Projeto 8), falsos positivos consomem tempo de analista.
- **O que é:** expandir o Projeto 8 para um modelo de dois agentes com papéis opostos — um "auditor" que propõe achados suspeitos e um "debatedor" que tenta refutá-los via análise de fluxo de dados. Só o que sobrevive ao debate chega ao analista humano. O relatório aponta esse padrão (MDASH) como capaz de reduzir falsos positivos em mais de dois terços.
- **Ferramentas envolvidas:** dois modelos de IA (idealmente de famílias/fornecedores distintos, para evitar viés correlacionado) + infraestrutura do Projeto 8.
- **Esforço:** alto — maturidade de IA generativa e engenharia de prompt/validação significativa.
- **Métrica de sucesso:** redução mensurável de falsos positivos chegando à fila humana, sem aumento de falsos negativos (auditado por amostragem).

### Projeto 11: Modelo Local/On-Prem para Resposta a Incidentes
- **Problema que resolve:** o "paradoxo Hugging Face" documentado no relatório — guardrails de APIs comerciais de IA recusam analisar payloads/telemetria de ataque real por interpretá-los como pedido malicioso, travando a investigação forense justamente quando mais se precisa dela.
- **O que é:** hospedar internamente um modelo de pesos abertos, isolado do perímetro de rede, dedicado exclusivamente à análise forense e de resposta a incidentes — sem as restrições de um provedor externo. Uso restrito à equipe de IR, com controles de acesso rígidos.
- **Ferramentas envolvidas:** infraestrutura própria (GPU on-prem ou cloud isolada) + modelo aberto; não integra ao fluxo de detecção do dia a dia, é ferramenta de exceção para incidentes.
- **Esforço:** alto — investimento em infraestrutura dedicada, ainda que de uso esporádico.
- **Métrica de sucesso:** disponibilidade comprovada em simulações de incidente (tabletop exercises); tempo de reconstrução de linha do tempo de ataque.

---

## Seção Transversal — Governança e Riscos da Automação com IA

Todo projeto que envolve agentes de IA atuando sobre código ou infraestrutura (Projetos 8, 9, 10, 11) carrega os riscos que o próprio relatório documenta: **envenenamento de relatórios/prompts** e **injeção de backdoors** via submissões maliciosas disfarçadas de bugs legítimos. Para uma adquirência, isso não é risco abstrato — são agentes com potencial de tocar código que processa transações financeiras.

Controles obrigatórios, válidos a partir do Projeto 8:

- **RBAC rígido e credenciais mínimas** para qualquer agente de IA — sem acesso amplo a segredos, chaves ou produção.
- **Auditoria por segundo modelo** antes de qualquer merge automatizado (nunca um único modelo decide sozinho).
- **Blindagem de sistemas de tracking** (Jira, GitHub Issues) contra prompt injection indireta — todo relatório de bug que alimenta um agente de IA deve passar por sanitização.
- **Human-in-the-loop obrigatório** em toda ação que altere código de produção — nenhum projeto desta lista propõe remediação totalmente autônoma sem revisão humana.
- **Trilha de auditoria completa** de toda decisão tomada ou proposta por IA, para sustentar evidência perante reguladores (PCI-DSS, Bacen).

---

## Tabela-Resumo: Esforço x Impacto

| # | Projeto | Horizonte | Esforço | Impacto | Dor principal endereçada |
|---|---|---|---|---|---|
| 1 | Correlação de achados | Curto | Baixo | Alto | Alert fatigue |
| 2 | Overlay EPSS v4 | Curto | Baixo | Alto | Alert fatigue / MTTR |
| 3 | Tagueamento PCI (CDE) | Curto | Baixo-Médio | Alto | Contexto de negócio / Compliance |
| 4 | Dashboard executivo | Curto | Baixo | Médio | Visibilidade de liderança |
| 5 | Adoção de SSVC | Médio | Médio | Alto | Contexto de negócio |
| 6 | Reachability analysis | Médio | Médio | Médio | Alert fatigue (falso positivo) |
| 7 | Combinações tóxicas (cloud) | Médio | Médio-Alto | Alto | Contexto de negócio |
| 8 | Triagem assistida por IA | Médio | Médio-Alto | Alto | Alert fatigue / MTTR |
| 9 | APR supervisionado | Longo | Alto | Alto | MTTR |
| 10 | Debate agêntico | Longo | Alto | Alto | Alert fatigue (falso positivo) |
| 11 | Modelo local para IR | Longo | Alto | Médio | Resposta a incidentes |

**Recomendação de sequenciamento:** iniciar pelos Projetos 1–4 (baixo esforço, alto impacto, sem dependência de IA generativa) para gerar tração e evidência de resultado antes de propor investimento nos horizontes médio e longo — que exigem orçamento maior e apetite de risco para automação com IA.
