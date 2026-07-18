---
name: avaliacao-classificacao-vulnerabilidades
description: "Use quando precisar calcular impacto, probabilidade, quadrante (Q1-Q16), prioridade e SLA de vulnerabilidades conforme NRM_134."
argument-hint: "Forneca valores de BIA, PCI, exposicao, arquitetura, CVSS, threat intel, exploit e camada afetada"
---

# Avaliacao e Classificacao de Vulnerabilidades (Motor de Risco NRM_134)

## Quando usar
- Priorizacao de backlog de vulnerabilidades
- Reclassificacao de risco apos mudanca de contexto
- Definicao de prioridade e prazo de correcao (SLA)

## Formulas oficiais
- **Impacto** = (BIA * 1) + (PCI * 1) + (Exposicao * 1) + (Arquitetura * 1.5)
- **Probabilidade** = (CVSS * 1) + (ThreatIntel * 1.1) + (Exploit * 1.1) + (CamadaAfetada * 0.8)

## Escalas recomendadas
- BIA: Crise 100, Alto 50, Medio 25, Baixo 10
- PCI: Sim 100, Nao 10
- Exposicao: Exposto 100, Nao exposto 10
- Arquitetura: App/Web 100, API 80, Mobile 60, Infra 50, Workflow 40, Enduser 20, Mainframe 10
- CVSS (faixa): Critico 100, Alto 80, Medio 40, Baixo 10
- ThreatIntel: Listada 100, Nao listada 10
- Exploit: Possui exploit 100, Nao possui 10
- Camada afetada: Aplicacao 100, Middleware 80, Banco 50, SO 30, Appliance 20, Hardening 10

## Matriz e SLA
- Score acima de 400 deve ser limitado ao eixo 400.
- Classificar quadrante de Q1 a Q16 pela matriz de impacto x probabilidade (eixo X = probabilidade 1-4, eixo Y = impacto 1-4).
- **SLA por quadrante**:
  - Q13-Q16 (Muito Alta/Crítico): 24 horas
  - Q9-Q12 (Alta): 7 dias
  - Q5-Q8 (Média): 30 dias
  - Q1-Q4 (Baixa): 90 dias

## Processo de execucao
1. Validar completude dos 8 fatores de entrada.
2. Calcular impacto e probabilidade.
3. Determinar quadrante e prioridade.
4. Definir SLA.
5. Registrar resultado no ITSM com justificativa objetiva e evidencias.
6. Encaminhar para tratativa/correcao.

## Excecao operacional
- Quando nao houver CVSS fornecido por ferramenta automatizada, usar severidade da ferramenta como referencia inicial para priorizacao e registrar esta excecao no ticket.

