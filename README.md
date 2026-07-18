# SAGA-SAGV-V2-2 — Documentação e Contexto de Negócio

Repositório de **documentação, histórico e material de negócio** do projeto de
melhoria do processo de gestão de vulnerabilidades da Cielo. Não contém código
de implementação.

## Estrutura

- **`Old/`** — o modelo em produção hoje (regra NRM_134): `SKILL.md` descreve o
  motor Python de classificação/reclassificação de vulnerabilidades que
  consome dados do Tenable; `Comparativo.md` compara esse modelo com o modelo
  SSVC adaptado proposto em `vuln-mgmt-cielo/`.
- **`vuln-mgmt-cielo/docs-negocio/`** — a proposta técnica e de ROI já
  aprovada (`documento_projeto_vuln_mgmt.docx`) e a árvore de decisão SSVC em
  formato visual (`arvore-decisao-vulnerabilidades.mermaid`/`.html`).
- **`vuln-mgmt-cielo/vuln-mgmt-project/`** — pasta local que espelha o
  conteúdo do repositório de código/especificação de engenharia
  (`SAGA-SAGV-V2`, separado — ver `.gitignore` deste repositório). Contém
  PRD, arquitetura, modelo de dados, especificação do motor de decisão,
  integrações e o backlog de implementação em trilhas paralelas.

## Relação entre os dois repositórios

| Este repositório (`SAGA-SAGV-V2-2`) | Repositório de código (`SAGA-SAGV-V2`) |
|---|---|
| Documentação de negócio, histórico do modelo atual (NRM_134), comparativos | Especificação de engenharia e, à medida que as trilhas avançarem, o código de implementação (conectores, motor de decisão, orquestração, mitigação) |
| `Old/`, `vuln-mgmt-cielo/docs-negocio/` | `vuln-mgmt-cielo/vuln-mgmt-project/` (pasta local, git próprio) |
| https://github.com/rcenerini/SAGA-SAGV-V2-2.git | https://github.com/rcenerini/SAGA-SAGV-V2.git |

A pasta `vuln-mgmt-cielo/vuln-mgmt-project/` está fisicamente aninhada aqui
por conveniência local, mas é um repositório git independente — este
repositório a ignora via `.gitignore`.
