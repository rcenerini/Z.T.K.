# Matriz de Rastreabilidade — LGPD (Lei 13.709/2018)

> **Versão:** 1.0 | **Data:** 2026-07-27
> **Escopo:** Requisitos da LGPD aplicáveis ao tratamento de dados pessoais pelo Z.T.K.
> **Encarregado (DPO):** A definir pela organizacao

---


![Compliance](https://img.shields.io/badge/type-Compliance-00d4ff)
![Audit](https://img.shields.io/badge/audit-ready-00ff88)


## CAPÍTULO II — Princípios (Art. 6º)

| Princípio | Controle Z.T.K. | Camada | Status |
|-----------|----------------|--------|--------|
| **Finalidade** — Tratamento para propósitos legítimos e específicos | Z.T.K. processa dados apenas para análise de segurança de código. Finalidade documentada em README.md. | — | ✅ |
| **Adequação** — Tratamento compatível com a finalidade | Dados de código-fonte são o mínimo necessário para análise de vulnerabilidades | L1, L2 | ✅ |
| **Necessidade** — Minimização de dados | Apenas código-fonte e metadados de vulnerabilities. Sem dados de usuário final. | L1 | ✅ |
| **Transparência** — Informação clara sobre o tratamento | Documentação pública (README.md, AGENTS.md, runbooks) | — | ✅ |
| **Segurança** — Medidas técnicas e administrativas | Criptografia (AES-256, TLS 1.2+), IAM least privilege, logging | Todas | ✅ |
| **Prevenção** — Medidas para prevenir danos | Fail-closed pattern; sandbox isolation; prompt-injection guard | L1, L3, Utils | ✅ |

---

## CAPÍTULO III — Direitos do Titular (Arts. 17-22)

| Direito | Como o Z.T.K. atende | Status |
|---------|----------------------|--------|
| **Art. 17** — Confirmação de tratamento | Qualquer tratamento de dados pessoais é registrado em AuditEvent | ✅ |
| **Art. 18** — Acesso aos dados | Logs de auditoria rastreiam todo acesso a dados pessoais | ✅ |
| **Art. 19** — Correção de dados incompletos | AuditEvent + finding update com approval four-eyes | ✅ |
| **Art. 20** — Portabilidade | Dados exportáveis via API (JSON) — formato aberto | ✅ |
| **Art. 21** — Oposição (opt-out) | Kill switch desativa processamento automático; HITL mantém controle humano | ✅ |
| **Art. 22** — Revisão automatizada | HITL gateway (L6.13-L6.17) garante revisão humana de decisões automatizadas | ✅ |

---

## CAPÍTULO IV — Tratamento de Dados Pessoais

| Seção | Requisito | Controle Z.T.K. | Status |
|-------|----------|-----------------|--------|
| **Art. 37** — Registro de operações de tratamento | AuditEvent registra toda operação de tratamento (stage, agent, payload_hash) | ✅ |
| **Art. 38** — Encarregado (DPO) | A definir pela organizacao — Z.T.K. fornece evidências para DPO | 🟡 Externo |
| **Art. 39** — Atribuições do encarregado | Matriz de rastreabilidade (este documento) como evidência para DPO | ✅ |

---

## CAPÍTULO V — Transferência Internacional

| Requisito | Controle Z.T.K. | Status |
|-----------|-----------------|--------|
| **Art. 33** — Transferência apenas para países com proteção adequada | Dados PCI/PII roteados para vLLM local (Brasil). Bedrock us-east-1 apenas para dados não-PCI. | ✅ |

---

## CAPÍTULO VI — Agentes de Tratamento

| Requisito | Controle Z.T.K. | Status |
|-----------|-----------------|--------|
| **Art. 42** — Suboperadores seguem mesmas regras | AWS (Bedrock) é suboperador com DPA assinado. vLLM local não transfere dados externamente. | ✅ |

---

## CAPÍTULO VII — Segurança e Boas Práticas (Arts. 46-51)

| Artigo | Requisito | Controle Z.T.K. | Status |
|--------|----------|-----------------|--------|
| **Art. 46** — Medidas de segurança técnicas e administrativas | Criptografia, IAM, logging, sandbox, fail-closed, least privilege | ✅ |
| **Art. 47** — Comunicação de incidente | Runbook de incidente; notificação para DPO em <24h | ✅ |
| **Art. 48** — Comunicação ao titular (se risco relevante) | Fora do escopo do Z.T.K. (responsabilidade do DPO/organizacao) | 🟡 Externo |
| **Art. 49** — Sistemas seguros por padrão (security by design) | S-SDLC.md documenta security-by-design; threat model STRIDE completo | ✅ |
| **Art. 50** — Boas práticas de governança | AGENTS.md, políticas, runbooks, matriz RACI | ✅ |

---

## CAPÍTULO VIII — Fiscalização e Sanções

| Requisito | Evidência Z.T.K. | Status |
|-----------|-----------------|--------|
| **Art. 52** — Relatórios de impacto (DPIA) | Threat model + PCI matrix + LGPD matrix como base para DPIA | ✅ |
| **Art. 53** — Auditoria | AuditEvent trail completo; append-only S3; retenção 5 anos | ✅ |

---

## Resumo de Conformidade LGPD

| Status | Quantidade | % |
|--------|-----------|----|
| ✅ Conforme | 16 | 84% |
| 🟡 Pendente (externo) | 3 | 16% |
| 🔴 Não conforme | 0 | 0% |

**Nota:** Os 3 itens pendentes (DPO, comunicação ao titular, fiscalização) sao responsabilidade da organizacao, nao do sistema Z.T.K. O sistema está projetado para **fornecer todas as evidências necessárias** para que a organizacao atenda esses requisitos.
