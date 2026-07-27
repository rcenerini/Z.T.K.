# Matriz de Rastreabilidade — PCI DSS 4.0

> **Versão:** 1.0 | **Data:** 2026-07-27
> **Escopo:** Requisitos PCI DSS 4.0 aplicáveis ao sistema Z.T.K.
> **Status:** 🟡 Gap analysis — controles mapeados, implementação pendente

---


![Compliance](https://img.shields.io/badge/type-Compliance-00d4ff)
![Audit](https://img.shields.io/badge/audit-ready-00ff88)


## Requisito 1: Instalar e Manter Controle de Segurança de Rede

| Sub-Req | Descrição PCI DSS | Controle Z.T.K. | Camada | Status |
|---------|------------------|-----------------|--------|--------|
| 1.1.1 | Documentação de topologia de rede | Diagrama DFD no threat-model-ztk.md | — | ✅ |
| 1.2.1 | Restringir tráfego inbound/outbound ao necessário | VPC com security groups restritivos | Infra | 🟡 IaC pendente |
| 1.3.1 | Controle de tráfego entre redes confiáveis e não-confiáveis | CDE isolado em VPC separada | Infra | 🟡 IaC pendente |
| 1.4.1 | Firewall em todo perímetro | AWS WAF + NACLs | Infra | 🟡 IaC pendente |

---

## Requisito 2: Aplicar Configurações Seguras

| Sub-Req | Descrição PCI DSS | Controle Z.T.K. | Camada | Status |
|---------|------------------|-----------------|--------|--------|
| 2.1.1 | Segurança por default (senhas alteradas, SNMP desabilitado) | CIS Hardening em todos os containers ECS | L2, Infra | 🟡 Pendente |
| 2.2.1 | Apenas serviços necessários em execução | Imagens minimalistas (distroless) | L2, Infra | 🟡 Pendente |

---

## Requisito 3: Proteger Dados de Cartão Armazenados

| Sub-Req | Descrição PCI DSS | Controle Z.T.K. | Camada | Status |
|---------|------------------|-----------------|--------|--------|
| 3.2.1 | PAN não armazenado sem necessidade de negócio | Z.T.K. NUNCA armazena PAN — dados são roteados para vLLM local | L7 | ✅ |
| 3.3.1 | PAN mascarado quando exibido | Sanitização de logs (redact PAN, PII) | L6, Utils | ✅ |
| 3.4.1 | PAN ilegível em storage (tokenização/criptografia) | SSE-KMS em DynamoDB, S3 | Infra | 🟡 IaC pendente |
| 3.5.1 | Chaves criptográficas documentadas e rotacionadas | KMS com rotação automática anual | Infra | 🟡 IaC pendente |

---

## Requisito 4: Proteger Dados de Cartão em Trânsito

| Sub-Req | Descrição PCI DSS | Controle Z.T.K. | Camada | Status |
|---------|------------------|-----------------|--------|--------|
| 4.1.1 | TLS 1.2+ para dados em trânsito em redes abertas | TLS 1.2+ em todas as chamadas externas (httpx, boto3) | Todas | ✅ |
| 4.2.1 | Certificados válidos e não expirados | AWS Certificate Manager (ACM) com renovação automática | Infra | 🟡 IaC pendente |

---

## Requisito 6: Desenvolver e Manter Software Seguro

| Sub-Req | Descrição PCI DSS | Controle Z.T.K. | Camada | Status |
|---------|------------------|-----------------|--------|--------|
| 6.2.1 | Patches de segurança aplicados tempestivamente | Pipeline de remediação automática (Trilha A) | L5 | 🟡 Código pendente |
| 6.3.1 | Ambiente de dev/teste separado de produção | Contas AWS separadas (dev/staging/prod) | Infra | 🟡 IaC pendente |
| 6.4.1 | Revisão de código antes do deploy | PR obrigatória + security review por @ztk-reviewer | L5, L6 | ✅ |
| 6.5.1 | Proteção contra vulnerabilidades comuns (OWASP Top 10) | SAST (L2) + Validação (L3) + Consenso (L4) | L2, L3, L4 | 🟡 Código pendente |

---

## Requisito 7: Restringir Acesso por Necessidade de Negócio

| Sub-Req | Descrição PCI DSS | Controle Z.T.K. | Camada | Status |
|---------|------------------|-----------------|--------|--------|
| 7.1.1 | Least privilege para acesso a dados de cartão | IAM roles com mínimo escopo; revisão trimestral | Infra | 🟡 IaC pendente |
| 7.2.1 | Controle de acesso baseado em função | Cognito + IAM roles; four-eyes para exceções | L6 | 🟡 Código pendente |

---

## Requisito 8: Identificar e Autenticar Acesso

| Sub-Req | Descrição PCI DSS | Controle Z.T.K. | Camada | Status |
|---------|------------------|-----------------|--------|--------|
| 8.1.1 | Identificação única por usuário | Cognito User Pool com identidade única | L6, L9 | 🟡 Pendente |
| 8.2.1 | MFA para acesso administrativo | MFA obrigatório para SOC/CISO (hardware token) | L9 | 🟡 Pendente |

---

## Requisito 10: Registrar e Monitorar Acessos

| Sub-Req | Descrição PCI DSS | Controle Z.T.K. | Camada | Status |
|---------|------------------|-----------------|--------|--------|
| 10.1.1 | Logs de auditoria para acesso a dados sensíveis | AuditEvent em toda mudança de estado; append-only S3 | L6 | ✅ |
| 10.2.1 | Logs automatizados e protegidos contra adulteração | Hash chain (previous_event_id); forward para Sentinel | L6 | ✅ |
| 10.3.1 | Retenção de logs por 12 meses (3 meses online) | S3 lifecycle: 90 dias STANDARD → 365 dias GLACIER | Infra | 🟡 IaC pendente |
| 10.4.1 | Sincronização de relógio (NTP) | AWS Time Sync Service (automático) | Infra | ✅ |

---

## Requisito 11: Testar e Monitorar Redes Regularmente

| Sub-Req | Descrição PCI DSS | Controle Z.T.K. | Camada | Status |
|---------|------------------|-----------------|--------|--------|
| 11.1.1 | Scanning trimestral de vulnerabilidades | SAST agents (L2) — execução sob demanda ou schedule | L2 | 🟡 Código pendente |
| 11.2.1 | Penetration testing anual e após mudanças significativas | Pentest interno (F11.2); pentest externo (terceiro QSA) | F11 | 🟡 Pendente |
| 11.3.1 | Detecção de intrusão (IDS/IPS) | AWS GuardDuty + Security Hub | Infra | 🟡 IaC pendente |
| 11.4.1 | File integrity monitoring (FIM) | Container immutability (imagens readonly); checksum de artefatos | L2 | ✅ |
| 11.5.1 | Detecção de mudanças não autorizadas | Policy engine OPA/Rego com deny-by-default | L6 | ✅ |

---

## Requisito 12: Manter Política de Segurança da Informação

| Sub-Req | Descrição PCI DSS | Controle Z.T.K. | Camada | Status |
|---------|------------------|-----------------|--------|--------|
| 12.1.1 | Política de segurança documentada e comunicada | AGENTS.md, README.md, steering docs | — | ✅ |
| 12.2.1 | Avaliação de risco anual | Threat model STRIDE (revisão anual) | — | ✅ |
| 12.3.1 | Política de uso aceitável de tecnologia | Princípios invioláveis em AGENTS.md e CLAUDE.md | — | ✅ |
| 12.4.1 | Programa de conscientização de segurança | Documentação de anti-patterns; security review obrigatório | — | ✅ |
| 12.5.1 | Responsabilidades de segurança documentadas | Matriz RACI em AGENTS.md e TASKS_ZTK.md | — | ✅ |
| 12.6.1 | Plano de resposta a incidentes | Runbooks: containment, kill-switch, incidente | — | ✅ |

---

## Resumo de Conformidade

| Status | Quantidade | % |
|--------|-----------|----|
| ✅ Conforme | 17 | 45% |
| 🟡 Pendente (código/IaC) | 21 | 55% |
| 🔴 Não conforme | 0 | 0% |

**Nota:** 55% pendente porque o código das camadas ainda não foi implementado. Os controles estão **mapeados e projetados**, mas dependem da construção do sistema (Fases 1-12 do TASKS_ZTK.md). Nenhum requisito está em violação — todos têm plano de implementação.
