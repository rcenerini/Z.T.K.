# Threat Model STRIDE — Sistema Z.T.K.

> **Versão:** 1.0 | **Data:** 2026-07-27 | **Revisão:** Anual
> **Metodologia:** STRIDE por elemento do DFD (Data Flow Diagram)
> **Escopo:** 8 camadas + infraestrutura AWS + integrações externas

---


![Security](https://img.shields.io/badge/type-SSDL-ff6b35)
![Review](https://img.shields.io/badge/review-anual-00d4ff)


## 1. Diagrama de Fluxo de Dados (DFD) — Resumo Executivo

```
[Git Repo] → L1(Ingestão) → L2(SAST) → L3(PoC) → L4(Consenso) → L5(Remediação) → [PR/WAF]
                                  ↑            ↑
                            L7(LLM Ensemble)   |
                            (vLLM + Bedrock)    |
                                  ↑            ↑
                            L6(Governança) ←───┘
                            (OPA + Auditoria + HITL)

[Tenable] → L1 (via connector)
[ServiceNow] ← L6 (HITL tickets)
[F5/Akamai] ← L5 (WAF rules)
[Sentinel] ← L6 (audit events)
```

---

## 2. Matriz de Ameaças por Elemento

### Elemento 1: Repositório de Código Fonte (Git)

| ID | Ameaça | STRIDE | Severidade | Mitigação |
|----|--------|--------|-----------|-----------|
| T01 | Código malicioso injetado no repo | **Tampering** | CRITICAL | L1.03 prompt-injection guard; L3 executa em sandbox isolado |
| T02 | Acesso não autorizado ao repo | **Information Disclosure** | HIGH | Git read-only token, mínimo escopo (apenas repo alvo) |
| T03 | Repo com malware ofusca scan | **Tampering** | HIGH | L1 normaliza antes de classificar; sandbox na L3 |

### Elemento 2: Camada 1 — Ingestão & Triagem

| ID | Ameaça | STRIDE | Severidade | Mitigação |
|----|--------|--------|-----------|-----------|
| T04 | Prompt injection via código-fonte | **Tampering** | CRITICAL | L1.03 regex guard; envelopamento; system prompt robusto |
| T05 | Bypass do classificador de linguagem | **Tampering** | MEDIUM | Classificador determinístico (go-enry), sem LLM |
| T06 | Negação de serviço (arquivo gigante) | **Denial of Service** | MEDIUM | Limite de tamanho (10MB); timeout de 30s |
| T07 | Enumeração de tenants | **Information Disclosure** | HIGH | `tenant_id` validado contra IAM; logs não expõem cross-tenant |

### Elemento 3: Camada 2 — Especialistas SAST

| ID | Ameaça | STRIDE | Severidade | Mitigação |
|----|--------|--------|-----------|-----------|
| T08 | SAST tool comprometida (imagem maliciosa) | **Tampering** | HIGH | Imagens assinadas (Docker Content Trust); checksum verificado |
| T09 | SAST tool com 0-day explorável | **Elevation of Privilege** | HIGH | Container não-root; `readOnlyRootFilesystem`; sem rede |
| T10 | Vazamento de código-fonte via logs | **Information Disclosure** | HIGH | Logs sanitizados (PAN, PII redacted); S3 SSE-KMS |
| T11 | Correlator LLM alucina severidade | **Tampering** | MEDIUM | L4 Consensus debate + piso não-negociável; HITL para divergência |

### Elemento 4: Camada 3 — Validação & PoC

| ID | Ameaça | STRIDE | Severidade | Mitigação |
|----|--------|--------|-----------|-----------|
| T12 | Escape de sandbox (exploit acessa host) | **Elevation of Privilege** | CRITICAL | Firecracker KVM; sem rede; sem host fs; seccomp strict |
| T13 | Exploit exfiltra dados via side-channel | **Information Disclosure** | HIGH | Sem shared resources; microVM descartada após uso |
| T14 | Fuzzing sem aprovação HITL | **Repudiation** | HIGH | L3.13 bloqueado sem aprovação explícita registrada |
| T15 | Exploit consome recursos (fork bomb) | **Denial of Service** | MEDIUM | CPU/memory limits; timeout 30s; cgroups |

### Elemento 5: Camada 4 — Consenso & Debate

| ID | Ameaça | STRIDE | Severidade | Mitigação |
|----|--------|--------|-----------|-----------|
| T16 | LLM enviesado reduz severidade (Defender) | **Tampering** | HIGH | Piso não-negociável; Judge com restrição de piso; HITL para divergência |
| T17 | Prosecutor/Defender colidem (mesmo modelo) | **Spoofing** | MEDIUM | Modelos diferentes por design; seed aleatória diferente |
| T18 | Score determinístico manipulado | **Tampering** | MEDIUM | Tabela de pesos versionada no Git; imutável sem PR |

### Elemento 6: Camada 5 — Remediação

| ID | Ameaça | STRIDE | Severidade | Mitigação |
|----|--------|--------|-----------|-----------|
| T19 | Patch malicioso injetado | **Tampering** | CRITICAL | PR humana obrigatória para P0/P1; sandbox valida patch antes do PR |
| T20 | WAF rule bloqueia tráfego legítimo | **Denial of Service** | CRITICAL | Dry-run obrigatório; rollback automático; kill switch SOC |
| T21 | Patch quebra build em produção | **Denial of Service** | HIGH | Sandbox valida build+testes antes do PR |
| T22 | Contenção sem TTL (permanente) | **Repudiation** | HIGH | TTL obrigatório; expiração automática; auditoria de renovação |

### Elemento 7: Camada 6 — Governança

| ID | Ameaça | STRIDE | Severidade | Mitigação |
|----|--------|--------|-----------|-----------|
| T23 | Bypass de four-eyes (mesma pessoa aprova 2x) | **Spoofing** | HIGH | Validação de identidade (Cognito); mesmo `sub` bloqueado |
| T24 | Exceção sem prazo (permanente) | **Repudiation** | HIGH | TTL obrigatório; reversão automática; auditoria |
| T25 | Auditoria adulterada | **Tampering** | CRITICAL | Append-only S3; hash chain (previous_event_id); forward para Sentinel |
| T26 | Policy engine bypass | **Tampering** | HIGH | OPA deny-by-default; políticas versionadas em Git; `opa test` em CI |

### Elemento 8: Camada 7 — Model Ensemble

| ID | Ameaça | STRIDE | Severidade | Mitigação |
|----|--------|--------|-----------|-----------|
| T27 | Dados PCI enviados para Bedrock | **Information Disclosure** | CRITICAL | Router: `data_scope=PCI` → `provider=vllm_local` OBRIGATÓRIO |
| T28 | vLLM local comprometido | **Elevation of Privilege** | HIGH | GPU dedicada; sem rede externa; sem storage persistente |
| T29 | Custo explosivo (Bedrock sem limite) | **Denial of Service** | HIGH | Circuit breaker: 80% alerta, 100% pausa |
| T30 | Cache poisoning (respostas maliciosas cacheadas) | **Tampering** | MEDIUM | Cache por `content_hash`; TTL curto; invalidação seletiva |

### Elemento 9: Camada 8 — Escala

| ID | Ameaça | STRIDE | Severidade | Mitigação |
|----|--------|--------|-----------|-----------|
| T31 | Shadow mode bypass (agente promovido sem validação) | **Elevation of Privilege** | HIGH | Shadow 30 dias obrigatório; métricas quantitativas mínimas |
| T32 | Cross-tenant data leak | **Information Disclosure** | CRITICAL | `tenant_id` em todos os schemas; DynamoDB partition key = `tenant_id` |
| T33 | Agente malicioso onboarded | **Tampering** | HIGH | Agent onboarding gate; policy registration; security review |

### Elemento 10: Infraestrutura AWS

| ID | Ameaça | STRIDE | Severidade | Mitigação |
|----|--------|--------|-----------|-----------|
| T34 | IAM role excessivamente permissiva | **Elevation of Privilege** | CRITICAL | Least privilege; revisão trimestral; IAM Access Analyzer |
| T35 | Dados em repouso não criptografados | **Information Disclosure** | CRITICAL | SSE-KMS em DynamoDB, S3, SQS; KMS rotation automática |
| T36 | Acesso público a recursos internos | **Information Disclosure** | CRITICAL | VPC privada; sem internet gateway no CDE; VPC endpoints |
| T37 | Credenciais AWS expostas em código | **Information Disclosure** | CRITICAL | Nunca hardcode; IAM roles para EC2/Lambda; Secrets Manager |

---

## 3. Resumo por Severidade

| Severidade | Quantidade | IDs |
|-----------|-----------|-----|
| **CRITICAL** | 12 | T01, T04, T12, T19, T20, T25, T27, T32, T34-T37 |
| **HIGH** | 18 | T02, T03, T07-T10, T13, T14, T16, T22-T24, T26, T28, T29, T31, T33 |
| **MEDIUM** | 7 | T05, T06, T11, T15, T17, T18, T30 |
| **LOW** | 0 | — |

---

## 4. Riscos Aceitos (com justificativa)

| Risco | Justificativa | Aprovado por |
|-------|--------------|-------------|
| R01 — Latência da L3 (PoC em sandbox) pode exceder 30s | Firecracker cold start ocasional. Mitigação: pool de microVMs pré-aquecidas | Arquitetura |
| R02 — Cobertura inicial de CWE templates limitada (5 CWEs) | Começar com top 5, expandir conforme maturidade | Produto |

---

## 5. Revisão e Atualização

- **Revisão programada**: anual ou após incidente de segurança
- **Atualização**: novo elemento no DFD → novo threat model em 5 dias úteis
- **Responsável**: ZTK Strategist Agent + revisão humana (CISO)
