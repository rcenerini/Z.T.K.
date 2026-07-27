# ADR-002: Roteamento de Modelos LLM — vLLM Local vs Bedrock

**Status:** Proposto (aguardando decisao humana D002 e D005)
**Data:** 2026-07-25
**Autor:** Agente Engenheiro IA
**Stakeholders:** CISO, DPO, Engenheiro IA, Cloud Architect

## Contexto

O Z.T.K. usa LLMs em 4 cenarios:
1. **Interpretacao de SAST** (volume alto, respostas curtas)
2. **Debate adversarial** (reasoning profundo, saida longa)
3. **Geracao de patch** (codigo, precisao critica)
4. **Copiloto de excecoes** (interface web, interativo)

Constraints regulatórios:
- **Dados PCI/CHD/PAN nunca podem sair da VPC da organizacao**
- **Auditoria PCI DSS req. 10 exige logging de toda decisao**

## Opcoes Consideradas

### Opcao A: Bedrock para TUDO (nao-PCI + PCI)

**Pros:**
- Simplicidade operacional (uma API)
- Elasticidade perfeita
- Modelos frontier (Claude Opus)

**Contras:**
- **VIOLA PCI:** Dados PCI/CHD em API comercial, mesmo com BAA
- Custo imprevisivel em volume
- Latencia variavel

**Status:** REJEITADA por compliance

### Opcao B: vLLM Local para TUDO

**Pros:**
- Soberania total de dados
- Latencia previsivel
- Custo fixo (infra GPU)

**Contras:**
- Capacidade limitada por hardware
- Manutencao de modelo (updates, patches)
- GPU ociosa em horarios de baixo uso
- Nao acessa frontier models (Claude Opus)

**Custo estimado:** $800-1500/mes (g5.xlarge spot)

### Opcao C: Hibrido — vLLM Local (PCI) + Bedrock (nao-PCI)

**Pros:**
- PCI compliance: dados sensiveis nunca saem
- Eficiencia de custo: volume alto em local, picos em Bedrock
- Acesso a frontier models para reasoning complexo
- Elasticidade onde nao ha constraint regulatório

**Contras:**
- Duas plataformas para operar
- Roteamento complexo (Camada 7)
- Monitoramento de custo dual

**Custo estimado:** $400-1000/mes (mix)

## Modelos Especificos

### Local (PCI)
| Modelo | Parametros | VRAM | Uso |
|---|---|---|---|
| Llama 3.3 70B | 70B | ~40GB | Patch generation, debate |
| Qwen 2.5 72B | 72B | ~45GB | Codigo, interpretacao SAST |

**Nota:** g5.xlarge (24GB VRAM) nao cabe 70B direto. Requer:
- Quantizacao 4-bit (AWQ/GPTQ) para 70B
- OU instancia maior (g5.12xlarge — 4x GPU)

### Bedrock (nao-PCI)
| Modelo | Uso | Custo estimado |
|---|---|---|
| Claude Haiku | Triagem, logs, classificacao | $0.25 / 1M tokens |
| Claude Sonnet | Desenvolvimento, patch, IaC | $3 / 1M tokens |
| Claude Opus | Debate, ADR, scoring complexo | $15 / 1M tokens |

## Recomendacao do Agente

**Opcao C (Hibrido)** com **Llama 3.3 70B AWQ** em g5.xlarge Spot para local, e **Bedrock Claude Sonnet/Haiku** para nao-PCI.

Justificativa:
1. **Compliance:** vLLM local garante que PAN/CHD nunca saem da VPC
2. **Custo:** Spot reduz ~70%; Haiku eh 10x mais barato que Sonnet para volume
3. **Capacidade:** AWQ 4-bit permite rodar 70B em 24GB VRAM
4. **Elasticidade:** Bedrock absorve picos sem provisionar GPU ociosa

## Decisoes Pendentes

**D002:** Aprovamos Llama 3.3 70B AWQ como modelo local PCI?
Alternativa: Qwen 2.5 72B AWQ (melhor em codigo, mas menor comunidade)

**D005:** Aprovamos Bedrock Claude Sonnet para debate (nao-PCI)?
Alternativa: DeepSeek API (mais barato, mas data residency questionavel)

## Consequencias

- **Positivas:** Compliance garantido, custo otimizado
- **Negativas:** Complexidade de roteamento (mitigada por Camada 7)
- **Riscos:** vLLM local precisa de health check e auto-recovery (spot interruption)

---

*Este ADR foi gerado pelo agente engenheiro IA. Aguarda aprovacao humana.*
