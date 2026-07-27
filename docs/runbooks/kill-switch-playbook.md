# Runbook: Kill Switch de Emergência

> **Versão:** 1.0 | **Autoridade:** SOC | **SLA:** <30 segundos

---

## 1. Visão Geral

O kill switch é o mecanismo de emergência que **desativa todo o pipeline de remediação automática do Z.T.K.** em caso de comportamento anômalo ou incidente de segurança causado pelo próprio sistema.

**Princípio:** kill switch é ação única, irreversível sem aprovação CAB, e gera auditoria completa.

---

## 2. Autoridade

| Papel | Pode Acionar? | Pode Reativar? |
|-------|--------------|----------------|
| SOC Analista Sênior | ✅ Sim | ❌ Não |
| SOC Manager | ✅ Sim | ❌ Não |
| CISO | ✅ Sim | ✅ Sim (com CAB) |
| Engenharia | ❌ Não | ❌ Não |
| Compliance | ❌ Não | ❌ Não |

---

## 3. Gatilhos de Acionamento

### Gatilhos Automáticos (sistema detecta)

| Gatilho | Condição | SLA |
|---------|----------|-----|
| **Falso positivo em massa** | >50 regras de contenção ativas simultaneamente | Imediato |
| **Cascata de rollback** | >10 rollbacks em <5 minutos | Imediato |
| **Custo explosivo** | Bedrock cost >$1000/hora | Imediato |
| **Latência anormal** | Pipeline >10min por finding (normal: <2min) | 5 min |

### Gatilhos Manuais (humano detecta)

| Gatilho | Quem reporta |
|---------|-------------|
| Regra de WAF bloqueando tráfego legítimo | NOC / Suporte |
| Patch quebrou build em produção | Engenharia |
| Comportamento inesperado do LLM | Qualquer agente |
| Ordem do CISO | CISO |

---

## 4. Procedimento de Acionamento

### Via Interface Web (recomendado)

```
1. Acessar: https://ztk.cielo.internal/kill-switch
2. Autenticar com MFA (Cognito + hardware token)
3. Selecionar escopo:
   [ ] Pipeline completo (todas as camadas)
   [ ] Apenas Remediação (Camada 5)
   [ ] Apenas LLM (Camadas 2, 3, 4, 7)
4. Preencher justificativa (obrigatório, min 50 chars)
5. Clicar "CONFIRMAR KILL SWITCH"
6. Confirmar na segunda tela (double confirmation)
7. Sistema exibe: "KILL SWITCH ATIVADO — ID: KS-{timestamp}-{uuid8}"
```

### Via API (emergência)

```bash
curl -X POST https://api.ztk.cielo.internal/v1/kill-switch \
  -H "Authorization: Bearer ${SOC_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "scope": "full",
    "reason": "Mass false positive detection — WAF blocking legitimate traffic on /api/payments",
    "operator": "soc-analyst@cielo.com.br"
  }'
```

---

## 5. O Que Acontece Quando o Kill Switch é Acionado

| Componente | Ação Imediata |
|-----------|---------------|
| **Pipeline de Ingestão** | ✅ Continua (read-only é seguro) |
| **SAST Agents (L2)** | ✅ Continuam (análise não causa efeitos colaterais) |
| **Validação/PoC (L3)** | ✅ Continua em sandbox |
| **Consenso (L4)** | ✅ Continua (só produz scores) |
| **Remediação — Trilha A (patch)** | 🛑 **PARA IMEDIATAMENTE** — não gera nem publica PRs |
| **Remediação — Trilha B (contenção)** | 🛑 **PARA IMEDIATAMENTE** — não aplica novas regras WAF |
| **Regras de contenção ATIVAS** | ⚠️ Permanecem ativas (removê-las pode expor vulnerabilidade) |
| **LLM requests (L7)** | ⚠️ Completam o request atual, não iniciam novos |
| **Interface de Exceções** | ✅ Continua disponível |
| **Auditoria** | ✅ Continua (append-only) |

---

## 6. Pós-Acionamento

### Imediato (<5 min)
- [ ] Post-mortem channel aberto no Slack (#incident-ztk-{date})
- [ ] War room convocada (SOC + Engenharia + CISO)
- [ ] Evidências coletadas: logs, métricas, regras ativas, dashboards

### Curto Prazo (<1 hora)
- [ ] Causa raiz identificada
- [ ] Plano de correção definido
- [ ] CAB convocado para aprovar reativação
- [ ] Comunicação externa preparada (se impacto em cliente)

### Reativação (requer CAB)
- [ ] Causa raiz corrigida e testada
- [ ] Plano de reativação faseada aprovado
- [ ] Reativação por escopo: primeiro ingestão, depois análise, depois remediação
- [ ] Monitoramento intensificado por 24h pós-reativação

---

## 7. Auditoria

Todo acionamento de kill switch gera:

```json
{
  "event_id": "sha256...",
  "event_type": "KILL_SWITCH_ACTIVATED",
  "scope": "full",
  "operator": "soc-analyst@cielo.com.br",
  "reason": "...",
  "timestamp": "2026-07-27T14:30:00Z",
  "active_rules_at_kill": 12,
  "pending_patches_at_kill": 3
}
```

Audit trail é **imutável** e enviado para:
- S3 (append-only, particionado por data)
- Sentinel (SIEM corporativo)
- Compliance archive (retenção 5 anos)

---

## 8. Testes Obrigatórios

- [ ] Teste trimestral de kill switch em staging
- [ ] Tempo de acionamento <30 segundos (medido)
- [ ] Reativação faseada testada (ingestão → análise → remediação)
- [ ] Dupla confirmação funcional (não é possível acionar sem segundo clique)
- [ ] Auditoria gerada corretamente
