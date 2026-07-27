# Runbook: Exceção Four-Eyes

> **Versão:** 1.0 | **Camada:** 6 (Governança) | **SLA:** 24 horas

---

## 1. Visão Geral

O mecanismo de exceção four-eyes permite que um finding com severidade elevada seja temporariamente reduzido ou aceito como risco residual, mediante **aprovação de duas pessoas diferentes** com autoridade adequada.

**Princípio:** exceção é temporária. Toda exceção tem prazo de vigência e reversão automática.

---

## 2. Fluxo Completo

```
1. SOLICITAÇÃO  → 2. REVISÃO PAR → 3. APROVAÇÃO DUPLA → 4. APLICAÇÃO → 5. AUDITORIA → 6. EXPIRAÇÃO
     (owner)        (tech lead)       (gerente + super)    (automática)   (imutável)    (reversão)
```

---

## 3. Solicitação de Exceção

### Quem pode solicitar
- Engineering Owner do sistema afetado
- Tech Lead com conhecimento do código

### Formulário

```yaml
exception_request:
  finding_id: "uuid"
  requested_by: "email@cielo.com.br"
  reason_category: "FALSE_POSITIVE | RISK_ACCEPTED | COMPENSATING_CONTROL | DEFERRED_FIX"
  justification: "Detalhamento técnico do motivo (min 100 chars)"
  current_severity: "P1"
  requested_severity: "P3"
  ttl_days: 90
  compensating_control: "WAF rule ID WAF-12345 bloqueia exploração conhecida"
  risk_acceptance_owner: "Gerente Executivo responsável"
```

### Categorias de Exceção

| Categoria | Descrição | TTL Máximo |
|-----------|-----------|------------|
| FALSE_POSITIVE | Ferramenta reportou, mas análise humana confirma que não é vulnerável | 180 dias |
| RISK_ACCEPTED | Risco conhecido, aceito pelo negócio | 365 dias |
| COMPENSATING_CONTROL | Existe controle compensatório (WAF, firewall, segregação) | 90 dias |
| DEFERRED_FIX | Correção planejada mas depende de terceiros | 90 dias |

---

## 4. Aprovação Four-Eyes

### Regra
- **Duas pessoas diferentes** — mesma pessoa não pode aprovar duas vezes
- **Papéis requeridos**:
  - Aprovador 1: Gerente Executivo da área dona do sistema
  - Aprovador 2: Superintendente de Segurança ou CISO
- **Ordem não importa** — ambos precisam aprovar, em qualquer ordem
- **Rejeição por qualquer um** → exceção arquivada, finding volta à severidade original

### Validações Automáticas

```python
validations:
  - aprovador_1 != aprovador_2                   # Pessoas diferentes
  - aprovador_1.role in ["gerente_executivo"]    # Papel correto
  - aprovador_2.role in ["superintendente", "ciso"]
  - ttl_days <= MAX_TTL[category]                # TTL dentro do limite
  - finding.severity not in ["P0"]               # P0 NUNCA tem exceção
```

---

## 5. Aplicação

- Exceção aprovada → severidade do finding é temporariamente reduzida
- Finding volta ao pipeline com nova severidade
- `AuditEvent` registra: quem solicitou, quem aprovou, prazo, justificativa

---

## 6. Expiração e Reversão

| Evento | Ação Automática |
|--------|-----------------|
| TTL expirado | Severidade volta ao valor original |
| TTL expirado | Finding re-entra no pipeline de decisão |
| TTL expirado | Notificação para solicitante e aprovadores |
| Patch aplicado antes do TTL | Exceção pode ser encerrada manualmente |

### Renovação
- Solicitação de renovação segue o mesmo fluxo (nova four-eyes)
- Máximo 2 renovações por finding
- Após 2 renovações, finding é escalado para CISO

---

## 7. Auditoria

```json
{
  "event_type": "EXCEPTION_APPROVED",
  "finding_id": "uuid",
  "requested_by": "eng-owner@cielo.com.br",
  "approved_by": ["gerente@cielo.com.br", "super-seg@cielo.com.br"],
  "category": "COMPENSATING_CONTROL",
  "original_severity": "P1",
  "exception_severity": "P3",
  "ttl_days": 90,
  "expires_at": "2026-10-25T00:00:00Z",
  "justification": "..."
}
```

---

## 8. Dashboard de Exceções

Métricas disponíveis no Grafana:
- Exceções ativas por severidade
- Exceções próximas do vencimento (<7 dias)
- Tempo médio de aprovação
- Top 5 sistemas com mais exceções
- Exceções expiradas sem renovação

---

## 9. SLA

| Etapa | SLA |
|-------|-----|
| Solicitação → Primeira aprovação | 24 horas |
| Solicitação → Segunda aprovação | 48 horas |
| Aprovação → Aplicação | Automático (<1 min) |
| Expiração → Reversão | Automático (<1 min) |
| Renovação | Mesmo SLA de nova solicitação |
