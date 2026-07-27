# Runbook: Contenção Runtime (Trilha B)

> **Versão:** 1.0 | **Camada:** 5 (Remediação) | **SLA:** 5 minutos

---


![Runbook](https://img.shields.io/badge/type-Runbook-ff6b35)
![SLA](https://img.shields.io/badge/SLA-documentado-00ff88)


## 1. Visão Geral

Este runbook descreve o procedimento declarativo para contenção runtime de vulnerabilidades confirmadas que não podem ser corrigidas imediatamente (patch indisponível, janela de manutenção, dependência externa).

**Princípio:** contenção é temporária. Toda regra tem TTL. Nenhuma regra de contenção é permanente.

---

## 2. Gatilhos de Ativação

| Gatilho | Condição | Ação |
|---------|----------|------|
| **G1 — Vulnerabilidade Confirmada** | Camada 4 emite `DecisionTier = P0 \| P1 \| ACT_3` | Iniciar contenção imediata |
| **G2 — Patch Bloqueado** | Camada 5 Trilha A falha (build/testes quebram) | Iniciar contenção como fallback |
| **G3 — Zero-Day** | CVE com CVSS >= 9.0 sem patch disponível | Iniciar contenção + alerta CISO |
| **G4 — SLA Estourado** | TTL da contenção expirou sem merge do patch | Escalação progressiva |

---

## 3. Procedimento

### Passo 1: Selecionar Template (30s)

```yaml
input:
  cwe_ids: ["CWE-89"]
  severity: "P0"
  target_scope: "/api/auth/login"

action:
  - query: "SELECT template FROM containment_templates WHERE cwe_id IN ('CWE-89') AND severity IN ('P0','P1')"
  - if: result.empty?
    then: fallback_to_generic_injection_template()
```

### Passo 2: Dry-Run (2min)

```yaml
action:
  - deploy_rule(mode="dry_run", duration_minutes=5)
  - monitor:
      metric: "false_positive_rate"
      threshold: 0.1%  # >0.1% → abort
      window: 5min
  - evaluate:
      - if: false_positive_rate > 0.1%
        then: abort_and_rollback()
      - if: false_positive_rate <= 0.1%
        then: proceed_to_activate()
```

### Passo 3: Ativar (30s)

```yaml
action:
  - deploy_rule(mode="active", ttl_hours=72)
  - log_audit_event(stage="REMEDIATION", action="CONTAINED")
  - create_jira_ticket(
      type="Containment",
      ttl=72h,
      assignee="engineering-team"
    )
```

### Passo 4: Monitorar (contínuo)

```yaml
monitoring:
  - alert_on_trigger: true
  - alert_channel: "soc-slack"
  - dashboard: "grafana/containment"
  - metrics:
      - hits_per_minute
      - false_positive_rate
      - ttl_remaining_hours
```

### Passo 5: Resolver (antes do TTL expirar)

```yaml
resolution_paths:
  - path_a: "Patch merged → remover regra de contenção"
  - path_b: "TTL expirado sem patch → renovar contenção (requer aprovação)"
  - path_c: "Falso positivo confirmado → remover regra imediatamente"
```

---

## 4. Escalação Progressiva (TTL Expirado)

| Nível | Quando | Ação | Notificar |
|-------|--------|------|-----------|
| 1 | TTL < 24h restantes | Alerta automático | Engineering Owner |
| 2 | TTL expirado, sem renovação | Bloqueio de tráfego? | Engineering Manager |
| 3 | 2º ciclo TTL expirado | Escalação formal | CISO |
| 4 | 3º ciclo TTL expirado | Emergência | C-Level + CAB |

---

## 5. Rollback

```yaml
rollback_triggers:
  - false_positive_rate > 0.1%
  - customer_impact_reported
  - sla_breach_detected
  - manual_override(authority="SOC")

rollback_procedure:
  - step_1: "remove_rule(rule_id)"
  - step_2: "verify_removal()"
  - step_3: "log_audit_event(action='ROLLBACK')"
  - step_4: "notify_soc_channel()"
  - rto: "< 1 minuto"
```

---

## 6. Checklist de Aprovação CAB

- [ ] Template selecionado é apropriado para o CWE?
- [ ] Dry-run passou com <0.1% falso positivo?
- [ ] TTL é proporcional à severidade? (P0=24h, P1=72h, P2=168h)
- [ ] Rollback automatizado está configurado?
- [ ] Time de engenharia está ciente do prazo do patch?
- [ ] Kill switch está disponível para esta regra?

---

## 7. SLA por Severidade

| Severidade | TTL Padrão | Tempo para Ativar | Renovação Requer |
|-----------|-----------|-------------------|------------------|
| P0 | 24 horas | <5 minutos | CAB approval |
| P1 | 72 horas | <15 minutos | Tech Lead approval |
| P2 | 168 horas (7 dias) | <1 hora | Team Lead approval |
| P3 | 720 horas (30 dias) | <4 horas | Auto-renew (max 2x) |
