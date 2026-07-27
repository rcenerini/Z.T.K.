# Runbook: Resposta a Incidente no Z.T.K.

> **Versão:** 1.0 | **Data:** 2026-07-27 | **Canal:** #incident-ztk-prod

---

## 1. Classificação de Severidade

| Severidade | Definição | Exemplos | SLA de Resposta |
|-----------|-----------|----------|-----------------|
| **SEV1 — Crítico** | Z.T.K. causou impacto em produção (downtime, bloqueio de tráfego, vazamento) | WAF rule bloqueou /api/payments; patch quebrou build em prod | 15 minutos |
| **SEV2 — Alto** | Z.T.K. degradado (funcionalidade parcial, latência elevada) | Bedrock throttling; pipeline >10min por finding | 1 hora |
| **SEV3 — Médio** | Z.T.K. funcional mas com anomalias | Falso positivo em massa sem impacto; métricas anômalas | 4 horas |
| **SEV4 — Baixo** | Cosmético ou melhoria | Dashboard desatualizado; warning em logs | 24 horas |

---

## 2. Fluxo de Resposta

### Fase 1: Detecção & Triagem (0-15 min)

```
ALERTA (CloudWatch / Grafana / Humano)
  │
  ├── 1. Quem detectou? (SOC, NOC, Eng, automático)
  ├── 2. Classificar severidade (SEV1-SEV4)
  ├── 3. Criar canal de incidente (#incident-ztk-{date})
  └── 4. Notificar time de plantão
```

### Fase 2: Containment (15-60 min)

| Cenário | Ação Imediata |
|---------|--------------|
| WAF bloqueando tráfego legítimo | Acionar kill switch (escopo: remediação) |
| Patch quebrou em produção | Reverter PR; rollback do patch |
| Custo Bedrock explosivo | Circuit breaker L7; pausar tier caro |
| Prompt injection detectado | Kill switch LLM (escopo: L2, L3, L4, L7) |
| Vazamento de dados | Kill switch completo + notificar DPO + CISO |

### Fase 3: Investigação (1-4 horas)

```yaml
investigation:
  - coletar_evidencias:
      - logs: CloudWatch Logs Insights (últimas 24h)
      - metrics: Grafana dashboard do período
      - audit: S3 audit trail (finding_id afetados)
      - config: versão do código no momento do incidente
  - identificar_causa_raiz:
      - 5 Whys analysis
      - timeline de eventos
      - finding_id(s) envolvido(s)
  - documentar:
      - post-mortem draft em docs/post-mortem/
```

### Fase 4: Remediação (4-24 horas)

| Causa | Remediação |
|-------|-----------|
| Regra de contenção muito agressiva | Refinar regex do template CWE; dry-run mais longo |
| Patch com bug | Corrigir bug; adicionar teste de regressão |
| Prompt injection bypass | Atualizar regex do L1.03; adicionar payload ao teste |
| Configuração errada | Corrigir config; adicionar validação no CI/CD |

### Fase 5: Recuperação (24-48 horas)

```yaml
recovery:
  - reativar_sistema:
      - ordem: ingestão → análise → scoring → remediação
      - monitoramento intensificado (24h)
  - validar:
      - smoke tests passam
      - métricas normalizadas
      - sem recorrência do incidente
  - comunicar:
      - status final para stakeholders
      - post-mortem publicado
```

---

## 3. Ferramentas

| Ferramenta | Uso |
|-----------|-----|
| **CloudWatch Logs Insights** | Query de logs do período do incidente |
| **Grafana** | Dashboards de métricas (operação, segurança, custo) |
| **S3 Audit Trail** | Evidências de auditoria por finding_id |
| **AWS X-Ray** | Tracing distribuído do pipeline |
| **Slack** | Canal de incidente (#incident-ztk-{date}) |
| **Jira** | Ticket de incidente + tasks de remediação |
| **Git** | Histórico de código; identificar commit suspeito |

---

## 4. Comunicação

### Notificações Obrigatórias

| Severidade | Notificar | Canal | Quando |
|-----------|----------|-------|--------|
| SEV1 | CISO + DPO + CAB | Telefone + Slack | <15 min |
| SEV2 | Tech Lead + SOC Manager | Slack + Email | <1 hora |
| SEV3 | Team Lead | Slack | <4 horas |
| SEV4 | N/A | Ticket Jira | <24 horas |

### Template de Comunicação

```
🚨 INCIDENTE Z.T.K. — SEV{n}

Status: {investigating|contained|resolved}
Data/Hora: {timestamp}
Duração: {duration}

O que aconteceu:
{one-line summary}

Impacto:
- Clientes afetados: {count or "none"}
- Sistemas afetados: {components}
- Dados expostos: {yes/no + details if yes}

Ação tomada:
- {containment action}
- {next steps}

Canal: #incident-ztk-{date}
Responsável: {name}
```

---

## 5. Post-Mortem

### Estrutura do Documento

```markdown
# Post-Mortem: {incident title}

| Campo | Valor |
|-------|-------|
| Data | YYYY-MM-DD |
| Severidade | SEV1-4 |
| Duração | X horas Y minutos |
| Responsável | nome |

## Timeline (UTC)
- 14:30 — Alerta CloudWatch: Bedrock error rate >10%
- 14:32 — SOC reconhece incidente, classifica SEV2
- 14:35 — Canal #incident-ztk-2026-07-27 criado
- ...

## Causa Raiz
...

## Impacto
...

## Ações Corretivas
1. ...
2. ...

## Lições Aprendidas
...
```

---

## 6. Contatos

| Papel | Nome | Slack | Telefone |
|-------|------|-------|----------|
| Tech Lead ZTK | [definir] | @tech-lead-ztk | [definir] |
| SOC Manager | [definir] | @soc-manager | [definir] |
| CISO | [definir] | @ciso | [definir] |
| DPO | [definir] | @dpo | [definir] |
| Infra AWS | [definir] | @infra-aws | [definir] |
