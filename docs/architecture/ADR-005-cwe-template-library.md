# ADR-005: Biblioteca de Templates de Contenção por CWE

| Campo | Valor |
|-------|-------|
| **Status** | Proposto |
| **Data** | 2026-07-27 |
| **Autor** | ZTK Strategist Agent |
| **Stakeholders** | Arquitetura, Segurança, Operações |

---

## Contexto

A Camada 5 (Remediação), Trilha B, aplica regras de contenção runtime (WAF, Firewall, IAM) quando uma vulnerabilidade confirmada não pode ser corrigida imediatamente. Cada tipo de vulnerabilidade (CWE) exige um padrão de contenção diferente. Sem templates padronizados:

1. Cada regra é escrita do zero — inconsistente, propensa a erros
2. Regras mal configuradas podem bloquear tráfego legítimo (falso positivo de contenção)
3. Auditoria e revisão de segurança são difíceis sem formato padronizado
4. SLA de contenção (minutos) não é atingível com criação manual

## Decisão

Criaremos uma **biblioteca versionada de templates de contenção por CWE**, em formato YAML declarativo.

### Formato do Template

```yaml
template_id: "CWE-89-WAF-001"
version: "1.0.0"
cwe_ids: ["CWE-89"]
title: "SQL Injection — WAF Rule Template"
description: "Bloqueia padrões comuns de SQL injection em parâmetros HTTP"
severity_applicable: ["P0", "P1"]

target:
  type: WAF_RULE
  provider: "f5_bigip"  # f5_bigip | akamai | azure_waf | aws_waf
  default_action: BLOCK

pattern:
  - name: "sqli_union_select"
    regex: "(?i)(\\bunion\\b.+\\bselect\\b)"
    locations: ["ARGS", "HEADERS", "COOKIES"]
  - name: "sqli_or_1_equals_1"
    regex: "(?i)(\\bor\\b\\s+['\"]?1['\"]?\\s*=\\s*['\"]?1['\"]?)"
    locations: ["ARGS"]
  - name: "sqli_semicolon_drop"
    regex: "(?i);\\s*(\\bdrop\\b|\\bdelete\\b|\\btruncate\\b)"
    locations: ["ARGS", "BODY"]

ttl:
  default_hours: 72
  max_hours: 168
  renewal_requires_approval: true

dry_run:
  required: true
  validation_period_minutes: 5
  rollback_trigger_percent: 0.1  # 0.1% false positive → rollback

rollback:
  procedure: "remove_rule"
  automated: true
  verification: "replay_last_1000_requests"

audit:
  log_level: "INFO"
  alert_on_trigger: true
  alert_channel: "soc-slack"
```

### Versionamento

- SemVer (MAJOR.MINOR.PATCH) para cada template
- MAJOR: mudança de comportamento (ex: adicionar/remover padrão de regex)
- MINOR: novo parâmetro ou provider suportado
- PATCH: correção de regex, ajuste de threshold

### Aprovação

- Templates novos: revisão por `@ztk-reviewer` + aprovação CAB
- Updates MINOR/PATCH: revisão por `@ztk-reviewer`, deploy automático
- Updates MAJOR: mesmo fluxo de template novo

## Consequências

### Positivas
- Consistência: mesma vulnerabilidade = mesma contenção, sempre
- Velocidade: SLA de contenção <5 minutos (template pronto, só preencher target)
- Auditabilidade: template_id + version no AuditEvent
- Segurança: cada template passa por security review antes de ser usado

### Negativas
- Cobertura inicial limitada — começar com top 25 CWE, expandir gradualmente
- Templates muito genéricos podem causar falsos positivos
- Manutenção contínua — provedores WAF atualizam APIs

### Riscos Residuais
- **Template desatualizado**: regex não cobre nova variante de ataque
  - Mitigação: revisão trimestral de todos os templates ativos
- **Falso positivo em escala**: template muito agressivo bloqueia tráfego legítimo
  - Mitigação: dry-run obrigatório + rollback automático

## Roadmap de Cobertura

| Fase | CWEs | Quantidade |
|------|------|-----------|
| Fase 1 (MVP) | CWE-89, CWE-79, CWE-78, CWE-502, CWE-918 | 5 |
| Fase 2 | + CWE-352, CWE-287, CWE-22, CWE-200, CWE-434 | 10 |
| Fase 3 | + CWE-611, CWE-776, CWE-400, CWE-862, CWE-863 | 15 |
| Completo | Top 25 CWE + PCI-specific | 25+ |

## Validação

- [ ] 5 templates iniciais testados com dry-run em staging
- [ ] Rollback automático testado (induzir 0.2% falso positivo → rollback em <1min)
- [ ] Template versionado no Git, deploy via CI/CD
- [ ] Auditoria: todo apply registra template_id + version
