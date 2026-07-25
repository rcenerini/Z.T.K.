## Descrição

<!-- Descreva o que esta PR implementa em uma frase -->

## Tipo de Mudanca

- [ ] Feature (nova camada/agente)
- [ ] Bugfix
- [ ] Refatoracao de seguranca
- [ ] Infraestrutura (Terraform/IaC)
- [ ] Documentacao (ADR, runbook)
- [ ] Dependencia de terceiro (atualizacao de ferramenta)

## Checklist de Seguranca (obrigatorio)

- [ ] Nenhum secret/credencial hardcoded
- [ ] Input validation implementada (whitelist)
- [ ] SQL/Command injection prevenido
- [ ] Erros nao expoem dados sensiveis (stack traces, schema)
- [ ] Fail-closed implementado (comportamento conservador em erro)
- [ ] Audit event emitido para toda decisao/acao
- [ ] Idempotencia verificada em gravacoes externas
- [ ] Testes cobrem cenarios de falha (fail-closed)
- [ ] mypy strict passa sem erros
- [ ] bandit passa sem issues high/critical

## Checklist de Compliance

- [ ] Nao afeta escopo PCI (ou afeta: justificado no ADR)
- [ ] Nao expoe CHD/PAN em logs ou prompts
- [ ] Retencao de audit log alinhada a PCI DSS req. 10
- [ ] Shadow mode disponivel (se nova camada/agente)

## Testes

- [ ] Testes unitarios (`pytest`)
- [ ] Testes de integracao
- [ ] Contract tests (se conector/API externa)
- [ ] Testes de fail-closed (simulacao de erro)
- [ ] Cobertura de codigo >= 85%

## Camada Afetada (se aplicavel)

- [ ] Layer 1 — Entrada & Triagem
- [ ] Layer 2 — Especialistas de Seguranca
- [ ] Layer 3 — Validacao
- [ ] Layer 4 — Consenso/Debate
- [ ] Layer 5 — Remediacao
- [ ] Layer 6 — Governanca
- [ ] Layer 7 — Model Ensemble
- [ ] Layer 8 — Escala
- [ ] Shared / Cross-layer

## ADR Relacionado

- ADR-XXX: (link ou referencia)

## Mudancas de Infraestrutura

- [ ] Terraform plan anexado/revisado
- [ ] OPA/Rego test passou (`opa test`)
- [ ] Checkov/tfscan sem findings critical

## Breaking Changes

- [ ] Nenhuma
- [ ] Sim (descreva abaixo e justifique)

## Notas para Revisor

<!-- Informacoes adicionais para o revisor humano -->

## Screenshots / Evidencias

<!-- Se interface de excecoes ou dashboard Grafana -->
