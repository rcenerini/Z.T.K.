# S-SDLC — Secure Software Development Lifecycle

**Projeto:** Z.T.K. (Zero Trust Kill)
**Versao:** 1.0
**Data:** 2026-07-25

## Visao Geral

O Z.T.K. segue S-SDLC com gates de seguranca em cada fase. Nenhuma fase pode ser
pulada ou reduzida sem aprovacao do Security Architect e registro de risco aceito.

## Fases e Gates

### Fase 0: Requirements (EARS + ASVS + Threat Model)

**Entrada:** User story aprovada pelo Product Owner
**Saida:** Especificacao tecnica com security user stories

**Gates obrigatorios:**
- [ ] EARS (Easy Approach to Requirements Syntax) aplicado
- [ ] ASVS (Application Security Verification Standard) nivel 2+ mapeado
- [ ] Security user stories definidas (ex: "Como atacante, nao consigo injetar prompt")
- [ ] Threat model STRIDE concluido para a feature
- [ ] Matriz de risco (impacto x probabilidade) preenchida

**Ferramentas:** OWASP ASVS, Microsoft Threat Modeling Tool, EARS template

### Fase 1: Design (ADR + Contratos + Matriz de Testes)

**Entrada:** Especificacao aprovada
**Saida:** ADR aprovado, contratos Pydantic, matriz de testes

**Gates obrigatorios:**
- [ ] ADR redigido e revisado (minimo 2 aprovadores: arquiteto + security)
- [ ] Contratos de API definidos (Pydantic schemas para input/output)
- [ ] Matriz de testes completa (happy path + casos de falha + fail-closed)
- [ ] Decisoes pendentes (D001-D006) resolvidas ou registradas como risco
- [ ] Infraestrutura necessaria mapeada no Terraform

**Ferramentas:** ADR template, Pydantic, OpenAPI/Swagger

### Fase 2: Code (Implementacao + Unit Tests)

**Entrada:** ADR aprovado
**Saida:** Codigo em branch + testes unitarios + coverage report

**Gates obrigatorios:**
- [ ] Python 3.12+ com type hints obrigatorios
- [ ] Pydantic v2 para todos os schemas
- [ ] Nenhum secret hardcoded (validado por TruffleHog)
- [ ] Nenhuma query concatenada (ORM ou prepared statements)
- [ ] Input validation com whitelist
- [ ] Erros nao expoem stack traces ou dados sensiveis
- [ ] Audit event em toda acao que grava estado
- [ ] Testes unitarios cobrindo matriz definida na Fase 1
- [ ] Cobertura >= 85% (100% para decision_engine)

**Ferramentas:** Ruff, mypy strict, bandit, TruffleHog, pytest

### Fase 3: Build (CI/CD + Container Scan)

**Entrada:** PR aberta
**Saida:** Artefato assinado, SBOM gerado

**Gates obrigatorios:**
- [ ] CI passa (lint, typecheck, tests, SAST, secrets, IaC scan)
- [ ] Container scan (Trivy) sem vulnerabilidades critical/high
- [ ] SBOM gerado (CycloneDX)
- [ ] Imagem assinada (Cosign/Sigstore)
- [ ] OPA/Rego policy tests passam
- [ ] Review de seguranca por revisor humano ou agente de review

**Ferramentas:** GitHub Actions, Trivy, Syft, Cosign, OPA

### Fase 4: Test (Integration + Contract + Security)

**Entrada:** PR aprovada
**Saida:** Testes de integracao, contract, e2e passando

**Gates obrigatorios:**
- [ ] Testes de integracao (com mocks AWS via Moto)
- [ ] Contract tests para APIs externas (Veracode, Orca, etc.)
- [ ] Testes de fail-closed (simulacao de falha de API, timeout, erro)
- [ ] Testes de seguranca (fuzzing leve, injection attempts)
- [ ] Performance tests (se agente de alta frequencia)

**Ferramentas:** pytest, Moto, WireMock, OWASP ZAP (leve)

### Fase 5: Deploy (Terraform + GitOps)

**Entrada:** PR mergeada em main
**Saida:** Deploy em staging, validacao

**Gates obrigatorios:**
- [ ] Terraform plan revisado (nenhum destroy nao intencional)
- [ ] Checkov/tfscan sem findings critical
- [ ] Deploy em staging com shadow mode habilitado
- [ ] Smoke tests em staging
- [ ] Rollback testado (verificar que `terraform destroy` + `terraform apply` funciona)

**Ferramentas:** Terraform, ArgoCD/Flux (se EKS), GitHub Actions

### Fase 6: Operate (Grafana + HITL + Kill Switch)

**Entrada:** Deploy em producao
**Saida:** Monitoramento, incidentes, melhorias

**Gates obrigatorios:**
- [ ] Dashboard Grafana configurado para a camada
- [ ] Alertas CloudWatch para erros, latencia, custo
- [ ] HITL queue integrada (se agente de Camada 4/5/6)
- [ ] Kill switch testado em dry-run (se Camada 5)
- [ ] Runbook de incidente atualizado
- [ ] Retrospectiva de seguranca apos 7 dias de operacao

**Ferramentas:** Grafana, CloudWatch, PagerDuty, Jira Service Management

## Responsaveis por Fase

| Fase | Responsavel Primario | Responsavel de Seguranca |
|---|---|---|
| 0 — Requirements | Product Owner | Security Architect |
| 1 — Design | Security Architect | Security Architect |
| 2 — Code | Engenheiro Backend | Revisor de Codigo (Agente/Humano) |
| 3 — Build | DevSecOps Lead | QA Gatekeeper |
| 4 — Test | QA Gatekeeper | Red Team (se aplicavel) |
| 5 — Deploy | Platform Engineer | Cloud Security Architect |
| 6 — Operate | SRE / SOC | SOC Manager |

## Escalonamento de Excecoes

Se um gate nao puder ser cumprido:
1. Registrar excecao no sistema de excecoes (interface dedicada)
2. Justificativa tecnica obrigatoria
3. Aprovacao de: Engenheiro responsavel + Security Architect
4. Se envolve PCI/LGPD: DPO + CISO
5. Prazo de remediacao definido (nunca indefinido)

## Metricas de Maturidade

| Metrica | Meta | Frequencia |
|---|---|---|
| % de features com threat model | 100% | Por sprint |
| % de PRs passando quality gates | > 95% | Semanal |
| Tempo medio de review de seguranca | < 2h | Semanal |
| Bugs de seguranca em producao | 0 (P0/P1) | Mensal |
| Cobertura de testes | >= 85% | Por build |

---

*Documento mantido pelo agente de seguranca. Revisao mensal obrigatoria.*
