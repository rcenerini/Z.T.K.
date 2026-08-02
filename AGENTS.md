# AGENTS.md — Z.T.K. (Zero Trust Kill)

![Version](https://img.shields.io/badge/version-1.1-00d4ff)
![Agents](https://img.shields.io/badge/agents-12-ff6b35)
![DeepSeek](https://img.shields.io/badge/LLM-DeepSeek_v4--pro-7b42bc)
![Status](https://img.shields.io/badge/status-COMPLETO-00ff88)

> **Versão:** 1.1 | **Atualização:** 2026-07-27

---

## O que e este projeto

Z.T.K. (Zero Trust Kill) — sistema multiagente determinístico de análise e
autocorreção de segurança de código para ambiente de adquirência/PCI DSS.

**Merge MVP1 + MVP2:**
- **MVP1** (SAGA-SAGV_V2): pipeline de priorizacao SSVC — 37/42 tarefas concluidas
- **MVP2** (este repo): M4 Copiloto LLM para tier ATTEND — em desenvolvimento

## Ordem de Trabalho

1. Nunca implemente uma tarefa fora da ordem definida em `TASKS_ZTK.md`
2. Antes de gerar codigo, verifique padroes existentes no projeto
3. Use @explore para mapear a codebase antes de qualquer modificacao
4. Prefira editar arquivos existentes a criar novos
5. Nao crie documentacao (.md) a menos que explicitamente solicitado

## Stack Tecnologica

- Python 3.12+ com type hints obrigatorios (mypy --strict)
- Pydantic v2 para schemas e validacao
- AWS: Lambda, ECS Fargate, Bedrock, DynamoDB, S3, SQS, EventBridge
- Terraform 1.7+ para IaC
- pytest com cobertura minima 85%
- structlog para logging JSON estruturado

## Alocacao de modelos LLM por papel

| Papel | Modelo | Justificativa |
|---|---|---|
| **Executor principal** (build/coding) | `deepseek-v4-pro` | Coding, testes, refactor |
| **Orquestrador** (squad-orchestrator) | `deepseek-v4-pro` | Coordenacao de squads |
| **QA Engineer** (qa-engineer) | `qwen3.6-plus` | Execucao de testes |
| **Security Reviewer** | `deepseek-v4-pro` | Auditoria de seguranca |
| **Git** (commits) | `deepseek-v4-flash` | Operacoes de versionamento |
| **Documentacao** | `deepseek-v4-flash` | Geracao de documentacao |

## Workflow da Squad Agentica

Toda sprint segue o pipeline na seguinte ordem:

1. **@explore** — mapeia codebase antes de qualquer modificacao (sempre primeiro)
2. **Implementacao de codigo** — agente executor principal
3. **@security-reviewer** — auditoria de seguranca contra OWASP, credenciais, IAM, crypto
4. **@qa-engineer** — quality gates: testes, lint, typecheck, regressao
5. **@git** — commits atomicos em Conventional Commits, apos validacao

## Regras Criticas (NUNCA VIOLAR)

1. **NUNCA hardcode credenciais** — API keys, passwords, tokens, secrets
2. **NUNCA use verify=False** ou desabilite SSL/TLS
3. **NUNCA use eval() ou exec()** com input nao sanitizado
4. **NUNCA concatene strings em queries SQL** — use prepared statements ou ORM
5. **NUNCA use algoritmos criptograficos obsoletos** (MD5, SHA-1, DES, 3DES, RC4)
6. **NUNCA exponha stack traces** ou informacoes internas em mensagens de erro
7. **SEMPRE valide inputs com whitelist** (nunca blacklist)
8. **SEMPRE aplique least privilege** — verifique autorizacao em TODAS as operacoes sensiveis
9. **SEMPRE use TLS 1.2+** para dados em transito, **AES-256** para dados em repouso
10. **SEMPRE sanitize outputs** para prevenir XSS

## Pipeline de Qualidade (ANTES de cada commit)

```powershell
# 1. Testes
python -m pytest mvp2/copilot/tests/test_copilot.py -v

# 2. Type check
python -m mypy mvp2/copilot/src/copilot/ --strict

# 3. Lint
python -m ruff check mvp2/copilot/

# 4. Secret scan (SEMPRE)
python scripts/secret_scan.py        # se existir
# ou manualmente:
grep -r "verify=False" --include="*.py" mvp2/
grep -r "api_key\s*=\s*['\"]" --include="*.py" mvp2/
grep -r "password\s*=\s*['\"]" --include="*.py" mvp2/
grep -r "token\s*=\s*['\"]" --include="*.py" mvp2/
```

## Conventional Commits

```
feat(copilot): descricao
fix(copilot): descricao
test(copilot): descricao
docs: descricao
chore: descricao
```

## Estrutura do Repositorio

```
ZTK/
├── mvp2/                    ← MVP2: Modulo Copiloto LLM
│   ├── copilot/
│   │   ├── src/copilot/     ← Codigo-fonte do copiloto
│   │   ├── tests/           ← Testes unitarios
│   │   └── data/            ← RAG index + prompt schema (stubs JSON)
│   └── shared/              ← Schemas compartilhados (futuro)
├── src/                     ← Codigo-fonte das 8 camadas (em construcao)
├── infra/terraform/         ← IaC (modulos provisionados)
├── docs/                    ← ADRs, runbooks, S-SDLC
├── .opencode/               ← Configuracao do OpenCode (agentes, steering)
├── opencode.json            ← Configuracao nativa do OpenCode
├── TASKS_ZTK.md             ← Backlog estruturado
├── AGENTS.md                ← Voce esta aqui
└── README.md                ← Visao geral do projeto
```

## AI Handoff — Estado do projeto em 2026-07-27 (COMPLETO)

### O que esta pronto (100% — 62 arquivos Python, ~9.200 LOC)

| Modulo | Status |
|---|---|
| MVP1 SAGA-SAGV_V2 | 37/42 tarefas (88%) — 5 gates humanos pendentes |
| MVP2 Copilot | 8 modulos, 49/49 testes |
| Fase 0 — Fundacao | Schemas + Infra (11 modulos) + OPA + CI/CD |
| **8 Camadas** | **L1 a L8 implementadas** |
| Interface Excecoes | Dashboard (5 paginas) + API REST (12 endpoints) |
| Grafana Dashboards | 4 paineis HTML + docs de observabilidade |
| Security Tests | Bandit 0 HIGH, SAST audit completo |
| Governance Review | Handoff final com projecao de custo (~$1.705/mes) |
| MITRE Catalog | ATT&CK (28 tecnicas) + ATLAS (15 LLM threats) |
| Arquitetura SVGs | Funcional (8 camadas C4) + Tecnica (AWS stack) |
| Infra Hardening | Aurora pgvector + vLLM CIS Level 1 + Bedrock budget |
| Release Publico | MIT license + CONTRIBUTING + SECURITY |
| Documentacao | 51 .md, 6 ADRs, threat model, compliance |
| Config OpenCode | 12 agentes ZTK + orquestrador |
| **TOTAL TESTES** | **297 unitarios + 30 OPA + 9 integracao = 336** |

### O que NAO esta pronto (bloqueios externos)

| Item | Bloqueio | Codigo |
|---|---|---|
| Gates humanos MVP1 (G2/G5/G7/G9/G10) | Stakeholders externos | — |
| `terraform apply` | Sem conta AWS target | ✅ IaC pronta (11 modulos) |
| Bedrock IAM/config | Time de plataforma | ✅ Role + budget provisionados |
| Aurora pgvector | `terraform apply` pendente | ✅ Modulo completo (161 LOC) |
| vLLM local (GPU) | `terraform apply` pendente | ✅ Script hardening CIS L1 (299 LOC) |
| Deploy AWS real | IaC provisionada, apply pendente | ✅ CI/CD pipeline completo |

### POC — Validada em 2026-08-01

| Validacao | Resultado |
|---|---|
| Pipeline E2E (L1-L5) | ✅ Git repo → Patch + Containment em <1s |
| Performance (1.000 findings) | ✅ 1.214/sec, P99 5ms |
| RunPod GPU (RTX 3090) | ✅ Deployado via API, $0.22/hr |
| Railway Dashboard | ✅ Deployado (gratuito) |
| Admin Dashboard (9 tabs) | ✅ Funcional local + remoto |
| Testes (336+) | ✅ Todos passando |
| OPA Policies (30/30) | ✅ Passando |
| Secret Scan | ✅ Zero leaks |

### Proximo Passo — Integracao Pipeline + CI/CD (Pendente)

```
Git push/PR → GitHub Action → Pipeline L1-L5 → POST /api/pipeline/analyze → Dashboard M9
```

| # | O que implementar | Esforco |
|---|---|---|
| 1 | Endpoint `POST /api/pipeline/analyze` — recebe `{repo_url, commit_sha}`, roda pipeline, retorna JSON | 1h |
| 2 | GitHub Action `pipeline.yml` — dispara no push, chama endpoint de analise | 30min |
| 3 | Webhook de resultados — dashboard atualiza em tempo real (sem F5) | 30min |
| 4 | Conectar RunPod GPU ao pipeline (vLLM) | 1h |

### Handoff — Proximos passos para producao
1. Obter conta AWS com VPC e permissões IAM
2. `terraform apply` (IaC provisionada, validada)
3. Configurar Bedrock IAM + Aurora pgvector + EC2 GPU
4. Resolver gates MVP1 (stakeholders)
5. Deploy staging + smoke tests
6. Pentest externo (QSA)
7. CAB approval → producao
