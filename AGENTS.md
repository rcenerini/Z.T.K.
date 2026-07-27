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

### O que esta pronto (100%)

| Modulo | Status |
|---|---|
| MVP1 SAGA-SAGV_V2 | 37/42 tarefas (88%) — 5 gates humanos pendentes |
| MVP2 Copilot | 8 modulos, 49/49 testes |
| Fase 0 — Fundacao | Schemas + Infra + OPA + CI/CD |
| **8 Camadas** | **L1 a L8 implementadas, 248/248 testes** |
| Interface Excecoes | Dashboard + API REST |
| Grafana Dashboards | 4 paineis de observabilidade |
| Security Tests | Bandit 0 HIGH, 297/297 |
| Governance Review | Handoff final com projecao de custo |
| Documentacao | 32 .md, 5 ADRs, threat model, compliance |
| Config OpenCode | 12 agentes ZTK + orquestrador |

### O que NAO esta pronto (externo)

| Item | Bloqueio |
|---|---|
| Gates humanos MVP1 (G2/G5/G7/G9/G10) | Aguardando stakeholders externos |
| Aurora PostgreSQL + pgvector (RAG real) | Futuro |
| Bedrock IAM/config | Aguardando time de plataforma |
| vLLM local (GPU) | Infra pendente |
| Deploy AWS real | IaC provisionada, apply pendente |

### Handoff — Proximos passos para producao
1. `terraform apply` (IaC provisionada, validada)
2. Configurar Bedrock IAM
3. Resolver gates MVP1
4. Deploy staging + smoke tests
5. Pentest externo
6. CAB approval → producao
