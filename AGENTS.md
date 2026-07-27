# AGENTS.md — Z.T.K. (Zero Trust Kill)

**Versao:** 1.0 | **Atualizacao:** 2026-07-26
**Escopo:** Todos os agentes OpenCode trabalhando neste repositorio
**Mandamento:** Leia este guia ANTES de qualquer implementacao

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

## AI Handoff — Estado do projeto em 2026-07-26

### O que esta 100% pronto

| Modulo | Status |
|---|---|
| MVP1 SAGA-SAGV_V2 | 37/42 tarefas (88%) |
| MVP2 copilot/models.py | Implementado |
| MVP2 copilot/config.py | Implementado |
| MVP2 copilot/prompt_builder.py | Implementado |
| MVP2 copilot/rag_retriever.py | Implementado (stub JSON) |
| MVP2 copilot/claude_client.py | Implementado (Bedrock) |
| MVP2 copilot/handler.py | Implementado |
| MVP2 copilot/observability.py | Implementado |
| MVP2 copilot/tests/test_copilot.py | 39/49 passando |
| MVP2 copilot/data/ | RAG index + prompt schema OK |
| Config OpenCode | 12 agentes + orquestrador |
| Steering docs | ZTK_DEVELOPMENT_GUIDE, ZTK_LAYER_ROADMAP |

### O que NAO esta pronto

| Item | Bloqueio |
|---|---|
| Gates humanos MVP1 (G2/G5/G7/G9/G10) | Aguardando stakeholders externos |
| Aurora PostgreSQL + pgvector (RAG real) | Futuro |
| Bedrock IAM/config | Aguardando time de plataforma |
| 10 testes falhando no copilot (bugs de runtime) | Em correcao |
| Codigo das 8 camadas (src/layer*) | Apenas __init__.py |

### Proximos passos

1. Corrigir 10 testes falhando (logger kwargs + parse enum + double-count)
2. Executar secret scan antes de commit
3. Implementar F0.1.1 (schema Finding — inicio da Fase 0)
4. Configurar Bedrock IAM quando disponivel
