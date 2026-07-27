
```markdown
# ZTK_DEVELOPMENT_GUIDE.md
## Guia de Desenvolvimento para Agentes OpenCode no Projeto Z.T.K.

> **Versão:** 1.0 | **Data:** 2026-07-25
> **Escopo:** Todos os agentes OpenCode trabalhando no repositório Z.T.K.
> **Mandamento:** Leia este guia ANTES de qualquer implementação. Nenhum código deve ser gerado sem conformidade com este documento.

---


![Steering](https://img.shields.io/badge/type-Steering_Doc-00d4ff)
![Version](https://img.shields.io/badge/version-1.0-00ff88)


## 1. FILOSOFIA DE DESENVOLVIMENTO

### 1.1 Princípio Central Determinístico

> **"Sempre que existir uma ferramenta determinística capaz de resolver a tarefa, o LLM não decide — ele apenas interpreta a saída da ferramenta."**

Este princípio não é opcional. Ele é requisito de design e será verificado em code review:

- **NÃO** use LLM para: classificação de linguagem, roteamento de pipeline, scoring de evidência, cálculo de CVSS, decisão de severidade, decisão de roteamento PCI vs non-PCI.
- **USE** LLM para: interpretar saída SARIF/JSON de ferramenta SAST, argumentar em debate adversarial (Prosecutor/Defender), gerar patch de código a partir de contexto AST, copilotar análise de exceção.

### 1.2 Fail-Closed como Padrão

Toda função/método que toma decisão de segurança deve ter comportamento conservador em caso de:

- Dado ausente ou malformado
- Timeout de ferramenta externa
- Falha de API (NVD, EPSS, OSV)
- Indisponibilidade de cache
- Ambiguidade de configuração

**Proibido:** assumir valor default "seguro" ou "baixo risco". **Obrigatório:** marcar como `"unknown"`, `"inconclusivo"`, `"critical"` ou `"requires_human_validation"`.

### 1.3 Idempotência em Estado Externo

Toda gravação em DynamoDB, S3, SQS, Jira, WAF deve ser segura para reexecução:

- DynamoDB: `ConditionExpression` em `put_item`
- S3: `If-None-Match: *` + `head_object` antes de write
- SQS: dedup por `finding_id` + `stage`
- Jira: idempotência via campo custom `finding_id`
- WAF: dry-run antes de apply, versioning de regra

---

## 2. PADRÕES DE CÓDIGO (Obrigatórios)

### 2.1 Python 3.12+

```python
# EXEMPLO DE CONFORMIDADE
from typing import Any
import structlog
from pydantic import BaseModel, Field, field_validator

logger = structlog.get_logger()

class Finding(BaseModel):
    finding_id: str = Field(..., min_length=1)
    severity: str = Field(..., pattern="^(P0|P1|P2|P3|P4|CRITICAL|HIGH|MEDIUM|LOW)$")
    
    @field_validator("finding_id")
    @classmethod
    def validate_uuid(cls, v: str) -> str:
        if not is_valid_uuid(v):
            raise ValueError("finding_id deve ser UUID válido")
        return v

# EXEMPLO DE FAIL-CLOSED
def classify_language(repo_path: str) -> str:
    try:
        result = run_enry(repo_path)
        if result.confidence < 0.8:
            return "unclassified"  # conservador
        return result.language
    except Exception as e:
        logger.error("language_classifier_failed", error=str(e), repo_path=repo_path)
        return "unclassified"  # NUNCA assume
```

**Regras:**
- Type hints obrigatórios em 100% das funções públicas
- `mypy --strict` passa sem erros
- `ruff check` passa sem warnings (exceto E501)
- `bandit` passa sem findings (exceto B101 em testes)

### 2.2 Estrutura de Arquivo por Componente

Cada agente/serviço segue a estrutura:

```
src/layer{N}_{nome}/agent_id/
├── __init__.py
├── handler.py          # Entrypoint (Lambda ou ECS)
├── service.py          # Lógica de domínio
├── repository.py       # Acesso a dados (DynamoDB/S3/SQS)
├── schemas.py          # Schemas Pydantic específicos
├── config.py           # Configuração via env vars / Parameter Store
├── Dockerfile          # Se ECS/Fargate
└── tests/
    ├── __init__.py
    ├── test_handler.py
    ├── test_service.py
    └── fixtures/
```

**Proibido:** misturar lógica de domínio em `handler.py`. Handler deve ter <30 linhas.

### 2.3 Async/Await para IO-Bound

```python
# CORRETO
async def fetch_epss(cve_id: str) -> EPSSResult:
    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.get(f"{EPSS_URL}/{cve_id}")
    return parse_epss(response.json())

# INCORRETO (síncrono bloqueante)
def fetch_epss(cve_id: str) -> EPSSResult:
    response = requests.get(f"{EPSS_URL}/{cve_id}")  # NUNCA
    return parse_epss(response.json())
```

### 2.4 Context Managers e Recursos

```python
# CORRETO
async with boto3_session() as session:
    async with session.client("dynamodb") as client:
        ...

# INCORRETO
client = boto3.client("dynamodb")  # NUNCA sem context manager
```

### 2.5 Logging (NUNCA print)

```python
logger = structlog.get_logger(agent_id="L1.02", layer="1")

logger.info(
    "language_classified",
    repo_path=repo_path,
    language=language,
    confidence=confidence,
    request_id=request_id,  # OBRIGATÓRIO
)
```

Campos obrigatórios em todo log:
- `timestamp` (ISO 8601)
- `level`
- `agent_id`
- `layer`
- `finding_id` (se aplicável)
- `request_id` (correlation_id)
- `message` (evento estruturado, não frase livre)

---

## 3. SEQUÊNCIA DE DESENVOLVIMENTO

### 3.1 Ordem Obrigatória

NUNCA pular fases. NUNCA construir Camada N sem a Camada N-1 estar com schemas definidos e testes passando.

```
F0.1 (Shared schemas) → F0.2 (Infra base) → F1 (Camada 1) → F2 (Camada 6)
→ F3 (Camada 2) → F4 (Camada 3) → F5 (Camada 4) → F6 (Camada 5)
→ F7 (Camada 7) → F8 (Camada 8) → F9 (Interface) → F10 (Docs) → F11 (SecTests)
```

### 3.2 Regra do Um-Por-Vez

Cada task implementa **UM** agente/serviço/componente. Não agrupe:

- ❌ "Implementar todos os SAST agents de uma vez"
- ❌ "Construir Camada 2 e 3 juntas"
- ❌ "Fazer frontend e backend da interface simultaneamente"

### 3.3 Fundação Primeiro

Antes de tocar qualquer camada:

1. `shared/schemas/` deve ter schemas base estáveis
2. `shared/utils/` deve ter utilitários testados
3. Infra base (VPC, DynamoDB, S3, SQS, IAM) deve estar implantável (`terraform plan` passa)
4. CI/CD (`make all`) deve passar verde
5. OPA policies base (`deny_by_default.rego`) deve passar `opa test`

---

## 4. PADRÕES POR CAMADA

### 4.1 Camada 1 (Ingress/Triagem)

- **Determinística 100%** — nenhum LLM
- **Output:** SQS message para `queue_normalize`
- **Fail-closed:** conteúdo suspeito → isolado, nunca descartado silenciosamente
- **Guard:** L1.03 (prompt injection) é filtro obrigatório antes de qualquer conteúdo ir para Camada 2+

### 4.2 Camada 2 (Especialistas)

- **Framework primeiro:** `sast_framework/` (executor, parser, correlator) antes de instanciar por linguagem
- **Container:** cada SAST agent roda em container ECS Fargate Spot isolado
- **Parser:** normaliza SARIF/JSON para `Finding` (schema F0.1.1)
- **Correlator (L2.16):** único ponto com LLM nesta camada. Input: lista de `Finding`. Output: `CorrelatedFinding`
- **Fail-closed:** timeout/falha de ferramenta → `"não analisado"`, nunca `"aprovado"`

### 4.3 Camada 3 (Validação)

- **Sandbox obrigatório:** PoC agents rodam em Firecracker/gVisor, sem rede, sem host fs, sem dados reais
- **HITL para fuzzing:** L3.13 só executa com aprovação humana explícita registrada
- **Score engine (L3.18):** determinístico, sem LLM. Tabela de pesos hardcoded e versionada
- **Fail-closed:** call-graph incompleto → `"inconclusivo"`, nunca `"não alcançável"`

### 4.4 Camada 4 (Consenso)

- **Debate só para zona cinzenta (4-7):** score ≥8 ou ≤0 → skip debate, resolve deterministicamente
- **Pisos:** PCI→P1, LGPD→P1, Antifraude→P0. NUNCA violados pelo Judge
- **Override:** só via Camada 6 (four-eyes)
- **LLM:** Prosecutor e Defender são enviesados propositalmente. Judge é moderador com restrição de piso

### 4.5 Camada 5 (Remediação)

- **Trilha A (código):** nunca merge automático em P0/P1. PR sempre requer aprovação humana.
- **Trilha B (contenção):** template validado por CWE, dry-run obrigatório, TTL obrigatório, kill switch disponível
- **SLA breach:** renovação de TTL sem merge → escalação progressiva até C-level
- **Kill switch:** autoridade SOC, ação única, notificação imediata, audit event

### 4.6 Camada 6 (Governança)

- **Policy Engine (OPA/Rego):** deny-by-default, testável, versionado
- **Auditoria:** append-only, particionado S3, forward para Sentinel
- **HITL:** fila única, notificação Teams/e-mail, ticket Jira, SLA monitor
- **Four-eyes:** Gerente Executivo + Superintendente, mesma pessoa bloqueada, prazo de vigência, reversão automática

### 4.7 Camada 7 (Model Ensemble)

- **Roteamento PCI:** dados CHD/PII/PAN → vLLM local OBRIGATORIAMENTE. NUNCA Bedrock.
- **Tiers:** Volume (distilled), Reasoning (frontier), Generation (ensemble)
- **Ensemble:** só para patch generation (L7.11-12). Divergência → HITL.
- **Circuit breaker:** 80% alerta, 100% pausa tier caro. NUNCA pausa HITL/kill

### 4.8 Camada 8 (Escala)

- **Ativação condicional:** monorepo → análise por módulo, não por repositório inteiro
- **Shadow mode:** todo novo agente roda 30 dias em shadow antes de promoção
- **Tool lifecycle:** monitoramento de updates, PR automático, ownership registry
- **Multi-tenancy:** `tenant_id` em todos os schemas desde v1

---

## 5. WORKFLOW DE DESENVOLVIMENTO (Checklist do Agente)

Antes de começar qualquer task:

1. **Leia este guia** e o `CLAUDE.md`
2. **Consulte `TASKS_ZTK.md`** para confirmar a task atual e suas dependências
3. **Verifique schemas em `shared/schemas/`** — se um schema necessário não existe, pare e solicite F0.1.x primeiro
4. **Confirme infra em `infra/terraform/`** — se um módulo necessário não existe, pare e solicite F0.2.x primeiro

Durante a implementação:

5. **Implemente UM componente por vez** — handler → service → repository → schemas → tests
6. **Rode `make lint typecheck test`** a cada arquivo salvo — não acumule débito técnico
7. **Nunca ignore mypy strict** — corrija o tipo, não use `# type: ignore`
8. **Valide com `@ztk-reviewer`** antes de considerar a task concluída

Após implementação:

9. **Rode `make quality-gates`** localmente — todos os gates devem passar
10. **Atualize `TASKS_ZTK.md`** — marque a task como `[-]` (em progresso) ou `[x]` (concluído)
11. **Solicite `@ztk-qa`** para validação de cobertura e testes
12. **Solicite `@git`** para commit no formato Conventional Commits

---

## 6. QUALITY GATES ANTES DE ENTREGAR

Todo código entregue deve passar:

| Gate | Comando | Threshold |
|------|---------|-----------|
| Lint | `make lint` | ruff check passa, zero warnings |
| Type check | `make typecheck` | mypy --strict, zero erros |
| Unit tests | `make test-unit` | pytest passa, cobertura >= 85% |
| Security SAST | `make security-sast` | bandit -ll, zero HIGH/CRITICAL |
| Secrets | `make security-secrets` | trufflehog, zero leaks |
| Infra scan | `make security-iac` | checkov/tfsec, zero HIGH |
| OPA tests | `make opa-test` | opa test, 100% pass |

**Se qualquer gate falhar:** a task NÃO está concluída. Corrija antes de prosseguir.

---

## 7. ANTI-PATTERNS PROIBIDOS

| Anti-Pattern | Por que é proibido | Correto |
|--------------|-------------------|---------|
| LLM decide severidade sozinho | Não é auditável, sujeito a alucinação | Scoring determinístico com tabela de pesos |
| Merge automático em P0/P1 | Compromete controle de mudança | PR + aprovação humana obrigatória |
| Credencial hardcoded | Viola PCI DSS, LGPD, principio Zero Trust | AWS Secrets Manager + IAM least privilege |
| `except Exception: pass` | Silencia falhas de segurança | `fail_closed` decorator + log estruturado |
| Query SQL concatenada | SQL injection | Prepared statements / ORM |
| `print()` em produção | Logs não estruturados, não correlacionáveis | structlog JSON com `request_id` |
| Schema sem validator Pydantic | Dados malformados propagam | Validators em todos os campos críticos |
| Container com root + writable fs | Escalada de privilégio | `runAsNonRoot`, `readOnlyRootFilesystem` |
| Bedrock para dados PCI | Dados saem da VPC | vLLM local obrigatório |
| Função >100 linhas | Complexidade, difícil de testar | Refatorar em service + repository + utils |

---

## 8. REFERÊNCIAS RÁPIDAS

| Documento | Onde encontrar | Quando consultar |
|-----------|---------------|------------------|
| `TASKS_ZTK.md` | Raiz do projeto | Antes de qualquer implementação |
| `CLAUDE.md` | Raiz do projeto | Contexto técnico e princípios |
| `ZTK-Arquitetura-Completa.md` | `Brainstorming/refinado_v1/` | Arquitetura detalhada das 8 camadas |
| `SAGA-SAGV-V2_ZTK-Arquitetura-Conjunta.md` | `Brainstorming/refinado_v1/` | Visão conjunta MVP1 + MVP2 |
| `ADR-001` | `docs/architecture/` | Decisão ECS vs EKS |
| `ADR-002` | `docs/architecture/` | Decisão model routing |
| `S-SDLC.md` | `docs/ssdlc/` | Fases SSDLC e gates |
| `pyproject.toml` | Raiz do projeto | Dependências e config de ferramentas |
| `Makefile` | Raiz do projeto | Comandos de quality gates |
| `opencode.json` | Raiz do projeto | Configuração dos 12 agentes ZTK |

---

## 9. CONTATO E ESCALONAMENTO

- **Dúvida técnica de arquitetura:** `@ztk-strategist`
- **Dúvida de segurança em código:** `@ztk-reviewer`
- **Dúvida de compliance/normativa:** `@ztk-governance` ou `@ztk-regulatory`
- **Dúvida de infraestrutura:** `@ztk-infra`
- **Dúvida de backend Python:** `@ztk-backend`
- **Dúvida de testes/QA:** `@ztk-qa`
- **Bug de segurança encontrado durante dev:** `@ztk-security-ops` (imediato)
- **Orquestração de workflow complexo:** `@ztk-orchestrator`