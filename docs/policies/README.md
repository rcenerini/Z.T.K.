# Políticas Z.T.K. (OPA/Rego)

![OPA](https://img.shields.io/badge/engine-OPA%2FRego-00d4ff)
![Policies](https://img.shields.io/badge/policies-3-ff6b35)
![Tests](https://img.shields.io/badge/tests-30%2F30-00ff88)

> **Versão:** 1.0 | **Fase:** F0.3 | **Princípio:** deny-by-default

---

## 1. Visão Geral

As políticas Z.T.K. são escritas em **Rego** (linguagem declarativa do Open Policy Agent)
e aplicadas em três pontos do pipeline:

| Ponto | Política | Gatilho |
|-------|----------|---------|
| **CI/CD (pre-commit)** | `deny_by_default` | Todo PR — valida operações sensíveis |
| **CI/CD (terraform plan)** | `iam_least_privilege` | Todo `terraform plan` — audita IAM |
| **Runtime (L7 Router)** | `data_sovereignty` | Todo LLM request — bloqueia PCI→Bedrock |

---

## 2. Políticas

### 2.1 deny_by_default.rego

**Princípio:** tudo é negado, exceto o que for explicitamente permitido.

```rego
default allow := false
```

| Operação | Condição | Decisão |
|----------|----------|---------|
| `read_code` | Sempre | ✅ Allow |
| `read_finding` | Sempre | ✅ Allow |
| `containment_dry_run` | `dry_run == true` | ✅ Allow |
| `containment_live` | — | ❌ Deny |
| `merge_pr` | `security_review + severity not in [P0,P1]` | ✅ Allow |
| `merge_pr` (P0/P1) | — | ❌ Deny (humano obrigatório) |
| `deploy:production` | `cab_approved == true` | ✅ Allow |
| `write_audit_event` | Sempre | ✅ Allow |
| `kill_switch` | `authority == "SOC"` | ✅ Allow |
| Qualquer outra | — | ❌ Deny |

### 2.2 iam_least_privilege.rego

**Violações detectadas:**

| Violação | Severidade | Exemplo |
|----------|-----------|---------|
| `Allow + Resource:* + Action:*` | **CRITICAL** | Superadmin implícito |
| `Resource:*` sem condição | **HIGH** | Escopo aberto |
| Ações perigosas (`iam:*`, `kms:Delete*`) | **CRITICAL** | Destruição de infra |
| KMS sem rotação | **HIGH** | PCI DSS 3.6 |
| S3 sem block public access | **CRITICAL** | Exposição de dados |
| DynamoDB sem PITR | **HIGH** | PCI DSS 10.7 |
| DynamoDB sem criptografia | **HIGH** | PCI DSS 3.4 |

### 2.3 data_sovereignty.rego

**Regra de ouro:** `data_scope=PCI|PII → provider=vllm_local`

| Violação | Severidade |
|----------|-----------|
| PCI → Bedrock | **CRITICAL** |
| PII → Bedrock sem `force_local` | **HIGH** |
| Padrão PAN em prompt Bedrock | **CRITICAL** |
| vLLM sem isolamento de rede | **HIGH** |
| vLLM com storage persistente | **HIGH** |

---

## 3. Testes

```bash
# Executar todos os testes
opa test infra/policies/ tests/policy/ -v

# Resultado esperado: 27/27 passing
```

| Arquivo | Testes |
|---------|--------|
| `deny_by_default` | 11 |
| `iam_least_privilege` | 8 |
| `data_sovereignty` | 8 |

---

## 4. Integração CI/CD

```yaml
# .github/workflows/ci.yml (trecho)
- name: OPA Policy Tests
  run: |
    curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_windows_amd64
    ./opa test infra/policies/ tests/policy/ -v
```

---

## 5. Estrutura

```
infra/policies/
├── deny_by_default.rego      ← Baseline (default deny)
├── iam_least_privilege.rego  ← IAM audit
└── data_sovereignty.rego     ← PCI routing enforcement

tests/policy/
└── test_policies.rego        ← 27 testes unitários
```
