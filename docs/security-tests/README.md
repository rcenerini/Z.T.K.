# Security Tests — Z.T.K. Auto-Audit

![Bandit](https://img.shields.io/badge/Bandit-0_HIGH-00ff88)
![Secrets](https://img.shields.io/badge/Secrets-0_LEAKS-00ff88)
![OPA](https://img.shields.io/badge/OPA-30%2F30-00ff88)
![Tests](https://img.shields.io/badge/Unit_Tests-297%2F297-00ff88)

> **Versão:** 1.0 | **Fase:** M11 | **Data:** 2026-07-27

---

## 1. Resultados — SAST (Bandit)

**Total escaneado:** 6.542 lines of code em 3 módulos (src/, mvp2/, interface_excecoes/)

| Severidade | Quantidade | Status |
|-----------|-----------|--------|
| HIGH | **0** | ✅ |
| MEDIUM | 2 | ✅ Ambos intencionais |
| LOW | 124 | ✅ Assert em testes + hardcoded tmp |

### Findings MEDIUM (intencionais)

| # | CWE | Arquivo | Justificativa |
|---|-----|---------|--------------|
| M1 | CWE-89 | `mvp2/copilot/tests/test_copilot.py:491` | **Test fixture** — string SQL no teste do RAG retriever. Não é código de produção. |
| M2 | CWE-377 | `src/layer3_validation/sandbox_executor.py:197` | **Sandbox** — `/tmp` é o filesystem isolado da microVM. Intencional para execução efêmera. |

### LOW (esperados)

- **B101 (assert)**: 124 ocorrências em arquivos de teste (`test_*.py`). Assert é a API padrão do pytest.
- **B110 (except Exception)**: catch amplo com `fail_closed` — comportamento seguro documentado.

---

## 2. Secret Scan

| Padrão | Resultado |
|--------|-----------|
| `verify=False` | **0 ocorrências** ✅ |
| `api_key = "..."` | **0 ocorrências** ✅ |
| `password = "..."` | **0 ocorrências** ✅ |
| `token = "..."` | **0 ocorrências** ✅ |
| `PAN/CHD/cvv` | **0 ocorrências** ✅ |

---

## 3. OPA Policies

| Política | Testes |
|----------|--------|
| `deny_by_default.rego` | 15/15 |
| `iam_least_privilege.rego` | 8/8 |
| `data_sovereignty.rego` | 7/7 |
| **Total** | **30/30** ✅ |

---

## 4. Unit Test Coverage

| Camada | Testes |
|--------|--------|
| MVP2 Copilot | 49 |
| F0 — Shared | 40 |
| L1 — Entrada | 48 |
| L2 — Especialistas | 20 |
| L3 — Validação | 20 |
| L4 — Consenso | 21 |
| L5 — Remediação | 22 |
| L6 — Governança | 34 |
| L7 — Ensemble | 18 |
| L8 — Escala | 17 |
| M9 — Dashboard | 8 |
| **Total** | **297** ✅ |

---

## 5. CI/CD Integration

```yaml
# .github/workflows/ci.yml (trecho)
- name: SAST — Bandit
  run: bandit -r src/ mvp2/ interface_excecoes/ -ll -f json -o bandit-report.json
  continue-on-error: true

- name: Secret Scan
  run: |
    ! grep -r "verify=False" --include="*.py" src/ mvp2/ interface_excecoes/
    ! grep -rP "(api_key|password|token)\s*=\s*['\"]" --include="*.py" src/ mvp2/ interface_excecoes/

- name: OPA Test
  run: opa test infra/policies/ tests/policy/ -v
```

---

## 6. Recomendações Pós-Audit

| # | Recomendação | Prioridade |
|---|-------------|-----------|
| 1 | Adicionar Sarif output ao Bandit para integração com GitHub Code Scanning | Média |
| 2 | Rodar Semgrep com ruleset `p/security-audit` no pipeline | Média |
| 3 | Adicionar dependency scan (pip-audit) para CVEs em libs | Média |
| 4 | Penetration test externo (terceiro) antes de produção | Alta |
