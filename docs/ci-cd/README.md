# CI/CD Pipeline — Z.T.K.

![CI](https://img.shields.io/badge/CI-GitHub_Actions-2088FF?logo=githubactions)
![CD](https://img.shields.io/badge/CD-GitHub_Enterprise-2088FF?logo=github)
![Terraform](https://img.shields.io/badge/Terraform-1.7%2B-7b42bc?logo=terraform)
![Status](https://img.shields.io/badge/gates-7-00ff88)

> **Versão:** 1.0 | **Fase:** F0.4 | **Plataforma:** GitHub Enterprise

---

## 1. Visão Geral

O pipeline CI/CD do Z.T.K. implementa **7 gates de qualidade** executados a cada
push/PR, com deploy automatizado via GitHub Environments (proteção de branch +
aprovação manual).

### Diagrama

```
push/PR → main
  │
  ├─ CI Pipeline (.github/workflows/ci.yml)
  │   ├─ Gate 1: Lint + Typecheck    (ruff, mypy)
  │   ├─ Gate 2: Unit Tests           (pytest, coverage)
  │   ├─ Gate 3: SAST                 (bandit)
  │   ├─ Gate 4: Secret Scan          (detect-secrets + grep)
  │   ├─ Gate 5: OPA Tests            (opa test)
  │   └─ Gate 6: Terraform Validate   (terraform validate)
  │
  └─ Regression Gate
       │
       └─ CD Pipeline (.github/workflows/cd.yml)
            ├─ Terraform Plan
            ├─ Manual Approval (GitHub Environment protection)
            └─ Terraform Apply
```

---

## 2. Gates

| # | Gate | Ferramenta | Bloqueia Merge? | Tempo Médio |
|---|------|-----------|-----------------|-------------|
| 1 | **Lint + Typecheck** | ruff, mypy | ⚠️ Warning | <2 min |
| 2 | **Unit Tests** | pytest | ✅ Sim | <3 min |
| 3 | **SAST** | bandit | ⚠️ Warning | <1 min |
| 4 | **Secret Scan** | detect-secrets + grep | ✅ Sim | <1 min |
| 5 | **OPA Tests** | opa test | ✅ Sim | <1 min |
| 6 | **Terraform Validate** | terraform | ✅ Sim | <2 min |
| 7 | **Regression Gate** | — | ✅ Sim | <1 min |

---

## 3. Comandos Locais (simula CI)

```bash
# Pipeline completo (igual ao CI)
make ci

# Lint + types
make lint typecheck

# Testes por modulo
make test-mvp2        # MVP2 Copilot (49 testes)
make test-shared      # Shared Schemas (40 testes)
make test             # Ambos

# Security
make security-sast    # Bandit SAST
make security-secrets # Credential scan
make security-iac     # Checkov (infra)

# OPA
make opa-test         # 30/30 testes

# Terraform
make tf-validate      # fmt + init + validate

# ALL GATES
make quality-gates    # lint + typecheck + test + sast + secrets + opa + terraform
```

---

## 4. Configuração GitHub Enterprise

### Secrets necessários

| Secret | Descrição |
|--------|-----------|
| `AWS_DEPLOY_ROLE_ARN` | ARN da IAM Role para deploy |
| `AWS_ACCESS_KEY_ID` | (Opcional — preferir OIDC) |
| `AWS_SECRET_ACCESS_KEY` | (Opcional — preferir OIDC) |

### Environment Protection Rules

**Settings → Environments → production:**
- [x] Required reviewers: Tech Lead + Security
- [x] Wait timer: 0 minutes
- [x] Deployment branches: main
- [x] Allow administrators to bypass: No

---

## 5. Fluxo de Deploy

| Etapa | Responsável | Ação |
|-------|------------|------|
| 1. PR aberto | Developer | CI pipeline roda automaticamente |
| 2. CI verde | Developer | Merge permitido |
| 3. Merge → main | Automático | CI roda novamente + CD inicia |
| 4. Terraform Plan | Automático | Plano gerado e armazenado como artefato |
| 5. Aprovação Manual | Tech Lead / Security | Revisa plano e aprova no GitHub UI |
| 6. Terraform Apply | Automático | Aplica mudanças na AWS |
| 7. Health Check | Automático | Verifica deploy |

---

## 6. Rollback

```bash
# Via GitHub Actions UI:
# Actions → CD Pipeline → Run workflow → Rollback
# Ou manualmente:
make tf-destroy
```
