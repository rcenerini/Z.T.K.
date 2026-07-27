# Contribuindo para o Z.T.K.

Obrigado pelo interesse em contribuir! Este documento descreve o processo.

## Como Contribuir

1. **Fork** o repositório
2. Crie uma branch: `git checkout -b feature/sua-feature`
3. Implemente seguindo os padrões do projeto
4. Execute os testes: `powershell -File scripts/run_all_tests.ps1`
5. Commit: `git commit -m "feat(scope): descricao"` (Conventional Commits)
6. Push: `git push origin feature/sua-feature`
7. Abra um Pull Request

## Padrões de Código

- Python 3.12+ com type hints obrigatórios
- Pydantic v2 para schemas
- pytest para testes (mínimo 85% cobertura)
- Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `chore:`)

## Quality Gates

Antes de abrir um PR, execute:

```bash
# Windows
powershell -File scripts/run_all_tests.ps1

# Linux/macOS
bash scripts/run_all_tests.sh
```

## Estrutura do Projeto

```
ZTK/
├── src/           ← 8 camadas do pipeline multiagente
├── mvp2/          ← Copiloto LLM (Bedrock)
├── infra/         ← Terraform + OPA policies
├── docs/          ← ADRs, runbooks, compliance
├── tests/         ← Unitários + Integração
└── scripts/       ← Test runner + pre-commit hooks
```

## Adicionando Novos Agentes

1. Crie o módulo em `src/layer<N>_<nome>/`
2. Implemente com `fail_closed` e `structlog`
3. Adicione testes em `tests/unit/layer<N>/`
4. Registre no `TASKS_ZTK.md`
5. Atualize `docs/security/blocking-rules.md` se houver novos bloqueios

## Segurança

- **NUNCA** commite credenciais
- **NUNCA** use `verify=False`
- **SEMPRE** valide inputs
- Reporte vulnerabilidades em [SECURITY.md](SECURITY.md)
