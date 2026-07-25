# Makefile — ZTK Quality Gates & Dev
.PHONY: all install test lint security quality-gates deploy-docs

PYTHON := python3.12
UV := uv

all: install quality-gates

install:
	$(UV) sync --all-groups

# Testes
test:
	$(UV) run pytest --cov=src --cov-report=term-missing

test-unit:
	$(UV) run pytest tests/unit/ -v

test-integration:
	$(UV) run pytest tests/integration/ -v -m integration

test-contract:
	$(UV) run pytest tests/contract/ -v -m contract

test-security:
	$(UV) run pytest tests/security/ -v -m security

test-fail-closed:
	$(UV) run pytest -v -m fail_closed

test-e2e:
	$(UV) run pytest tests/e2e/ -v -m e2e

# Lint e Type Check
lint:
	$(UV) run ruff check src/ tests/
	$(UV) run ruff format --check src/ tests/

lint-fix:
	$(UV) run ruff check --fix src/ tests/
	$(UV) run ruff format src/ tests/

typecheck:
	$(UV) run mypy --strict src/

# Security Scan
security-sast:
	$(UV) run bandit -r src/ -ll

security-secrets:
	@command -v trufflehog >/dev/null 2>&1 || { echo "trufflehog nao instalado"; exit 1; }
	trufflehog git file://. --only-verified

security-iac:
	@command -v checkov >/dev/null 2>&1 || { echo "checkov nao instalado"; exit 1; }
	checkov -d infra/terraform/ --framework terraform --compact

opa-test:
	@command -v opa >/dev/null 2>&1 || { echo "opa nao instalado"; exit 1; }
	find infra/policies -name "*_test.rego" -exec dirname {} \; | sort -u | xargs -I {} opa test {}

# Quality Gates (CI/CD completo)
quality-gates: lint typecheck test security-sast security-secrets opa-test
	@echo "=== QUALITY GATES PASSED ==="

# Pre-commit hooks local
pre-commit-install:
	@cp scripts/pre-commit/pre-commit-hook.sh .git/hooks/pre-commit
	@chmod +x .git/hooks/pre-commit
	@echo "Pre-commit hook instalado"

# Limpeza
clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov dist/

# Infra
tf-plan:
	cd infra/terraform && terraform plan

tf-apply:
	cd infra/terraform && terraform apply

tf-destroy:
	cd infra/terraform && terraform destroy
