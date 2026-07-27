# Makefile — ZTK Quality Gates & Dev
.PHONY: all install test lint security quality-gates deploy-docs ci cd

PYTHON := python3.12
UV := uv

all: install quality-gates

install:
	$(UV) sync --all-groups

# ── Testes ──────────────────────────────────────────────────────────────────

test: test-mvp2 test-shared
	@echo "✅ All tests passed"

test-mvp2:
	PYTHONPATH=mvp2/copilot/src $(UV) run pytest mvp2/copilot/tests/ -v --tb=short

test-shared:
	PYTHONPATH=src $(UV) run pytest tests/unit/shared/ -v --tb=short

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

# ── Lint & Type Check ───────────────────────────────────────────────────────

lint:
	$(UV) run ruff check src/ mvp2/ tests/
	$(UV) run ruff format --check src/ mvp2/ tests/

lint-fix:
	$(UV) run ruff check --fix src/ mvp2/ tests/
	$(UV) run ruff format src/ mvp2/ tests/

typecheck:
	$(UV) run mypy --strict src/shared/ mvp2/copilot/src/copilot/

# ── Security ────────────────────────────────────────────────────────────────

security-sast:
	$(UV) run bandit -r src/ mvp2/ -ll

security-secrets:
	@echo "=== Checking for verify=False ==="
	@! grep -r "verify=False" --include="*.py" src/ mvp2/ || (echo "❌ CRITICAL: verify=False found" && exit 1)
	@echo "=== Checking for hardcoded credentials ==="
	@! grep -rP "(api_key|password|token|secret)\s*=\s*['\"][^$$]" --include="*.py" src/ mvp2/ || (echo "❌ CRITICAL: Potential credential" && exit 1)
	@echo "✅ Secret scan passed"

security-iac:
	@command -v checkov >/dev/null 2>&1 || { echo "checkov nao instalado"; exit 1; }
	checkov -d infra/terraform/ --framework terraform --compact

# ── OPA Policies ────────────────────────────────────────────────────────────

opa-test:
	@command -v opa >/dev/null 2>&1 || { echo "opa nao instalado"; exit 1; }
	opa test infra/policies/ tests/policy/ -v

# ── Terraform ───────────────────────────────────────────────────────────────

tf-validate:
	cd infra/terraform && terraform fmt -recursive && terraform init -backend=false && terraform validate

tf-plan:
	cd infra/terraform && terraform plan

tf-apply:
	cd infra/terraform && terraform apply

tf-destroy:
	cd infra/terraform && terraform destroy

# ── Quality Gates (CI/CD completo) ──────────────────────────────────────────

quality-gates: lint typecheck test security-sast security-secrets opa-test tf-validate
	@echo "============================================"
	@echo "  ✅ ALL QUALITY GATES PASSED"
	@echo "============================================"

# ── CI/CD Pipeline (simula o GitHub Actions localmente) ─────────────────────

ci: lint typecheck test security-sast security-secrets opa-test tf-validate
	@echo "✅ CI pipeline complete"

cd: tf-plan
	@echo "⚠️  CD: Review terraform plan before applying"
	@echo "   Run 'make tf-apply' to deploy"

# ── Pre-commit Hooks ────────────────────────────────────────────────────────

pre-commit-install:
	@cp scripts/pre-commit/pre-commit-hook.sh .git/hooks/pre-commit
	@chmod +x .git/hooks/pre-commit
	@echo "Pre-commit hook instalado"

# ── Clean ───────────────────────────────────────────────────────────────────

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov dist/
