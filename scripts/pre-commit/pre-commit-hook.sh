#!/bin/bash
# Pre-commit hook — ZTK
# Instalado via: make pre-commit-install

set -euo pipefail

echo "[pre-commit] Rodando quality gates locais..."

# Lint
make lint || { echo "[pre-commit] LINT FALHOU"; exit 1; }

# Type check
make typecheck || { echo "[pre-commit] TYPE CHECK FALHOU"; exit 1; }

# Security scan rapido
make security-sast || { echo "[pre-commit] SAST FALHOU"; exit 1; }

# Secrets detection
git diff --cached --name-only | xargs trufflehog git file://. --only-verified || { echo "[pre-commit] SECRETS DETECTADOS"; exit 1; }

echo "[pre-commit] Todos os gates passaram. Commit permitido."
