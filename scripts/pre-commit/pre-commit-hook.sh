#!/bin/bash
# Z.T.K. Pre-commit Hook — Bloqueia credenciais, secrets, debug code
# Instalar: cp scripts/pre-commit/pre-commit-hook.sh .git/hooks/pre-commit
#           chmod +x .git/hooks/pre-commit
# PCI DSS 6.4.2 | NIST SP 800-53 SA-11 | CIS Control 16.2

set -e
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
BLOCKED=0

echo -e "${CYAN}[Z.T.K. Pre-commit Hook]${NC}"

# Only check staged Python files
FILES=$(git diff --cached --name-only --diff-filter=ACM | grep '\.py$' || true)
if [ -z "$FILES" ]; then
    echo -e "${GREEN}  No Python files staged — skipping${NC}"
    exit 0
fi

# ── Gate 1: verify=False (CRITICAL — PCI DSS 4.1) ──────────────────
echo -n "  [verify=False] "
if git diff --cached -- $FILES | grep -q 'verify=False'; then
    echo -e "${RED}BLOCKED${NC}"
    echo -e "${RED}  PCI DSS 4.1 violation: verify=False disables TLS validation${NC}"
    BLOCKED=1
else
    echo -e "${GREEN}OK${NC}"
fi

# ── Gate 2: Hardcoded credentials (CRITICAL — PCI DSS 7.1) ────────
echo -n "  [Credentials ] "
CREDS=$(git diff --cached -- $FILES | grep -P "(api_key|password|secret|token)\s*=\s*['\"][A-Za-z0-9_\-]{8,}" || true)
if [ -n "$CREDS" ]; then
    echo -e "${RED}BLOCKED${NC}"
    echo -e "${RED}  Potential hardcoded credential detected:${NC}"
    echo "$CREDS" | head -3 | sed 's/^/    /'
    BLOCKED=1
else
    echo -e "${GREEN}OK${NC}"
fi

# ── Gate 3: eval/exec usage (HIGH) ─────────────────────────────────
echo -n "  [eval/exec  ] "
if git diff --cached -- $FILES | grep -qP '\b(eval|exec)\s*\('; then
    echo -e "${RED}BLOCKED${NC}"
    echo -e "${RED}  eval/exec with user input is prohibited${NC}"
    BLOCKED=1
else
    echo -e "${GREEN}OK${NC}"
fi

# ── Gate 4: Debug breakpoints (MEDIUM) ─────────────────────────────
echo -n "  [Debug code ] "
if git diff --cached -- $FILES | grep -qP '\b(breakpoint\(\)|pdb\.set_trace\(\)|ipdb\.set_trace\(\))'; then
    echo -e "${RED}BLOCKED${NC}"
    echo -e "${RED}  Remove breakpoint()/pdb before committing${NC}"
    BLOCKED=1
else
    echo -e "${GREEN}OK${NC}"
fi

# ── Gate 5: File size (MEDIUM — DoS prevention) ────────────────────
echo -n "  [File size  ] "
LARGE=$(git diff --cached --name-only | while read f; do [ -f "$f" ] && [ $(stat -f%z "$f" 2>/dev/null || stat -c%s "$f" 2>/dev/null || echo 0) -gt 524288 ] && echo "$f"; done)
if [ -n "$LARGE" ]; then
    echo -e "${RED}BLOCKED${NC}"
    echo -e "${RED}  Files >500KB:${NC}"; echo "$LARGE" | sed 's/^/    /'
    BLOCKED=1
else
    echo -e "${GREEN}OK${NC}"
fi

# ── Result ─────────────────────────────────────────────────────────
if [ $BLOCKED -eq 0 ]; then
    echo -e "${GREEN}  All pre-commit checks passed${NC}"
    exit 0
else
    echo -e "${RED}  Pre-commit hook blocked — fix issues above before committing${NC}"
    exit 1
fi
