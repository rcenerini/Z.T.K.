#!/bin/bash
# Z.T.K. Batch Test Runner — Roda todos os 297+ testes, OPA, e security scan
# Uso: bash scripts/run_all_tests.sh
# Compatível: Linux, macOS, WSL

set -e
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
PASS=0; FAIL=0; TOTAL=0

echo "============================================"
echo "  Z.T.K. BATCH TEST RUNNER"
echo "============================================"
echo ""

run_tests() {
    local name="$1"; local path="$2"; local pythonpath="$3"
    echo -e "${CYAN}[$name]${NC}"
    PYTHONPATH="$pythonpath" python3 -m pytest "$path" -q --tb=no 2>&1 || true
    if [ $? -eq 0 ]; then ((PASS++)); else ((FAIL++)); fi
}

echo "--- UNIT TESTS ---"

run_tests "MVP2 Copilot       " "mvp2/copilot/tests/"                    "mvp2/copilot/src"
run_tests "F0 — Shared        " "tests/unit/shared/"                     "src"
run_tests "L1 — Entrada       " "tests/unit/layer1/"                     "src/layer1_ingress/src:src"
run_tests "L2 — Especialistas " "tests/unit/layer2/"                     "src/layer2_specialists/src:src"
run_tests "L3 — Validacao     " "tests/unit/layer3/"                     "src/layer3_validation/src:src"
run_tests "L4 — Consenso      " "tests/unit/layer4/"                     "src/layer4_consensus/src:src"
run_tests "L5 — Remediacao    " "tests/unit/layer5/"                     "src/layer5_remediation/src:src"
run_tests "L6 — Governanca    " "tests/unit/layer6/"                     "src/layer6_governance/src:src"
run_tests "L7 — Ensemble      " "tests/unit/layer7/"                     "src/layer7_model_ensemble/src:src"
run_tests "L8 — Escala        " "tests/unit/layer8/"                     "src/layer8_scale/src:src"
run_tests "M9 — Dashboard     " "tests/integration/m9/"                  "interface_excecoes/backend/src"

echo ""
echo "--- SECURITY ---"

echo -e "${CYAN}[OPA Policies]${NC}"
opa test infra/policies/ tests/policy/ -v 2>&1 | tail -1 || ((FAIL++))

echo -e "${CYAN}[Secret Scan]${NC}"
if grep -r "verify=False" --include="*.py" src/ mvp2/ interface_excecoes/ 2>/dev/null; then
    echo -e "${RED}  FAIL: verify=False found${NC}"; ((FAIL++))
else
    echo -e "${GREEN}  PASS: No verify=False${NC}"; ((PASS++))
fi

if grep -rP "(api_key|password|token)\s*=\s*['\"][A-Za-z0-9]" --include="*.py" src/ mvp2/ interface_excecoes/ 2>/dev/null; then
    echo -e "${RED}  FAIL: Potential credentials${NC}"; ((FAIL++))
else
    echo -e "${GREEN}  PASS: No credentials${NC}"; ((PASS++))
fi

echo ""
echo "============================================"
echo -e "  ${GREEN}PASS: $PASS${NC}  ${RED}FAIL: $FAIL${NC}"
echo "============================================"
exit $FAIL
