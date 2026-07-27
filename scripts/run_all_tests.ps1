# Z.T.K. Batch Test Runner — PowerShell (Windows)
# Uso: .\scripts\run_all_tests.ps1

$ErrorActionPreference = "Continue"
$PY = "C:\Users\segundovaio\AppData\Local\Python\bin\python3.exe"
$PASS = 0; $FAIL = 0

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Z.T.K. BATCH TEST RUNNER" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

$modules = @(
    @{Name="MVP2 Copilot       "; Path="mvp2/copilot/tests/";              Py="mvp2/copilot/src"},
    @{Name="F0   Shared        "; Path="tests/unit/shared/";               Py="src"},
    @{Name="L1   Entrada       "; Path="tests/unit/layer1/";               Py="src/layer1_ingress/src;src"},
    @{Name="L2   Especialistas "; Path="tests/unit/layer2/";               Py="src/layer2_specialists/src;src"},
    @{Name="L3   Validacao     "; Path="tests/unit/layer3/";               Py="src/layer3_validation/src;src"},
    @{Name="L4   Consenso      "; Path="tests/unit/layer4/";               Py="src/layer4_consensus/src;src"},
    @{Name="L5   Remediacao    "; Path="tests/unit/layer5/";               Py="src/layer5_remediation/src;src"},
    @{Name="L6   Governanca    "; Path="tests/unit/layer6/";               Py="src/layer6_governance/src;src"},
    @{Name="L7   Ensemble      "; Path="tests/unit/layer7/";               Py="src/layer7_model_ensemble/src;src"},
    @{Name="L8   Escala        "; Path="tests/unit/layer8/";               Py="src/layer8_scale/src;src"},
    @{Name="M9   Dashboard     "; Path="tests/integration/m9/";            Py="interface_excecoes/backend/src"}
)

foreach ($m in $modules) {
    Write-Host "[$($m.Name)]" -ForegroundColor Cyan -NoNewline
    $env:PYTHONPATH = $m.Py
    $out = & $PY -m pytest $m.Path -q --tb=no 2>&1
    $passMatch = $out | Select-String "(\d+)\s+passed"
    $failMatch = $out | Select-String "(\d+)\s+failed"
    if ($passMatch) { Write-Host " $($passMatch.Line.Trim())" -ForegroundColor Green; $PASS++ }
    if ($failMatch) { Write-Host " $($failMatch.Line.Trim())" -ForegroundColor Red; $FAIL++ }
    if (!$passMatch -and !$failMatch) { Write-Host " ERROR" -ForegroundColor Red; $FAIL++ }
}

Write-Host ""
Write-Host "--- SECURITY ---" -ForegroundColor Cyan

Write-Host "[OPA Policies]" -ForegroundColor Cyan -NoNewline
$opa = & "$env:TEMP\opa.exe" test infra/policies/ tests/policy/ -v 2>&1 | Select-String "PASS:|FAIL:"
if ($opa -match "FAIL") { Write-Host " FAIL" -ForegroundColor Red; $FAIL++ }
else { Write-Host " PASS" -ForegroundColor Green; $PASS++ }

Write-Host "[Secret Scan]" -ForegroundColor Cyan -NoNewline
$vfy = Select-String -Path "src\**\*.py","mvp2\**\*.py","interface_excecoes\**\*.py" -Pattern "verify=False" -SimpleMatch 2>$null
$cred = Select-String -Path "src\**\*.py","mvp2\**\*.py","interface_excecoes\**\*.py" -Pattern '(api_key|password|token)\s*=\s*[''"]\w{3,}' 2>$null
if ($vfy -or $cred) { Write-Host " FAIL" -ForegroundColor Red; $FAIL++ }
else { Write-Host " PASS" -ForegroundColor Green; $PASS++ }

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  PASS: $PASS  FAIL: $FAIL" -ForegroundColor $(if ($FAIL -gt 0) { "Red" } else { "Green" })
Write-Host "============================================" -ForegroundColor Cyan
exit $FAIL
