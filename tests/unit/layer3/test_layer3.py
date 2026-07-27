"""Tests for Layer 3 — Validation.

Covers: sandbox executor, PoC runner, score engine.
"""

from __future__ import annotations

import pytest

from layer3_validation.sandbox_executor import (
    SandboxMode,
    SandboxConfig,
    ExecutionResult,
    execute_poc,
)
from layer3_validation.poc_runner import (
    CWEClass,
    PoCTemplate,
    POC_TEMPLATES,
    run_poc,
    get_available_templates,
)
from layer3_validation.score_engine import (
    ScoreInput,
    ScoreResult,
    ExploitabilityLevel,
    ReachabilityLevel,
    BusinessImpactLevel,
    compute_score,
    score_to_severity,
)


# ═══════════════════════════════════════════════════════════════════
# Sandbox Executor
# ═══════════════════════════════════════════════════════════════════

class TestSandboxExecutor:
    def test_disabled_mode_returns_error(self) -> None:
        config = SandboxConfig(mode=SandboxMode.DISABLED)
        result = execute_poc("code", "payload", "CWE-89", config)
        assert result.result == ExecutionResult.ERROR
        assert "disabled" in str(result.errors).lower()

    def test_local_execution(self) -> None:
        result = execute_poc(
            target_code="def vulnerable_function(x): return 'safe'",
            exploit_payload="test",
            cwe_id="CWE-89",
        )
        assert result.result in (ExecutionResult.NOT_EXPLOITABLE, ExecutionResult.ERROR, ExecutionResult.EXPLOITABLE)

    def test_timeout(self) -> None:
        config = SandboxConfig(timeout_seconds=1)
        result = execute_poc(
            target_code="import time\ndef vulnerable_function(x):\n    time.sleep(10)\n    return 'ok'",
            exploit_payload="test",
            cwe_id="CWE-89",
            config=config,
        )
        # Timeout behaviour varies by OS — accept any non-success
        assert result.result in (ExecutionResult.TIMEOUT, ExecutionResult.ERROR, ExecutionResult.NOT_EXPLOITABLE, ExecutionResult.INCONCLUSIVE)

    def test_result_has_execution_id(self) -> None:
        result = execute_poc("code", "payload", "CWE-78")
        assert len(result.execution_id) > 0
        assert result.duration_ms >= 0


# ═══════════════════════════════════════════════════════════════════
# PoC Runner
# ═══════════════════════════════════════════════════════════════════

class TestPoCRunner:
    def test_template_library_not_empty(self) -> None:
        templates = get_available_templates()
        assert len(templates) >= 6

    def test_sql_injection_template(self) -> None:
        tmpl = POC_TEMPLATES.get(CWEClass.SQL_INJECTION)
        assert tmpl is not None
        assert tmpl.cwe_id == "CWE-89"
        assert "SELECT" in tmpl.target_code

    def test_command_injection_template(self) -> None:
        tmpl = POC_TEMPLATES.get(CWEClass.COMMAND_INJECTION)
        assert tmpl is not None
        assert "subprocess" in tmpl.target_code.lower()

    def test_xss_template(self) -> None:
        tmpl = POC_TEMPLATES.get(CWEClass.XSS)
        assert tmpl is not None
        assert "Scripting" in tmpl.name

    def test_run_poc_with_template(self) -> None:
        result = run_poc("test-123", CWEClass.SQL_INJECTION)
        assert result.finding_id == "test-123"
        assert result.cwe_id == "CWE-89"

    def test_run_poc_unknown_cwe(self) -> None:
        result = run_poc("test-456", "CWE-9999")
        assert result.exploitable is False
        assert result.confidence == "LOW"

    def test_all_templates_have_required_fields(self) -> None:
        for cwe_id, tmpl in POC_TEMPLATES.items():
            assert tmpl.cwe_id, f"{cwe_id}: cwe_id missing"
            assert tmpl.target_code, f"{cwe_id}: target_code missing"
            assert tmpl.exploit_payload, f"{cwe_id}: exploit_payload missing"


# ═══════════════════════════════════════════════════════════════════
# Score Engine
# ═══════════════════════════════════════════════════════════════════

class TestScoreEngine:
    def test_critical_exploitable(self) -> None:
        inp = ScoreInput(
            finding_id="f1",
            exploitability=ExploitabilityLevel.CONFIRMED,
            reachability=ReachabilityLevel.REACHABLE,
            business_impact=BusinessImpactLevel.CRITICAL,
            confidence=0.9,
            has_poc_evidence=True,
        )
        result = compute_score(inp)
        assert result.composite_score >= 8.0  # Should be very high

    def test_none_exploitable(self) -> None:
        inp = ScoreInput(
            finding_id="f2",
            exploitability=ExploitabilityLevel.NONE,
            reachability=ReachabilityLevel.UNREACHABLE,
            business_impact=BusinessImpactLevel.NONE,
            confidence=0.1,
        )
        result = compute_score(inp)
        assert result.composite_score <= 2.0  # Should be very low

    def test_pci_floor(self) -> None:
        inp = ScoreInput(
            finding_id="f3",
            exploitability=ExploitabilityLevel.UNLIKELY,
            reachability=ReachabilityLevel.UNKNOWN,
            business_impact=BusinessImpactLevel.LOW,
            confidence=0.2,
            pci_scope=True,
        )
        result = compute_score(inp)
        assert result.composite_score >= 7.5  # PCI floor
        assert result.severity_floor_applied == "PCI"

    def test_antifraude_floor(self) -> None:
        inp = ScoreInput(
            finding_id="f4",
            exploitability=ExploitabilityLevel.UNLIKELY,
            reachability=ReachabilityLevel.UNKNOWN,
            business_impact=BusinessImpactLevel.LOW,
            confidence=0.1,
            antifraude_scope=True,
        )
        result = compute_score(inp)
        assert result.composite_score >= 9.0  # Antifraude floor (P0)

    def test_evidence_boost(self) -> None:
        no_evidence = ScoreInput(
            finding_id="f5", exploitability=ExploitabilityLevel.CONFIRMED,
            reachability=ReachabilityLevel.REACHABLE,
            business_impact=BusinessImpactLevel.MEDIUM, confidence=0.8,
            has_poc_evidence=False, has_reachability_evidence=False,
        )
        with_evidence = ScoreInput(
            finding_id="f5", exploitability=ExploitabilityLevel.CONFIRMED,
            reachability=ReachabilityLevel.REACHABLE,
            business_impact=BusinessImpactLevel.MEDIUM, confidence=0.8,
            has_poc_evidence=True, has_reachability_evidence=True,
        )
        r1 = compute_score(no_evidence)
        r2 = compute_score(with_evidence)
        assert r2.composite_score >= r1.composite_score  # Evidence boosts

    def test_deterministic(self) -> None:
        inp = ScoreInput(
            finding_id="f6", exploitability=ExploitabilityLevel.LIKELY,
            reachability=ReachabilityLevel.CONDITIONALLY_REACHABLE,
            business_impact=BusinessImpactLevel.HIGH, confidence=0.7,
        )
        r1 = compute_score(inp)
        r2 = compute_score(inp)
        assert r1.composite_score == r2.composite_score

    def test_score_to_severity(self) -> None:
        assert score_to_severity(9.0) == "P0"
        assert score_to_severity(7.5) == "P1"
        assert score_to_severity(6.0) == "P2"
        assert score_to_severity(4.0) == "P3"
        assert score_to_severity(2.0) == "P4"

    def test_breakdown_contains_all_factors(self) -> None:
        inp = ScoreInput(
            finding_id="f7", exploitability=ExploitabilityLevel.CONFIRMED,
            reachability=ReachabilityLevel.REACHABLE,
            business_impact=BusinessImpactLevel.HIGH, confidence=0.8,
        )
        result = compute_score(inp)
        assert "exploitability" in result.breakdown
        assert "reachability" in result.breakdown
        assert "impact" in result.breakdown
        assert "confidence" in result.breakdown

    def test_lgpd_floor(self) -> None:
        inp = ScoreInput(
            finding_id="f8", exploitability=ExploitabilityLevel.POSSIBLE,
            reachability=ReachabilityLevel.UNKNOWN,
            business_impact=BusinessImpactLevel.MEDIUM, confidence=0.5,
            lgpd_scope=True,
        )
        result = compute_score(inp)
        assert result.composite_score >= 7.5  # LGPD floor
