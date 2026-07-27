"""Tests for Layer 8 — Scale.

Covers: Activation engine, shadow mode, tool lifecycle, multi-tenancy.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from layer8_scale.activation_engine import (
    AgentActivationRule,
    ActivationDecision,
    ShadowStatus,
    ShadowAgent,
    ToolStatus,
    ToolLifecycle,
    should_activate,
    evaluate_shadow_agent,
    check_tool_updates,
    validate_tenant_isolation,
    generate_tenant_cost_report,
)


# ═══════════════════════════════════════════════════════════════════
# Activation Engine
# ═══════════════════════════════════════════════════════════════════

class TestActivationEngine:
    def test_language_match(self) -> None:
        rule = AgentActivationRule(agent_id="L2.01", language="python")
        assert should_activate(rule, language="python") == ActivationDecision.ACTIVATED

    def test_language_mismatch(self) -> None:
        rule = AgentActivationRule(agent_id="L2.01", language="python")
        assert should_activate(rule, language="java") == ActivationDecision.SKIPPED

    def test_disabled_agent(self) -> None:
        rule = AgentActivationRule(agent_id="L2.01", language="python", enabled=False)
        assert should_activate(rule, language="python") == ActivationDecision.DISABLED

    def test_budget_limit(self) -> None:
        rule = AgentActivationRule(agent_id="L2.01", language="python", max_budget_tokens=1000)
        assert should_activate(rule, language="python", budget_available=500) == ActivationDecision.SKIPPED

    def test_budget_sufficient(self) -> None:
        rule = AgentActivationRule(agent_id="L2.01", language="python", max_budget_tokens=1000)
        assert should_activate(rule, language="python", budget_available=5000) == ActivationDecision.ACTIVATED

    def test_all_language_matches_any(self) -> None:
        rule = AgentActivationRule(agent_id="L2.28", language="all")
        assert should_activate(rule, language="python") == ActivationDecision.ACTIVATED
        assert should_activate(rule, language="java") == ActivationDecision.ACTIVATED


# ═══════════════════════════════════════════════════════════════════
# Shadow Mode
# ═══════════════════════════════════════════════════════════════════

class TestShadowMode:
    def test_new_agent_in_shadow(self) -> None:
        agent = ShadowAgent(agent_id="new-agent")
        assert agent.status == ShadowStatus.SHADOW

    def test_not_enough_days(self) -> None:
        agent = ShadowAgent(agent_id="new-agent")
        result = evaluate_shadow_agent(agent)
        assert result.status == ShadowStatus.SHADOW

    def test_promotion_criteria(self) -> None:
        agent = ShadowAgent(
            agent_id="ready-agent",
            activated_at=datetime.now(timezone.utc) - timedelta(days=31),
            total_runs=200,
            false_positives=5,  # 2.5% FPR
            avg_processing_time_ms=3000,
        )
        result = evaluate_shadow_agent(agent)
        assert result.status == ShadowStatus.PROMOTED
        assert result.promotion_criteria_met is True

    def test_high_fpr_rejected(self) -> None:
        agent = ShadowAgent(
            agent_id="noisy-agent",
            activated_at=datetime.now(timezone.utc) - timedelta(days=31),
            total_runs=100,
            false_positives=50,  # 50% FPR — too high
        )
        result = evaluate_shadow_agent(agent)
        assert result.status == ShadowStatus.REJECTED
        assert result.promotion_criteria_met is False


# ═══════════════════════════════════════════════════════════════════
# Tool Lifecycle
# ═══════════════════════════════════════════════════════════════════

class TestToolLifecycle:
    def test_no_update(self) -> None:
        tool = ToolLifecycle(tool_id="t1", name="Bandit", version="1.7.0")
        result = check_tool_updates(tool, "1.7.0")
        assert result.status == ToolStatus.ACTIVE

    def test_update_available(self) -> None:
        tool = ToolLifecycle(tool_id="t1", name="Bandit", version="1.7.0")
        result = check_tool_updates(tool, "1.8.0")
        assert result.status == ToolStatus.UPDATE_AVAILABLE
        assert result.latest_version == "1.8.0"

    def test_last_checked_updated(self) -> None:
        tool = ToolLifecycle(tool_id="t1", name="Bandit", version="1.0")
        result = check_tool_updates(tool)
        assert result.last_checked is not None


# ═══════════════════════════════════════════════════════════════════
# Multi-tenancy
# ═══════════════════════════════════════════════════════════════════

class TestMultiTenancy:
    def test_valid_tenant(self) -> None:
        ok, msg = validate_tenant_isolation("ztk-proj", {"ztk-proj", "ztk-dev"})
        assert ok is True

    def test_invalid_tenant(self) -> None:
        ok, msg = validate_tenant_isolation("evil-tenant", {"ztk-proj"})
        assert ok is False

    def test_empty_tenant_denied(self) -> None:
        ok, msg = validate_tenant_isolation("")
        assert ok is False

    def test_cost_report(self) -> None:
        report = generate_tenant_cost_report("ztk-proj", requests=100, tokens_used=50000, cost_usd=15.75)
        assert report["tenant_id"] == "ztk-proj"
        assert report["cost_usd"] == 15.75
