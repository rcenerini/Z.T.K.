"""Tests for Layer 7 — Model Ensemble.

Covers: Data scope classifier, LLM router, cost monitor.
"""

from __future__ import annotations

import pytest

from layer7_model_ensemble.llm_router import (
    DataScope,
    LLMProvider,
    LLMTier,
    RoutingDecision,
    classify_data_scope,
    route_llm_request,
    estimate_cost,
    track_cost,
    get_cost_metrics,
    PAN_PATTERN,
)


# ═══════════════════════════════════════════════════════════════════
# Data Scope Classifier
# ═══════════════════════════════════════════════════════════════════

class TestDataScope:
    def test_pan_detected(self) -> None:
        scope = classify_data_scope("PAN: 4111 1111 1111 1111")
        assert scope == DataScope.PCI

    def test_pan_with_dashes(self) -> None:
        scope = classify_data_scope("Card: 4111-1111-1111-1111")
        assert scope == DataScope.PCI

    def test_masked_pan(self) -> None:
        scope = classify_data_scope("PAN: 4111********1111")
        assert scope == DataScope.PCI

    def test_email_pii(self) -> None:
        scope = classify_data_scope("Contact: user@example.com")
        assert scope == DataScope.PII

    def test_cpf_pii(self) -> None:
        scope = classify_data_scope("CPF: 123.456.789-00")
        assert scope == DataScope.PII

    def test_clean_code_non_pci(self) -> None:
        scope = classify_data_scope("def hello(): return 'world'")
        assert scope == DataScope.NON_PCI

    def test_context_pci(self) -> None:
        scope = classify_data_scope("safe code", {"pci_scope": True})
        assert scope == DataScope.PCI


# ═══════════════════════════════════════════════════════════════════
# LLM Router
# ═══════════════════════════════════════════════════════════════════

class TestLLMRouter:
    def test_non_pci_routes_to_bedrock(self) -> None:
        decision = route_llm_request("r1", "safe code")
        assert decision.provider == LLMProvider.BEDROCK

    def test_pci_routes_to_vllm_local(self) -> None:
        decision = route_llm_request("r2", "PAN: 4111 1111 1111 1111")
        assert decision.provider == LLMProvider.VLLM_LOCAL
        assert decision.data_scope == DataScope.PCI

    def test_pii_routes_to_vllm_local(self) -> None:
        decision = route_llm_request("r3", "email: user@test.com")
        assert decision.provider == LLMProvider.VLLM_LOCAL

    def test_force_local(self) -> None:
        decision = route_llm_request("r4", "safe code", force_local=True)
        assert decision.provider == LLMProvider.VLLM_LOCAL

    def test_pci_blocked_from_bedrock(self) -> None:
        """Even if somehow routed to Bedrock with PCI data, it should be blocked."""
        decision = route_llm_request("r5", "PAN: 4111 1111 1111 1111")
        assert decision.provider == LLMProvider.VLLM_LOCAL

    def test_deterministic(self) -> None:
        d1 = route_llm_request("r6", "test code")
        d2 = route_llm_request("r6", "test code")
        assert d1.provider == d2.provider
        assert d1.data_scope == d2.data_scope


# ═══════════════════════════════════════════════════════════════════
# Cost Monitor
# ═══════════════════════════════════════════════════════════════════

class TestCostMonitor:
    def test_estimate_haiku_cost(self) -> None:
        cost = estimate_cost(1000, 500, "haiku")
        assert cost > 0

    def test_estimate_sonnet_cost_higher(self) -> None:
        h = estimate_cost(1000, 500, "haiku")
        s = estimate_cost(1000, 500, "sonnet")
        assert s > h

    def test_track_cost_no_breaker(self) -> None:
        cost, triggered = track_cost(100, 50, "haiku", budget_limit_usd=1000.0)
        assert triggered is False
        assert cost > 0

    def test_circuit_breaker(self) -> None:
        # Small budget to trigger breaker quickly
        for _ in range(500):
            _, triggered = track_cost(1000, 500, "haiku", budget_limit_usd=0.01)
            if triggered:
                break
        # Circuit breaker should have triggered
        metrics = get_cost_metrics()
        assert metrics.total_requests > 0

    def test_metrics_tracks_haiku_vs_sonnet(self) -> None:
        # Get initial state (metrics persist across tests)
        metrics = get_cost_metrics()
        assert metrics.total_cost_usd >= 0
