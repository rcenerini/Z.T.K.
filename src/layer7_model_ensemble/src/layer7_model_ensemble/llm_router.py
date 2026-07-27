"""L7 — Model Ensemble: Data Scope Classifier + LLM Router.

Determines whether a request must go to vLLM local (PCI/PII) or can use Bedrock.
Enforces data sovereignty (ADR-002).

Rules (non-negotiable):
- data_scope=PCI → provider=vllm_local (NEVER Bedrock)
- data_scope=PII → provider=vllm_local (preferred)
- data_scope=NON_PCI → provider=bedrock (allowed)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from shared.utils.fail_closed import fail_closed
from shared.utils.structlog_setup import get_logger

logger = get_logger(__name__)


class DataScope(str, Enum):
    NON_PCI = "non_pci"
    PCI = "pci"
    PII = "pii"
    PUBLIC = "public"


class LLMProvider(str, Enum):
    VLLM_LOCAL = "vllm_local"
    BEDROCK = "bedrock"


class LLMTier(str, Enum):
    VOLUME = "volume"        # Haiku / distilled (fast, cheap)
    REASONING = "reasoning"  # Sonnet / frontier (deep)
    GENERATION = "generation"  # Opus / ensemble (expensive)


# PCI data patterns (PAN, CHD indicators)
PAN_PATTERN = re.compile(
    r"\b[34]\d{3}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b"  # 16-digit PAN
    r"|\b\d{4}[ -]\d{6}[ -]\d{5}\b"                   # PAN with spaces
    r"|\b\d{4}\*{8}\d{4}\b"                           # Masked PAN
)

PII_PATTERNS = [
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),  # email
    re.compile(r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b"),  # CPF
    re.compile(r"\b\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}\b"),  # CNPJ
]


@dataclass
class RoutingDecision:
    """LLM routing decision."""
    request_id: str
    data_scope: DataScope
    provider: LLMProvider
    tier: LLMTier
    reason: str
    force_local: bool = False
    blocked: bool = False
    block_reason: str = ""


@dataclass
class CostMetrics:
    """LLM cost tracking."""
    total_requests: int = 0
    haiku_requests: int = 0
    sonnet_requests: int = 0
    total_cost_usd: float = 0.0
    budget_limit_usd: float = 100.0  # Monthly budget cap
    circuit_breaker_triggered: bool = False


# Pricing per 1K tokens (Claude 3.5 via Bedrock)
PRICING: dict[str, dict[str, float]] = {
    "haiku": {"input": 0.00025, "output": 0.00125},
    "sonnet": {"input": 0.003, "output": 0.015},
}


def classify_data_scope(content: str, context: dict | None = None) -> DataScope:
    """Classify data sensitivity for LLM routing.

    Deterministic: same content always produces same scope.
    """
    # Check for PAN patterns
    if PAN_PATTERN.search(content):
        logger.info("pan_detected", snippet=content[:50])
        return DataScope.PCI

    # Check for PII patterns
    for pattern in PII_PATTERNS:
        if pattern.search(content):
            logger.info("pii_detected")
            return DataScope.PII

    # Context hints
    if context:
        if context.get("pci_scope"):
            return DataScope.PCI
        if context.get("pii_scope"):
            return DataScope.PII

    return DataScope.NON_PCI


@fail_closed(
    fallback_value=RoutingDecision(
        request_id="fail_closed", data_scope=DataScope.PCI,
        provider=LLMProvider.VLLM_LOCAL, tier=LLMTier.VOLUME,
        reason="Router failed — defaulting to vLLM local (safe)", blocked=True,
        block_reason="Router unavailable — fail-closed to local"
    ),
    fallback_message="LLM router failed — routing to vLLM local"
)
def route_llm_request(
    request_id: str,
    content: str,
    context: dict | None = None,
    force_local: bool = False,
) -> RoutingDecision:
    """Route an LLM request to the appropriate provider.

    NEVER routes PCI/PII to Bedrock. This is a hard constraint.
    """
    scope = classify_data_scope(content, context)

    # Determine provider
    if scope in (DataScope.PCI, DataScope.PII) or force_local:
        provider = LLMProvider.VLLM_LOCAL
        reason = f"Data scope={scope.value} → vLLM local (mandatory)"
    else:
        provider = LLMProvider.BEDROCK
        reason = f"Data scope={scope.value} → Bedrock (allowed)"

    # Block PCI → Bedrock attempts (should never happen due to Pydantic validator)
    if scope == DataScope.PCI and provider == LLMProvider.BEDROCK:
        return RoutingDecision(
            request_id=request_id, data_scope=scope, provider=LLMProvider.VLLM_LOCAL,
            tier=LLMTier.VOLUME, reason="PCI data blocked from Bedrock — rerouted to local",
            force_local=True, blocked=True, block_reason="PCI → Bedrock blocked by data_sovereignty policy"
        )

    # Determine tier
    tier = LLMTier.VOLUME
    if scope == DataScope.PCI:
        tier = LLMTier.REASONING  # PCI deserves deep analysis
    elif "debate" in str(context or {}).lower():
        tier = LLMTier.REASONING

    logger.info(
        "llm_routed",
        request_id=request_id[:8],
        scope=scope.value,
        provider=provider.value,
        tier=tier.value,
    )

    return RoutingDecision(
        request_id=request_id, data_scope=scope, provider=provider,
        tier=tier, reason=reason, force_local=force_local,
    )


# ── Cost Monitor + Circuit Breaker ────────────────────────────────

_cost_metrics = CostMetrics()


def estimate_cost(
    input_tokens: int,
    output_tokens: int,
    model: str = "haiku",
) -> float:
    """Estimate cost for an LLM request."""
    pricing = PRICING.get(model, PRICING["haiku"])
    return (input_tokens * pricing["input"] + output_tokens * pricing["output"]) / 1000


def track_cost(
    input_tokens: int,
    output_tokens: int,
    model: str = "haiku",
    budget_limit_usd: float = 100.0,
) -> tuple[float, bool]:
    """Track cumulative LLM cost and check circuit breaker.

    Returns (cost_usd, circuit_breaker_triggered).
    """
    cost = estimate_cost(input_tokens, output_tokens, model)
    _cost_metrics.total_requests += 1
    _cost_metrics.total_cost_usd += cost

    if model == "haiku":
        _cost_metrics.haiku_requests += 1
    else:
        _cost_metrics.sonnet_requests += 1

    # Circuit breaker: 80% warning, 100% block
    budget_pct = (_cost_metrics.total_cost_usd / budget_limit_usd) * 100

    if budget_pct >= 100.0:
        _cost_metrics.circuit_breaker_triggered = True
        logger.error("circuit_breaker_triggered", cost_usd=_cost_metrics.total_cost_usd, budget=budget_limit_usd)
        return cost, True

    if budget_pct >= 80.0:
        logger.warning("budget_warning", cost_pct=round(budget_pct, 1))

    return cost, False


def get_cost_metrics() -> CostMetrics:
    """Return current cost metrics."""
    return _cost_metrics
