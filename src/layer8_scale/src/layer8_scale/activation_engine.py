"""L8 — Scale: Activation Engine, Shadow Mode, Tool Lifecycle, Multi-tenancy.

Final layer — controls which agents run, agent lifecycle, and tenant isolation.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum

from shared.utils.fail_closed import fail_closed
from shared.utils.structlog_setup import get_logger

logger = get_logger(__name__)


# ═══════════════════════════════════════════════════════════════════
# Activation Engine — Conditional Agent Execution
# ═══════════════════════════════════════════════════════════════════

@dataclass
class AgentActivationRule:
    """Rule for when an agent should be activated."""
    agent_id: str
    language: str | None = None
    file_patterns: list[str] = field(default_factory=list)
    min_criticality_score: float = 0.0
    max_budget_tokens: int = 0
    enabled: bool = True


class ActivationDecision(str, Enum):
    ACTIVATED = "ACTIVATED"
    SKIPPED = "SKIPPED"
    DISABLED = "DISABLED"


def should_activate(
    rule: AgentActivationRule,
    language: str | None = None,
    file_paths: list[str] | None = None,
    criticality_score: float = 5.0,
    budget_available: int = 100000,
) -> ActivationDecision:
    """Determine whether an agent should be activated for a given context.

    Deterministic: same inputs always produce same decision.
    """
    if not rule.enabled:
        return ActivationDecision.DISABLED

    # Language match
    if rule.language and language and rule.language != language and rule.language != "all":
        return ActivationDecision.SKIPPED

    # File pattern match (optional)
    if rule.file_patterns and file_paths:
        import fnmatch
        matched = any(
            fnmatch.fnmatch(fp, pat)
            for fp in file_paths
            for pat in rule.file_patterns
        )
        if not matched:
            return ActivationDecision.SKIPPED

    # Criticality threshold
    if criticality_score < rule.min_criticality_score:
        return ActivationDecision.SKIPPED

    # Budget check
    if rule.max_budget_tokens > 0 and budget_available < rule.max_budget_tokens:
        return ActivationDecision.SKIPPED

    return ActivationDecision.ACTIVATED


# ═══════════════════════════════════════════════════════════════════
# Shadow Mode — 30-day validation before promotion
# ═══════════════════════════════════════════════════════════════════

class ShadowStatus(str, Enum):
    SHADOW = "SHADOW"           # Running in parallel, read-only
    EVALUATING = "EVALUATING"   # 30-day period complete, metrics under review
    PROMOTED = "PROMOTED"       # Promoted to production
    REJECTED = "REJECTED"       # Failed validation


@dataclass
class ShadowAgent:
    """An agent in shadow mode."""
    agent_id: str
    status: ShadowStatus = ShadowStatus.SHADOW
    activated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    shadow_days_required: int = 30
    total_runs: int = 0
    findings_produced: int = 0
    false_positives: int = 0
    avg_processing_time_ms: int = 0
    promotion_criteria_met: bool = False


def evaluate_shadow_agent(agent: ShadowAgent) -> ShadowAgent:
    """Evaluate a shadow agent for promotion readiness.

    Criteria for promotion:
    - 30+ days in shadow mode
    - 100+ runs executed
    - False positive rate <5%
    - Avg processing time <10s
    """
    days_in_shadow = (datetime.now(timezone.utc) - agent.activated_at).days

    if days_in_shadow < agent.shadow_days_required:
        return agent

    agent.status = ShadowStatus.EVALUATING

    # Check promotion criteria
    checks = {
        "days": days_in_shadow >= 30,
        "runs": agent.total_runs >= 100,
        "fpr": (agent.false_positives / max(1, agent.total_runs)) < 0.05,
        "latency": agent.avg_processing_time_ms < 10000,
    }

    agent.promotion_criteria_met = all(checks.values())

    if agent.promotion_criteria_met:
        agent.status = ShadowStatus.PROMOTED
        logger.info("shadow_agent_promoted", agent_id=agent.agent_id, days=days_in_shadow)
    else:
        agent.status = ShadowStatus.REJECTED
        logger.info("shadow_agent_rejected", agent_id=agent.agent_id, checks=checks)

    return agent


# ═══════════════════════════════════════════════════════════════════
# Tool Lifecycle Manager
# ═══════════════════════════════════════════════════════════════════

class ToolStatus(str, Enum):
    ACTIVE = "ACTIVE"
    UPDATE_AVAILABLE = "UPDATE_AVAILABLE"
    DEPRECATED = "DEPRECATED"
    REMOVED = "REMOVED"


@dataclass
class ToolLifecycle:
    """Lifecycle tracking for a SAST tool."""
    tool_id: str
    name: str
    version: str
    status: ToolStatus = ToolStatus.ACTIVE
    last_checked: datetime | None = None
    latest_version: str = ""
    cve_count: int = 0  # Known CVEs in this tool version
    auto_update: bool = False


def check_tool_updates(tool: ToolLifecycle, latest_version: str = "") -> ToolLifecycle:
    """Check if a tool has updates available."""
    tool.last_checked = datetime.now(timezone.utc)

    if latest_version and latest_version != tool.version:
        tool.status = ToolStatus.UPDATE_AVAILABLE
        tool.latest_version = latest_version
        logger.info("tool_update_available", tool= tool.name, current=tool.version, latest=latest_version)

    return tool


# ═══════════════════════════════════════════════════════════════════
# Multi-tenancy Guard
# ═══════════════════════════════════════════════════════════════════

def validate_tenant_isolation(
    tenant_id: str,
    allowed_tenants: set[str] | None = None,
) -> tuple[bool, str]:
    """Validate that a tenant can only access its own data.

    Deterministic: same tenant_id always produces same result.
    """
    if not tenant_id or tenant_id.strip() == "":
        return False, "Empty tenant_id — access denied"

    if allowed_tenants and tenant_id not in allowed_tenants:
        return False, f"Tenant '{tenant_id}' not in allowed list"

    return True, "Tenant access allowed"


def generate_tenant_cost_report(
    tenant_id: str,
    requests: int = 0,
    tokens_used: int = 0,
    cost_usd: float = 0.0,
) -> dict:
    """Generate a per-tenant cost report."""
    return {
        "tenant_id": tenant_id,
        "period": datetime.now(timezone.utc).strftime("%Y-%m"),
        "requests": requests,
        "tokens_used": tokens_used,
        "cost_usd": round(cost_usd, 4),
    }
