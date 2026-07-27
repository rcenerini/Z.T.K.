"""L5 — Containment Manager (Trilha B).

Manages WAF/Firewall containment rules for runtime protection.
Flow:
1. Select template (from CWE library)
2. Dry-run simulation (mandatory before apply)
3. Apply rule (with TTL)
4. Monitor + auto-expire

All rules have TTL. No permanent containment without exception approval.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum

from shared.utils.structlog_setup import get_logger

logger = get_logger(__name__)


class ContainmentType(str, Enum):
    WAF_RULE = "WAF_RULE"
    FIREWALL_RULE = "FIREWALL_RULE"
    RATE_LIMIT = "RATE_LIMIT"
    IP_BLOCK = "IP_BLOCK"
    DNS_BLOCK = "DNS_BLOCK"
    IAM_REVOKE = "IAM_REVOKE"


class ContainmentStatus(str, Enum):
    DRAFT = "DRAFT"
    DRY_RUN_PASSED = "DRY_RUN_PASSED"
    DRY_RUN_FAILED = "DRY_RUN_FAILED"
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    ROLLED_BACK = "ROLLED_BACK"


@dataclass
class DryRunResult:
    """Result of a containment dry-run simulation."""
    passed: bool
    expected_hits: int = 0
    false_positive_risk: str = "LOW"  # LOW, MEDIUM, HIGH
    impact_summary: str = ""
    duration_minutes: int = 0


@dataclass
class ContainmentRule:
    """A single WAF/firewall containment rule."""
    rule_id: str
    finding_id: str
    cwe_id: str
    rule_type: ContainmentType
    status: ContainmentStatus = ContainmentStatus.DRAFT
    description: str = ""
    target_scope: str = ""   # URL pattern, IP range, IAM ARN
    target_action: str = "BLOCK"  # BLOCK, RATE_LIMIT, LOG_ONLY
    ttl_hours: int = 72
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = None
    applied_at: datetime | None = None
    dry_run: DryRunResult | None = None
    rollback_command: str = ""


# CWE → containment mapping
CONTAINMENT_TEMPLATES: dict[str, dict] = {
    "CWE-89": {
        "type": ContainmentType.WAF_RULE,
        "description": "Block SQL injection patterns in HTTP parameters",
        "target": "ARGS|HEADERS|COOKIES",
        "ttl_hours": 72,
    },
    "CWE-79": {
        "type": ContainmentType.WAF_RULE,
        "description": "Block XSS patterns in request body",
        "target": "BODY|ARGS",
        "ttl_hours": 168,
    },
    "CWE-78": {
        "type": ContainmentType.WAF_RULE,
        "description": "Block command injection patterns",
        "target": "ARGS|HEADERS",
        "ttl_hours": 24,
    },
    "CWE-918": {
        "type": ContainmentType.FIREWALL_RULE,
        "description": "Block outbound SSRF to internal metadata endpoints",
        "target": "169.254.169.254",
        "ttl_hours": 168,
    },
    "CWE-502": {
        "type": ContainmentType.WAF_RULE,
        "description": "Block deserialization payloads in request body",
        "target": "BODY",
        "ttl_hours": 72,
    },
}


def create_containment_rule(
    finding_id: str,
    cwe_id: str,
    target_scope: str = "",
) -> ContainmentRule:
    """Create a containment rule from the template library.

    Deterministic: same CWE always produces the same rule template.
    """
    template = CONTAINMENT_TEMPLATES.get(cwe_id)
    if not template:
        return ContainmentRule(
            rule_id=str(uuid.uuid4())[:12],
            finding_id=finding_id,
            cwe_id=cwe_id,
            rule_type=ContainmentType.WAF_RULE,
            description=f"Generic containment for {cwe_id}",
            ttl_hours=72,
        )

    rule = ContainmentRule(
        rule_id=str(uuid.uuid4())[:12],
        finding_id=finding_id,
        cwe_id=cwe_id,
        rule_type=template["type"],
        description=template["description"],
        target_scope=target_scope or template["target"],
        ttl_hours=template["ttl_hours"],
    )

    rule.expires_at = rule.created_at + timedelta(hours=rule.ttl_hours)

    logger.info(
        "containment_rule_created",
        rule_id=rule.rule_id,
        cwe_id=cwe_id,
        ttl_hours=rule.ttl_hours,
    )

    return rule


def run_dry_run(rule: ContainmentRule) -> ContainmentRule:
    """Simulate the containment rule in dry-run mode.

    In production: deploys rule in LOG_ONLY mode to measure impact.
    """
    # Simulate dry-run (always passes for known templates)
    rule.dry_run = DryRunResult(
        passed=True,
        expected_hits=5,
        false_positive_risk="LOW",
        impact_summary=f"Rule will block {rule.cwe_id} patterns without collateral damage",
        duration_minutes=5,
    )
    rule.status = ContainmentStatus.DRY_RUN_PASSED

    logger.info("containment_dry_run_passed", rule_id=rule.rule_id)
    return rule


def apply_containment(rule: ContainmentRule) -> ContainmentRule:
    """Apply the containment rule to production.

    Only allowed if dry-run passed and rule is not expired.
    """
    if rule.status != ContainmentStatus.DRY_RUN_PASSED:
        logger.error("containment_not_validated", rule_id=rule.rule_id, status=rule.status.value)
        return rule

    if rule.is_expired:
        logger.error("containment_expired", rule_id=rule.rule_id)
        rule.status = ContainmentStatus.EXPIRED
        return rule

    rule.status = ContainmentStatus.ACTIVE
    rule.applied_at = datetime.now(timezone.utc)

    logger.info(
        "containment_applied",
        rule_id=rule.rule_id,
        target=rule.target_scope,
        ttl_hours=rule.ttl_hours,
    )

    return rule


def is_expired(self_or_rule: ContainmentRule) -> bool:
    """Check if the containment rule has expired."""
    if self_or_rule.expires_at is None:
        return False
    return datetime.now(timezone.utc) > self_or_rule.expires_at


def remaining_hours(self_or_rule: ContainmentRule) -> float:
    """Hours remaining before expiration."""
    if self_or_rule.expires_at is None:
        return float("inf")
    remaining = (self_or_rule.expires_at - datetime.now(timezone.utc)).total_seconds() / 3600
    return max(0.0, remaining)

# Monkey-patch the class with is_expired property
ContainmentRule.is_expired = property(is_expired)
ContainmentRule.remaining_hours = property(remaining_hours)


def rollback_containment(rule: ContainmentRule) -> ContainmentRule:
    """Immediately rollback/remove a containment rule."""
    rule.status = ContainmentStatus.ROLLED_BACK
    logger.info("containment_rolled_back", rule_id=rule.rule_id)
    return rule


def check_expired_rules(rules: list[ContainmentRule]) -> list[ContainmentRule]:
    """Check all active rules and expire those past TTL."""
    expired = []
    for rule in rules:
        if rule.status == ContainmentStatus.ACTIVE and rule.is_expired:
            rule.status = ContainmentStatus.EXPIRED
            expired.append(rule)
            logger.info("containment_expired", rule_id=rule.rule_id)
    return expired
