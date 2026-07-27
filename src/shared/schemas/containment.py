"""F0.1.5 — Schema `ContainmentRule` with TTL and dry-run support.

Remediation Camada 5, Trilha B: WAF/Firewall containment rules.
All containment rules MUST have TTL and MUST pass dry-run before apply.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Annotated, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator, model_validator


class ContainmentType(str, Enum):
    """Type of containment action."""
    WAF_RULE = "WAF_RULE"
    FIREWALL_RULE = "FIREWALL_RULE"
    RATE_LIMIT = "RATE_LIMIT"
    IP_BLOCK = "IP_BLOCK"
    DNS_BLOCK = "DNS_BLOCK"
    IAM_REVOKE = "IAM_REVOKE"
    KUBERNETES_NETWORK_POLICY = "KUBERNETES_NETWORK_POLICY"


class ContainmentStatus(str, Enum):
    """Lifecycle of a containment rule."""
    PROPOSED = "PROPOSED"
    DRY_RUN_PASSED = "DRY_RUN_PASSED"
    DRY_RUN_FAILED = "DRY_RUN_FAILED"
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    ROLLED_BACK = "ROLLED_BACK"


class DryRunResult(BaseModel):
    """Result of a containment dry-run simulation."""
    passed: bool
    expected_matches: Annotated[int, Field(ge=0)]
    false_positive_risk: Annotated[str, Field(min_length=1, description="LOW|MEDIUM|HIGH")]
    impact_summary: Annotated[str, Field(min_length=5, max_length=2000)]
    logs: Annotated[list[str], Field(default_factory=list)]
    duration_ms: Annotated[int, Field(ge=0)]


class ContainmentRule(BaseModel):
    """Containment rule for WAF/Firewall/IAM.

    Design constraints:
    - TTL mandatory — no permanent containment without exception approval
    - Dry-run mandatory before apply
    - Audit trail preserved
    - Kill-switch compatible
    """

    model_config = {"extra": "forbid"}

    rule_id: Annotated[UUID, Field(default_factory=uuid4)]
    finding_id: UUID
    tenant_id: Annotated[str, Field(min_length=1, max_length=64)]

    # What
    rule_type: ContainmentType
    cwe_ids: Annotated[list[str], Field(min_length=1, max_length=10)]
    description: Annotated[str, Field(min_length=10, max_length=2000)]

    # Target
    target_scope: Annotated[str, Field(min_length=1, max_length=256, description="IP range, URL pattern, IAM role ARN, etc.")]
    target_action: Annotated[str, Field(default="BLOCK", min_length=1, max_length=32, description="BLOCK, RATE_LIMIT, LOG_ONLY")]

    # Lifecycle (TTL mandatory)
    ttl_hours: Annotated[int, Field(ge=1, le=8784, description="Time-to-live in hours (max 1 year). Must be >= 1.")]
    created_at: Annotated[datetime, Field(default_factory=lambda: datetime.now(timezone.utc))]
    expires_at: Annotated[datetime, Field(default=None, description="Computed: created_at + ttl_hours")]
    status: Annotated[ContainmentStatus, Field(default=ContainmentStatus.PROPOSED)]

    # Dry-run (mandatory before apply)
    dry_run_result: Annotated[Optional[DryRunResult], Field(default=None)]

    # Audit
    applied_by: Annotated[Optional[str], Field(default=None, max_length=64)]
    applied_at: Annotated[Optional[datetime], Field(default=None)]
    revoked_by: Annotated[Optional[str], Field(default=None, max_length=64)]
    revoked_at: Annotated[Optional[datetime], Field(default=None)]
    revoked_reason: Annotated[Optional[str], Field(default=None, max_length=1000)]

    # Kill-switch
    kill_switch_compatible: Annotated[bool, Field(default=True)]
    kill_switch_authority: Annotated[str, Field(default="SOC", max_length=32)]

    # Rollback
    rollback_rule: Annotated[Optional[str], Field(default=None, max_length=2000, description="How to reverse this rule")]
    rollback_verified: Annotated[bool, Field(default=False)]

    @model_validator(mode="after")
    def compute_expiration(self) -> ContainmentRule:
        if self.created_at:
            self.expires_at = self.created_at + timedelta(hours=self.ttl_hours)
        return self

    @model_validator(mode="after")
    def validate_dry_run_before_active(self) -> ContainmentRule:
        if self.status == ContainmentStatus.ACTIVE and self.dry_run_result is None:
            raise ValueError("Cannot activate containment rule without dry-run result")
        if self.status == ContainmentStatus.ACTIVE and not self.dry_run_result.passed:
            raise ValueError("Cannot activate containment rule that failed dry-run")
        return self

    @property
    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at

    @property
    def remaining_hours(self) -> float:
        if self.expires_at is None:
            return float("inf")
        remaining = (self.expires_at - datetime.now(timezone.utc)).total_seconds() / 3600
        return max(0.0, remaining)
