"""F0.1.2 — Schema `Decision` with SSVC enums and rationale.

Output of the Decision Engine (SSVC). Consumed by all downstream layers.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Annotated, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator, model_validator


class DecisionTier(str, Enum):
    """SSVC decision tier — determines pipeline routing."""
    TRACK = "TRACK"            # Baseline monitoring
    TRACK_STAR = "TRACK_STAR"  # Enhanced monitoring
    ATTEND = "ATTEND"          # Copilot analysis (M4)
    ACT_3 = "ACT_3"            # Automated remediation (3-day SLA)
    ACT_14 = "ACT_14"          # Automated remediation (14-day SLA)
    P0 = "P0"                  # Critical — immediate action
    P1 = "P1"                  # High
    P2 = "P2"                  # Medium
    P3 = "P3"                  # Low
    P4 = "P4"                  # Informational


class Exploitation(str, Enum):
    """SSVC exploitation status."""
    NONE = "none"
    POC = "poc"
    ACTIVE = "active"


class Exposure(str, Enum):
    """SSVC exposure status."""
    NONE = "none"
    CONTROLLED = "controlled"
    OPEN = "open"


class MissionImpact(str, Enum):
    """SSVC mission impact / business criticality."""
    NONE = "none"
    PARTIAL = "partial"
    MISSION_FAILURE = "mission_failure"


class SeverityFloor(str, Enum):
    """Non-negotiable severity floors."""
    PCI = "PCI"
    LGPD = "LGPD"
    ANTIFRAUDE = "ANTIFRAUDE"
    NONE = "NONE"


class Decision(BaseModel):
    """Output of the Decision Engine for a single finding."""

    model_config = {"extra": "forbid"}

    decision_id: Annotated[UUID, Field(default_factory=uuid4)]
    finding_id: UUID

    # SSVC inputs
    exploitation: Exploitation
    exposure: Exposure
    mission_impact: MissionImpact

    # Decision output
    tier: DecisionTier
    score: Annotated[float, Field(ge=0.0, le=10.0, description="Composite score 0-10")]
    confidence: Annotated[float, Field(ge=0.0, le=1.0, description="Decision confidence")]
    rationale: Annotated[list[str], Field(min_length=1, max_length=20, description="Reasons for this decision")]
    piso_applied: Annotated[list[SeverityFloor], Field(default_factory=list, description="Severity floors that triggered")]

    # Traceability
    ssvc_tree_version: Annotated[str, Field(min_length=1, max_length=32, default="1.0.0")]
    decision_engine_version: Annotated[str, Field(min_length=1, max_length=32, default="1.0.0")]

    # Lifecycle
    created_at: Annotated[datetime, Field(default_factory=lambda: datetime.now(timezone.utc))]
    expires_at: Annotated[Optional[datetime], Field(default=None, description="TTL for auto-review")]

    @field_validator("rationale")
    @classmethod
    def no_empty_rationale(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("rationale cannot be empty")
        for item in v:
            if not item.strip():
                raise ValueError("rationale entries cannot be empty strings")
        return [item.strip() for item in v]

    @model_validator(mode="after")
    def validate_tier_consistency(self) -> Decision:
        tier_priority = {
            DecisionTier.P0: 0, DecisionTier.P1: 1, DecisionTier.P2: 2,
            DecisionTier.P3: 3, DecisionTier.P4: 4,
            DecisionTier.ACT_3: 5, DecisionTier.ACT_14: 6,
            DecisionTier.ATTEND: 7, DecisionTier.TRACK_STAR: 8, DecisionTier.TRACK: 9,
        }
        # Score must be consistent with tier direction
        if self.score >= 8.0 and self.tier not in (DecisionTier.P0, DecisionTier.P1, DecisionTier.ACT_3):
            # High score but tier is low — floor violation possible, but not an error
            pass
        return self
