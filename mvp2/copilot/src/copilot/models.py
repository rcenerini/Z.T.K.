"""Copilot data models — Pydantic v2 schemas for the ATTEND tier LLM copilot.

All models use strict validation. No defaults for security-critical fields.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Annotated, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator, model_validator


class AnalysisTier(str, Enum):
    """Tier classification matching the Decision Engine output."""
    ATTEND = "ATTEND"
    TRACK = "TRACK"
    TRACK_STAR = "TRACK_STAR"
    ACT_3 = "ACT_3"
    ACT_14 = "ACT_14"


class Severity(str, Enum):
    """Normalised severity scale (P0 = critical, P4 = informational)."""
    P0 = "P0"
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


class Confidence(str, Enum):
    """LLM confidence level."""
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class AmbiguityType(str, Enum):
    """Types of ambiguity the copilot can detect."""
    VERSION_CONFLICT = "VERSION_CONFLICT"
    MISSING_CONTEXT = "MISSING_CONTEXT"
    CONTRADICTORY_EVIDENCE = "CONTRADICTORY_EVIDENCE"
    UNCHARTED_CWE = "UNCHARTED_CWE"
    FALSE_POSITIVE_RISK = "FALSE_POSITIVE_RISK"


class FindingContext(BaseModel):
    """Input from Decision Engine that triggers copilot analysis."""
    finding_id: Annotated[UUID, Field(description="Unique finding identifier")]
    tenant_id: Annotated[str, Field(min_length=1, description="Tenant identifier")]
    source: Annotated[str, Field(min_length=1, description="Source tool (Tenable, Semgrep, etc.)")]
    severity: Severity
    cwe_ids: Annotated[list[str], Field(min_length=1, description="CWE identifiers")]
    file_path: Annotated[str, Field(min_length=1, description="Affected file path")]
    line_number: Annotated[int, Field(ge=1)]
    description: Annotated[str, Field(min_length=10, description="Finding description")]
    evidence: Annotated[str, Field(min_length=1, description="Raw evidence (code snippet, log)")]
    decision_tier: AnalysisTier
    score: Annotated[float, Field(ge=0.0, le=10.0, description="Decision engine score 0-10")]
    cvss_vector: Annotated[Optional[str], Field(default=None, pattern=r"^CVSS:4\.0/.*")]
    language: Annotated[Optional[str], Field(default=None, min_length=1)]
    related_findings: Annotated[list[UUID], Field(default_factory=list)]
    metadata: Annotated[dict[str, str], Field(default_factory=dict)]

    @field_validator("finding_id", mode="before")
    @classmethod
    def coerce_uuid(cls, v: object) -> UUID:
        if isinstance(v, UUID):
            return v
        try:
            return UUID(str(v))
        except (ValueError, TypeError):
            raise ValueError("finding_id must be a valid UUID") from None


class CopilotAnalysis(BaseModel):
    """Output of the LLM copilot for a single finding."""
    analysis_id: Annotated[UUID, Field(default_factory=uuid4)]
    finding_id: UUID
    tier_requested: AnalysisTier
    tier_actual: AnalysisTier
    model_used: Annotated[str, Field(min_length=3, description="Model ID used for analysis")]
    confidence: Confidence
    summary: Annotated[str, Field(min_length=20, max_length=2000)]
    recommendation: Annotated[str, Field(min_length=10, max_length=3000)]
    ambiguity_signals: Annotated[list[AmbiguitySignal], Field(default_factory=list)]
    rag_hits: Annotated[int, Field(ge=0, description="Number of RAG documents retrieved")]
    rag_relevant: Annotated[int, Field(ge=0, description="Number of RAG docs deemed relevant by LLM")]
    prompt_version: Annotated[str, Field(min_length=1)]
    processing_time_ms: Annotated[int, Field(ge=0)]
    timestamp: Annotated[datetime, Field(default_factory=lambda: datetime.now(timezone.utc))]
    escalation_required: Annotated[bool, Field(default=False, description="True if Sonnet escalation needed")]
    raw_response: Annotated[Optional[str], Field(default=None, description="Full LLM response (for audit)")]

    @model_validator(mode="after")
    def check_rag_consistency(self) -> CopilotAnalysis:
        if self.rag_relevant > self.rag_hits:
            raise ValueError("rag_relevant cannot exceed rag_hits")
        return self


class AmbiguitySignal(BaseModel):
    """Signal detected by the copilot indicating uncertainty."""
    signal_type: AmbiguityType
    description: Annotated[str, Field(min_length=10, max_length=1000)]
    severity_impact: Annotated[str, Field(min_length=1, description="How this affects severity assessment")]
    suggested_action: Annotated[str, Field(min_length=10, max_length=1000)]
    confidence: Confidence


class CopilotRequest(BaseModel):
    """Request envelope for the copilot handler."""
    request_id: Annotated[UUID, Field(default_factory=uuid4)]
    finding: FindingContext
    force_model: Annotated[Optional[str], Field(default=None, description="Override model selection")]
    shadow_mode: Annotated[bool, Field(default=True, description="Read-only mode (no side effects)")]
    timestamp: Annotated[datetime, Field(default_factory=lambda: datetime.now(timezone.utc))]


class CopilotResponse(BaseModel):
    """Response envelope from the copilot handler."""
    request_id: UUID
    finding_id: UUID
    analysis: Optional[CopilotAnalysis]
    error: Optional[str]
    shadow_mode: bool
    escalation_triggered: bool
    processing_time_ms: int
    timestamp: datetime
