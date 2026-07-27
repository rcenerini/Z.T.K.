"""F0.1.3 — Schema `AuditEvent` with idempotency key (SHA-256).

All state changes across all layers produce an AuditEvent.
Idempotent by (finding_id, stage, payload_hash).
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Annotated, Any, Optional
from uuid import UUID

from pydantic import BaseModel, Field, field_validator


class AuditStage(str, Enum):
    """Pipeline stage that generated the event."""
    INGESTION = "INGESTION"
    NORMALIZATION = "NORMALIZATION"
    ENRICHMENT = "ENRICHMENT"
    SCORING = "SCORING"
    DECISION = "DECISION"
    ANALYSIS = "ANALYSIS"
    VALIDATION = "VALIDATION"
    CONSENSUS = "CONSENSUS"
    REMEDIATION = "REMEDIATION"
    GOVERNANCE = "GOVERNANCE"
    EXCEPTION = "EXCEPTION"
    ENSEMBLE = "ENSEMBLE"
    SCALE = "SCALE"
    HITL = "HITL"
    KILL_SWITCH = "KILL_SWITCH"
    SYSTEM = "SYSTEM"


class AuditAction(str, Enum):
    """Action performed at this stage."""
    CREATED = "CREATED"
    UPDATED = "UPDATED"
    ENRICHED = "ENRICHED"
    SCORED = "SCORED"
    DECIDED = "DECIDED"
    ANALYSED = "ANALYSED"
    VALIDATED = "VALIDATED"
    ESCALATED = "ESCALATED"
    REMEDIATED = "REMEDIATED"
    CONTAINED = "CONTAINED"
    EXCEPTION_REQUESTED = "EXCEPTION_REQUESTED"
    EXCEPTION_APPROVED = "EXCEPTION_APPROVED"
    EXCEPTION_REJECTED = "EXCEPTION_REJECTED"
    EXCEPTION_EXPIRED = "EXCEPTION_EXPIRED"
    KILL_SWITCH_ACTIVATED = "KILL_SWITCH_ACTIVATED"
    SHADOW_MODE_PROMOTED = "SHADOW_MODE_PROMOTED"
    ERROR = "ERROR"
    ROLLBACK = "ROLLBACK"


class AuditEvent(BaseModel):
    """Immutable audit event for compliance and traceability.

    Idempotency: (finding_id, stage, payload_hash) must be unique.
    Deterministic event_id via SHA-256 of the trinca.
    """

    model_config = {"extra": "forbid", "frozen": True}

    # Event identity (deterministic)
    event_id: Annotated[str, Field(min_length=64, max_length=64, description="SHA-256 hash of (finding_id, stage, payload_hash)")]
    finding_id: UUID
    stage: AuditStage
    action: AuditAction

    # Who
    agent_id: Annotated[str, Field(min_length=1, max_length=64)]
    tenant_id: Annotated[str, Field(min_length=1, max_length=64)]

    # What
    payload: Annotated[dict[str, Any], Field(default_factory=dict, description="Arbitrary payload (will be serialized to JSON for hashing)")]
    payload_hash: Annotated[str, Field(min_length=64, max_length=64, description="SHA-256 of canonical JSON payload")]
    previous_event_id: Annotated[Optional[str], Field(default=None, min_length=64, max_length=64)]

    # When
    timestamp: Annotated[datetime, Field(default_factory=lambda: datetime.now(timezone.utc))]

    # Metadata
    request_id: Annotated[Optional[UUID], Field(default=None)]
    correlation_id: Annotated[Optional[str], Field(default=None, max_length=64)]
    version: Annotated[str, Field(default="1.0.0", min_length=1, max_length=16)]

    @staticmethod
    def compute_event_id(finding_id: UUID, stage: str, payload_hash: str) -> str:
        """Deterministic SHA-256 over the idempotency trinca."""
        raw = f"{finding_id}:{stage}:{payload_hash}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    @staticmethod
    def compute_payload_hash(payload: dict[str, Any]) -> str:
        """SHA-256 of canonical JSON (sorted keys, no spaces)."""
        import json
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @field_validator("event_id")
    @classmethod
    def validate_hex(cls, v: str) -> str:
        try:
            int(v, 16)
        except ValueError:
            raise ValueError("event_id must be valid hex") from None
        return v
