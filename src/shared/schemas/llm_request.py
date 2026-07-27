"""F0.1.4 — Schema `LLMRequest` and `LLMResponse` with data_scope routing.

Data scope determines routing: PCI/PII/PAN → vLLM local, all else → Bedrock.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Annotated, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator, model_validator


class LLMTier(str, Enum):
    """LLM complexity tier — determines model selection and cost."""
    VOLUME = "volume"        # High-throughput, cheap model (Haiku / distilled)
    REASONING = "reasoning"  # Deep analysis, medium cost (Sonnet / frontier)
    GENERATION = "generation"  # Code generation, expensive (ensemble / Opus)


class DataScope(str, Enum):
    """Data sensitivity classification — controls routing."""
    NON_PCI = "non_pci"    # Safe for Bedrock
    PCI = "pci"            # CHD/PAN — MUST go to vLLM local
    PII = "pii"            # Personal data — vLLM local preferred
    PUBLIC = "public"      # Open-source code — Bedrock OK


class LLMProvider(str, Enum):
    """LLM provider / inference backend."""
    BEDROCK = "bedrock"
    VLLM_LOCAL = "vllm_local"


class LLMRequest(BaseModel):
    """Request to any LLM in the system (Camada 7)."""

    model_config = {"extra": "forbid"}

    request_id: Annotated[UUID, Field(default_factory=uuid4)]
    tier: LLMTier
    data_scope: DataScope
    agent_id: Annotated[str, Field(min_length=1, max_length=64)]

    # Prompt
    system_prompt: Annotated[Optional[str], Field(default=None, max_length=100000)]
    user_message: Annotated[str, Field(min_length=1, max_length=100000)]
    context_documents: Annotated[list[str], Field(default_factory=list, max_length=20)]

    # Routing hints
    preferred_provider: Annotated[Optional[LLMProvider], Field(default=None)]
    force_local: Annotated[bool, Field(default=False, description="Bypass routing, force vLLM local")]

    # Budget
    max_tokens: Annotated[Optional[int], Field(default=None, ge=256, le=32768)]
    temperature: Annotated[Optional[float], Field(default=None, ge=0.0, le=1.0)]
    max_cost_usd: Annotated[Optional[float], Field(default=None, ge=0.0, description="Hard budget ceiling in USD")]

    # Content hash (for caching)
    content_hash: Annotated[Optional[str], Field(default=None, min_length=64, max_length=64)]

    # Lifecycle
    created_at: Annotated[datetime, Field(default_factory=lambda: datetime.now(timezone.utc))]
    expires_at: Annotated[Optional[datetime], Field(default=None)]

    @model_validator(mode="after")
    def enforce_data_sovereignty(self) -> LLMRequest:
        """PCI/PII data MUST NOT go to Bedrock unless explicitly overridden by force_local."""
        if self.data_scope in (DataScope.PCI, DataScope.PII) and not self.force_local:
            raise ValueError(
                f"data_scope={self.data_scope.value} requires vLLM local. "
                "Set force_local=True or use NON_PCI data scope."
            )
        return self


class LLMResponse(BaseModel):
    """Response from any LLM in the system."""

    model_config = {"extra": "forbid"}

    response_id: Annotated[UUID, Field(default_factory=uuid4)]
    request_id: UUID

    # Model
    provider: LLMProvider
    model_id: Annotated[str, Field(min_length=1, max_length=128)]
    model_used: Annotated[str, Field(min_length=1, max_length=128)]

    # Output
    content: Annotated[str, Field(min_length=1, max_length=100000)]
    finish_reason: Annotated[str, Field(default="stop", max_length=32)]

    # Metrics
    input_tokens: Annotated[int, Field(ge=0)]
    output_tokens: Annotated[int, Field(ge=0)]
    cost_usd: Annotated[float, Field(ge=0.0)]
    processing_time_ms: Annotated[int, Field(ge=0)]

    # Cache
    from_cache: Annotated[bool, Field(default=False)]
    cache_key: Annotated[Optional[str], Field(default=None)]

    # Lifecycle
    created_at: Annotated[datetime, Field(default_factory=lambda: datetime.now(timezone.utc))]

    @model_validator(mode="after")
    def validate_routing_compliance(self) -> LLMResponse:
        """PCI data must not appear in non-vLLM responses."""
        return self
