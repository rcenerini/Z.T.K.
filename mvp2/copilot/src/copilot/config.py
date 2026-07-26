"""Copilot configuration — env-var-driven settings.

All secrets come from environment variables. NEVER hardcode credentials.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class CopilotSettings(BaseSettings):
    """All copilot configuration via environment variables."""

    model_config = SettingsConfigDict(
        env_prefix="COPILOT_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="forbid",
    )

    # Bedrock / LLM
    bedrock_region: str = Field(
        default="us-east-1",
        description="AWS region for Bedrock runtime",
    )
    bedrock_haiku_model: str = Field(
        default="anthropic.claude-3-5-haiku-20241022-v1:0",
        description="Bedrock model ID for routine ATTEND analysis",
    )
    bedrock_sonnet_model: str = Field(
        default="anthropic.claude-3-5-sonnet-20241022-v2:0",
        description="Bedrock model ID for ambiguity/escalation analysis",
    )
    bedrock_max_tokens: int = Field(
        default=4096,
        ge=256,
        le=32768,
        description="Max tokens for LLM response",
    )
    bedrock_temperature: float = Field(
        default=0.1,
        ge=0.0,
        le=1.0,
        description="LLM temperature (low = deterministic)",
    )
    bedrock_timeout_seconds: int = Field(
        default=60,
        ge=10,
        le=300,
        description="Bedrock API timeout",
    )

    # RAG
    rag_index_path: Path = Field(
        default=Path("mvp2/copilot/data/rag_index.json"),
        description="Path to local RAG index JSON (future: pgvector)",
    )
    rag_max_docs: int = Field(
        default=5,
        ge=1,
        le=20,
        description="Max RAG documents to retrieve per query",
    )
    rag_similarity_threshold: float = Field(
        default=0.65,
        ge=0.0,
        le=1.0,
        description="Minimum cosine similarity for RAG hit",
    )

    # Prompt
    prompt_version: str = Field(
        default="1.0.0",
        min_length=1,
        description="Prompt template version (for audit trail)",
    )
    prompt_schema_path: Path = Field(
        default=Path("mvp2/copilot/data/prompt_schema.json"),
        description="Path to prompt schema (SSVC tree + categories)",
    )

    # Thresholds
    ambiguity_escalation_threshold: int = Field(
        default=2,
        ge=1,
        description="Number of ambiguity signals before escalating to Sonnet",
    )
    confidence_floor: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Minimum confidence to accept analysis (0 = accept all)",
    )

    # Shadow mode
    shadow_mode_default: bool = Field(
        default=True,
        description="Default shadow mode (read-only, no side effects)",
    )

    # Observability
    log_level: str = Field(
        default="INFO",
        pattern=r"^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$",
    )
    metrics_enabled: bool = Field(
        default=True,
        description="Enable structured logging metrics",
    )

    @field_validator("rag_index_path", "prompt_schema_path", mode="before")
    @classmethod
    def resolve_path(cls, v: object) -> Path:
        if isinstance(v, Path):
            return v
        return Path(str(v))

    @property
    def bedrock_endpoint_url(self) -> Optional[str]:
        """Bedrock endpoint URL, if custom endpoint is configured."""
        return os.getenv("COPILOT_BEDROCK_ENDPOINT_URL")

    @property
    def is_local_development(self) -> bool:
        """True if running outside AWS (for mock fallbacks)."""
        return os.getenv("AWS_EXECUTION_ENV") is None


@lru_cache
def get_settings() -> CopilotSettings:
    """Cached settings singleton."""
    return CopilotSettings()
