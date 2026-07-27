"""F0.1.1 — Schema base `Finding` (Pydantic v2).

Foundation for ALL layers. Every agent receives/produces this schema.
100% typed fields, strict validation, fail-closed by default.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Annotated, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator


class FindingSeverity(str, Enum):
    """Normalised severity scale — P0=critical, P4=informational."""
    P0 = "P0"
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


class FindingSource(str, Enum):
    """Source tool that produced the finding."""
    TENABLE = "Tenable"
    SEMGREP = "Semgrep"
    BANDIT = "Bandit"
    CODEQL = "CodeQL"
    TRUFFLEHOG = "TruffleHog"
    GITLEAKS = "Gitleaks"
    OPA = "OPA"
    CHECKOV = "Checkov"
    NVD = "NVD"
    OSV = "OSV"
    MANUAL = "Manual"


class FindingStatus(str, Enum):
    """Lifecycle status of a finding."""
    RAW = "RAW"
    NORMALIZED = "NORMALIZED"
    ENRICHED = "ENRICHED"
    SCORED = "SCORED"
    DECIDED = "DECIDED"
    IN_REMEDIATION = "IN_REMEDIATION"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    EXCEPTION = "EXCEPTION"


class Confidence(str, Enum):
    """Tool confidence level."""
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class Language(str, Enum):
    """Programming languages with dedicated SAST agents (Camada 2)."""
    PYTHON = "python"
    JAVA = "java"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    GO = "go"
    CPP = "cpp"
    C = "c"
    RUST = "rust"
    CSHARP = "csharp"
    PHP = "php"
    RUBY = "ruby"
    KOTLIN = "kotlin"
    SWIFT = "swift"
    DART = "dart"
    SCALA = "scala"
    TERRAFORM = "terraform"
    DOCKERFILE = "dockerfile"
    KUBERNETES = "kubernetes"
    OTHER = "other"


class AuditTrailEntry(BaseModel):
    """Single entry in the finding's audit trail."""
    timestamp: Annotated[datetime, Field(default_factory=lambda: datetime.now(timezone.utc))]
    stage: Annotated[str, Field(min_length=1, max_length=64)]
    agent_id: Annotated[str, Field(min_length=1, max_length=64)]
    action: Annotated[str, Field(min_length=1, max_length=128)]
    detail: Annotated[Optional[str], Field(default=None, max_length=2000)]
    previous_hash: Annotated[Optional[str], Field(default=None, min_length=64, max_length=64)]


class Finding(BaseModel):
    """Core finding schema — the universal data structure across all 8 layers."""

    model_config = {"extra": "forbid", "str_strip_whitespace": True}

    # Identity
    finding_id: Annotated[UUID, Field(default_factory=uuid4, description="Unique finding identifier")]
    tenant_id: Annotated[str, Field(min_length=1, max_length=64, description="Tenant identifier")]
    source: FindingSource

    # What was found
    severity: FindingSeverity
    cwe_ids: Annotated[list[str], Field(min_length=1, max_length=20, description="CWE identifiers")]
    title: Annotated[str, Field(min_length=5, max_length=256)]
    description: Annotated[str, Field(min_length=10, max_length=5000)]
    file_path: Annotated[str, Field(min_length=1, max_length=1024)]
    line_number: Annotated[int, Field(ge=1, le=1000000)]
    column_number: Annotated[Optional[int], Field(default=None, ge=1)]
    language: Annotated[Optional[Language], Field(default=None)]

    # Evidence
    evidence: Annotated[Optional[str], Field(default=None, max_length=10000, description="Code snippet, log, or raw output")]
    evidence_hash: Annotated[Optional[str], Field(default=None, min_length=64, max_length=64, description="SHA-256 of evidence")]

    # Metadata
    confidence: Annotated[Confidence, Field(default=Confidence.UNKNOWN)]
    status: Annotated[FindingStatus, Field(default=FindingStatus.RAW)]
    cvss_vector: Annotated[Optional[str], Field(default=None, pattern=r"^CVSS:[34]\.0/.*")]
    epss_score: Annotated[Optional[float], Field(default=None, ge=0.0, le=1.0)]
    related_findings: Annotated[list[UUID], Field(default_factory=list, max_length=50)]

    # Lifecycle
    created_at: Annotated[datetime, Field(default_factory=lambda: datetime.now(timezone.utc))]
    updated_at: Annotated[datetime, Field(default_factory=lambda: datetime.now(timezone.utc))]
    resolved_at: Annotated[Optional[datetime], Field(default=None)]

    # Audit
    audit_trail: Annotated[list[AuditTrailEntry], Field(default_factory=list, max_length=200)]

    # Extensibility (controlled)
    tags: Annotated[dict[str, str], Field(default_factory=dict, max_length=30)]
    metadata: Annotated[dict[str, str], Field(default_factory=dict, max_length=50)]

    @field_validator("finding_id", mode="before")
    @classmethod
    def coerce_uuid(cls, v: object) -> UUID:
        if isinstance(v, UUID):
            return v
        try:
            return UUID(str(v))
        except (ValueError, TypeError):
            raise ValueError("finding_id must be a valid UUID") from None

    @field_validator("cwe_ids")
    @classmethod
    def validate_cwe_format(cls, v: list[str]) -> list[str]:
        for cwe_id in v:
            if not cwe_id.startswith("CWE-"):
                raise ValueError(f"Invalid CWE format: {cwe_id}")
        return v

    @field_validator("tenant_id")
    @classmethod
    def validate_tenant_id(cls, v: str) -> str:
        if v in ("", " "):
            raise ValueError("tenant_id cannot be empty")
        return v.lower()

    def add_audit_entry(self, stage: str, agent_id: str, action: str, detail: str | None = None) -> None:
        """Append an audit trail entry. Idempotent-safe."""
        entry = AuditTrailEntry(stage=stage, agent_id=agent_id, action=action, detail=detail)
        self.audit_trail.append(entry)
        self.updated_at = datetime.now(timezone.utc)
