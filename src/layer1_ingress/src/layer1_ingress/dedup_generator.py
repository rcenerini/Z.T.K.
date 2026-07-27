"""L1.07 — Dedup / Idempotency Key Generator Agent.

Generates deterministic idempotency keys for every finding pipeline execution.
Ensures no duplicate processing across retries, replays, or parallel invocations.

Uses shared/utils/idempotency.py for core hashing logic.
"""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from shared.utils.idempotency import generate_idempotency_key
from shared.utils.structlog_setup import get_logger

logger = get_logger(__name__)


@dataclass
class DedupResult:
    """Deduplication result for a finding."""
    finding_id: UUID
    file_hash: str      # SHA-256 of concatenated file content hashes
    commit_sha: str     # Git commit SHA
    idempotency_key: str  # Deterministic key for this pipeline run
    stage_keys: dict[str, str] = None  # Per-stage keys

    def __post_init__(self) -> None:
        if self.stage_keys is None:
            self.stage_keys = {}


def generate_dedup_keys(
    finding_id: UUID,
    file_hashes: list[str],
    commit_sha: str,
) -> DedupResult:
    """Generate deduplication and idempotency keys for a finding.

    Deterministic: same inputs always produce same keys.
    Uses SHA-256 over sorted file hashes + commit SHA.
    """
    import hashlib

    # Combine all file hashes (sorted for determinism)
    sorted_hashes = sorted(file_hashes)
    combined = "|".join(sorted_hashes + [commit_sha])
    file_hash = hashlib.sha256(combined.encode()).hexdigest()

    # Master idempotency key (for the entire pipeline run)
    master_key = generate_idempotency_key(str(finding_id), "pipeline", combined)

    # Per-stage keys (for individual agent idempotency)
    stages = [
        "ingestion", "classification", "prompt_guard",
        "criticality", "routing", "scope_planning",
        "sast", "validation", "consensus", "remediation",
    ]
    stage_keys = {
        stage: generate_idempotency_key(str(finding_id), stage, file_hash)
        for stage in stages
    }

    result = DedupResult(
        finding_id=finding_id,
        file_hash=file_hash,
        commit_sha=commit_sha,
        idempotency_key=master_key,
        stage_keys=stage_keys,
    )

    logger.info(
        "dedup_keys_generated",
        finding_id=str(finding_id),
        file_hash=file_hash[:16],
        commit_sha=commit_sha[:8],
    )

    return result
