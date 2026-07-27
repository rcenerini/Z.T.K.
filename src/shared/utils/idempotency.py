"""F0.1.6 — Idempotency utilities.

Pure functions for deterministic idempotency key generation.
Used by all layers that write state (DynamoDB, S3, SQS, Jira, WAF).
"""

from __future__ import annotations

import hashlib
from uuid import UUID


def generate_idempotency_key(
    finding_id: UUID | str,
    stage: str,
    payload: dict | str | bytes,
) -> str:
    """Generate a deterministic idempotency key via SHA-256.

    Input: (finding_id, stage, payload) — the idempotency trinca.
    Output: 64-char hex string usable as DynamoDB sort key or SQS dedup ID.

    Deterministic: same input always produces same output.
    Used by: DynamoDB ConditionExpression, S3 If-None-Match, SQS MessageDeduplicationId.
    """
    raw = f"{finding_id}:{stage}:{_normalize_payload(payload)}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def generate_audit_event_id(
    finding_id: UUID | str,
    stage: str,
    payload: dict | str,
) -> str:
    """Generate AuditEvent.event_id via SHA-256.

    Alias for generate_idempotency_key — semantic clarity for audit events.
    """
    return generate_idempotency_key(finding_id, stage, payload)


def generate_waf_rule_name(
    finding_id: UUID | str,
    cwe_id: str,
    target_hash: str,
) -> str:
    """Generate a deterministic WAF rule name.

    Format: ztk-{first8_of_hash}-{cwe_id_lower}
    Max 64 chars, safe for F5/Akamai/Azure WAF naming conventions.
    """
    full_hash = generate_idempotency_key(finding_id, "waf_rule", target_hash)
    short_hash = full_hash[:8]
    safe_cwe = cwe_id.replace("-", "_").lower()[:48]
    return f"ztk-{short_hash}-{safe_cwe}"[:64]


def _normalize_payload(payload: dict | str | bytes) -> str:
    """Normalize payload to deterministic string for hashing."""
    import json

    if isinstance(payload, bytes):
        return payload.hex()
    if isinstance(payload, str):
        return payload
    # dict: canonical JSON with sorted keys, no spaces
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))
