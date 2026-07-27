"""L6.10-12 — Audit Collector Agent.

Unified audit event collection, forwarding, and retention management.
All state changes across all layers produce an AuditEvent consumed here.

L6.10: Audit collector — receive + validate + idempotency check
L6.11: Sentinel forwarder — forward events to SIEM
L6.12: Retention guard — enforce PCI DSS 10.7 (5 year retention)
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

from shared.schemas.audit_event import AuditAction, AuditEvent, AuditStage
from shared.utils.fail_closed import fail_closed
from shared.utils.structlog_setup import get_logger

logger = get_logger(__name__)


class RetentionPolicy(str, Enum):
    """Retention policies per event type (PCI DSS 10.7)."""
    AUDIT_EVENT = "5_years"       # 5 years — PCI DSS requirement
    SECURITY_EVENT = "5_years"     # 5 years — incident evidence
    OPERATIONAL_LOG = "1_year"    # 1 year — operational troubleshooting
    DEBUG_LOG = "90_days"          # 90 days — short-lived debug data


@dataclass
class CollectedEvent:
    """An audit event that has been collected and validated."""
    event: AuditEvent
    collected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    retention: RetentionPolicy = RetentionPolicy.AUDIT_EVENT
    forwarded_to_sentinel: bool = False
    forwarded_at: datetime | None = None


# In-memory event store (production: DynamoDB)
_event_store: dict[str, CollectedEvent] = {}


@fail_closed(fallback_value=False, fallback_message="Audit collection failed — event not stored")
def collect_event(
    event: AuditEvent,
    retention: RetentionPolicy = RetentionPolicy.AUDIT_EVENT,
) -> bool:
    """Collect and validate an audit event. Idempotent by event_id.

    Returns True if event was stored (new), False if duplicate (idempotent).
    """
    # Idempotency check
    if event.event_id in _event_store:
        logger.info("audit_event_duplicate", event_id=event.event_id[:16])
        return False

    # Validate event completeness
    if not event.finding_id or not event.agent_id or not event.stage:
        logger.error("audit_event_incomplete", event_id=event.event_id[:16])
        return False

    # Store event
    collected = CollectedEvent(event=event, retention=retention)
    _event_store[event.event_id] = collected

    logger.info(
        "audit_event_collected",
        event_id=event.event_id[:16],
        finding_id=str(event.finding_id)[:8],
        stage=event.stage.value,
        action=event.action.value,
    )

    return True


def forward_to_sentinel(event_id: str) -> bool:
    """Forward an audit event to SIEM (Sentinel).

    In production, this calls the Sentinel HTTP API.
    Currently: marks event as forwarded (stub).
    """
    if event_id not in _event_store:
        return False

    collected = _event_store[event_id]
    collected.forwarded_to_sentinel = True
    collected.forwarded_at = datetime.now(timezone.utc)

    logger.info("audit_event_forwarded", event_id=event_id[:16], destination="sentinel")
    return True


def enforce_retention(retention_days: int | None = None) -> list[str]:
    """Enforce retention policies — return events that should be purged.

    PCI DSS 10.7: retain 12 months minimum (we enforce 5 years).
    """
    now = datetime.now(timezone.utc)
    expired: list[str] = []

    retention_map: dict[RetentionPolicy, int] = {
        RetentionPolicy.AUDIT_EVENT: retention_days or 1825,  # 5 years
        RetentionPolicy.SECURITY_EVENT: retention_days or 1825,
        RetentionPolicy.OPERATIONAL_LOG: retention_days or 365,
        RetentionPolicy.DEBUG_LOG: retention_days or 90,
    }

    for event_id, collected in list(_event_store.items()):
        max_days = retention_map.get(collected.retention, 1825)
        age = (now - collected.collected_at).days
        if age > max_days:
            expired.append(event_id)

    for event_id in expired:
        del _event_store[event_id]
        logger.info("retention_purged", event_id=event_id[:16])

    return expired


def get_events_by_finding(finding_id: str) -> list[CollectedEvent]:
    """Retrieve all audit events for a finding (for audit trail display)."""
    return [
        c for c in _event_store.values()
        if str(c.event.finding_id) == finding_id
    ]


def get_event_count() -> int:
    """Total collected events (for metrics)."""
    return len(_event_store)


def compute_chain_hash(events: list[CollectedEvent]) -> str:
    """Compute a chain hash over events — provides tamper evidence.

    Each event's hash includes the previous event's hash,
    creating an append-only chain (similar to blockchain light).
    """
    chain_hash = "0" * 64  # Genesis hash

    for collected in sorted(events, key=lambda c: c.event.timestamp):
        raw = f"{chain_hash}:{collected.event.event_id}:{collected.event.payload_hash}"
        chain_hash = hashlib.sha256(raw.encode()).hexdigest()

    return chain_hash
