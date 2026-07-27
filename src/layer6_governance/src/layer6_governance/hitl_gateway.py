"""L6.13-17 — HITL Gateway Agent.

Human-in-the-Loop queue management:
  L6.13: HITL queue — register items requiring human review
  L6.14: Notifier — send notifications (Teams, email, Slack)
  L6.15: Jira ticket — create/update tickets
  L6.16: SLA monitor — track response times
  L6.17: Escalation — progressive escalation on SLA breach
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum

from shared.utils.fail_closed import fail_closed
from shared.utils.structlog_setup import get_logger

logger = get_logger(__name__)


class HITLPriority(str, Enum):
    """HITL item priority — determines SLA."""
    CRITICAL = "CRITICAL"   # 15 min response
    HIGH = "HIGH"           # 1 hour
    MEDIUM = "MEDIUM"       # 4 hours
    LOW = "LOW"             # 24 hours


class HITLStatus(str, Enum):
    PENDING = "PENDING"
    ASSIGNED = "ASSIGNED"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED = "RESOLVED"
    ESCALATED = "ESCALATED"
    EXPIRED = "EXPIRED"


class EscalationLevel(str, Enum):
    NONE = "NONE"
    LEVEL_1 = "LEVEL_1"  # Team lead
    LEVEL_2 = "LEVEL_2"  # Engineering manager
    LEVEL_3 = "LEVEL_3"  # CISO
    LEVEL_4 = "LEVEL_4"  # C-level


@dataclass
class HITLItem:
    """A single HITL queue item."""
    item_id: str
    finding_id: str
    tenant_id: str
    title: str
    description: str
    priority: HITLPriority
    status: HITLStatus = HITLStatus.PENDING
    assigned_to: str = ""
    escalation_level: EscalationLevel = EscalationLevel.NONE
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    sla_deadline: datetime | None = None
    resolved_at: datetime | None = None
    resolution: str = ""
    jira_ticket_id: str = ""

    def __post_init__(self) -> None:
        sla_hours = {
            HITLPriority.CRITICAL: 0.25,  # 15 min
            HITLPriority.HIGH: 1,
            HITLPriority.MEDIUM: 4,
            HITLPriority.LOW: 24,
        }
        self.sla_deadline = self.created_at + timedelta(hours=sla_hours.get(self.priority, 24))


# In-memory HITL queue (production: DynamoDB)
_hitl_queue: dict[str, HITLItem] = {}


@fail_closed(fallback_value=False, fallback_message="HITL enqueue failed")
def enqueue_item(
    finding_id: str,
    tenant_id: str,
    title: str,
    description: str,
    priority: HITLPriority = HITLPriority.MEDIUM,
) -> str | None:
    """Enqueue a new HITL item for human review.

    Returns item_id if successful, None on failure.
    """
    item_id = str(uuid.uuid4())
    item = HITLItem(
        item_id=item_id,
        finding_id=finding_id,
        tenant_id=tenant_id,
        title=title,
        description=description,
        priority=priority,
    )
    _hitl_queue[item_id] = item

    logger.info(
        "hitl_enqueued",
        item_id=item_id[:8],
        finding_id=finding_id[:8],
        priority=priority.value,
        sla_deadline=item.sla_deadline.isoformat() if item.sla_deadline else "none",
    )

    return item_id


def assign_item(item_id: str, assignee: str) -> bool:
    """Assign a HITL item to a human reviewer."""
    if item_id not in _hitl_queue:
        return False

    item = _hitl_queue[item_id]
    if item.status != HITLStatus.PENDING:
        logger.error("hitl_not_pending", item_id=item_id[:8], status=item.status.value)
        return False

    item.status = HITLStatus.ASSIGNED
    item.assigned_to = assignee

    logger.info("hitl_assigned", item_id=item_id[:8], assignee=assignee)
    return True


def resolve_item(item_id: str, resolution: str) -> bool:
    """Mark a HITL item as resolved."""
    if item_id not in _hitl_queue:
        return False

    item = _hitl_queue[item_id]
    item.status = HITLStatus.RESOLVED
    item.resolved_at = datetime.now(timezone.utc)
    item.resolution = resolution

    logger.info("hitl_resolved", item_id=item_id[:8], resolution=resolution[:100])
    return True


def check_sla_breaches() -> list[HITLItem]:
    """Check all HITL items for SLA breaches and escalate as needed.

    Returns list of items that breached SLA.
    """
    now = datetime.now(timezone.utc)
    breached: list[HITLItem] = []

    for item in _hitl_queue.values():
        if item.status in (HITLStatus.RESOLVED, HITLStatus.EXPIRED):
            continue

        if item.sla_deadline and now > item.sla_deadline:
            breached.append(item)

    return breached


def escalate_item(item_id: str) -> EscalationLevel:
    """Escalate a HITL item to the next level.

    Escalation chain: NONE → LEVEL_1 → LEVEL_2 → LEVEL_3 → LEVEL_4
    """
    if item_id not in _hitl_queue:
        return EscalationLevel.NONE

    item = _hitl_queue[item_id]

    escalation_order = [
        EscalationLevel.NONE,
        EscalationLevel.LEVEL_1,
        EscalationLevel.LEVEL_2,
        EscalationLevel.LEVEL_3,
        EscalationLevel.LEVEL_4,
    ]

    try:
        current_idx = escalation_order.index(item.escalation_level)
        if current_idx < len(escalation_order) - 1:
            next_level = escalation_order[current_idx + 1]
        else:
            next_level = EscalationLevel.LEVEL_4  # Max reached
    except ValueError:
        next_level = EscalationLevel.LEVEL_1

    item.escalation_level = next_level
    item.status = HITLStatus.ESCALATED

    notify_targets = {
        EscalationLevel.LEVEL_1: "Team Lead",
        EscalationLevel.LEVEL_2: "Engineering Manager",
        EscalationLevel.LEVEL_3: "CISO",
        EscalationLevel.LEVEL_4: "C-Level",
    }

    logger.info(
        "hitl_escalated",
        item_id=item_id[:8],
        level=next_level.value,
        notify=notify_targets.get(next_level, "Unknown"),
    )

    return next_level


def get_pending_count() -> int:
    """Count of pending/assigned/in-progress HITL items."""
    return sum(
        1 for item in _hitl_queue.values()
        if item.status in (HITLStatus.PENDING, HITLStatus.ASSIGNED, HITLStatus.IN_PROGRESS)
    )


def create_jira_ticket(item_id: str, project_key: str = "ZTK") -> str:
    """Create a Jira ticket for a HITL item (stub).

    In production, calls Jira REST API.
    """
    if item_id not in _hitl_queue:
        return ""

    item = _hitl_queue[item_id]
    ticket_id = f"{project_key}-{abs(hash(item_id)) % 10000:04d}"
    item.jira_ticket_id = ticket_id

    logger.info("jira_ticket_created", item_id=item_id[:8], ticket=ticket_id)
    return ticket_id
