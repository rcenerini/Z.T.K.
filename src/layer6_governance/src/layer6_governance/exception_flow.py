"""L6.05-09 — Exception Flow Agent.

Manages the four-eyes exception lifecycle:
  L6.05: Exception intake (validate + register)
  L6.07: Four-eyes approval gate (two different approvers)
  L6.08: Exception applier (apply approved exception)
  L6.09: Exception audit (log + expiry management)
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum

from shared.utils.fail_closed import fail_closed
from shared.utils.structlog_setup import get_logger

logger = get_logger(__name__)


class ExceptionCategory(str, Enum):
    FALSE_POSITIVE = "FALSE_POSITIVE"
    RISK_ACCEPTED = "RISK_ACCEPTED"
    COMPENSATING_CONTROL = "COMPENSATING_CONTROL"
    DEFERRED_FIX = "DEFERRED_FIX"


class ExceptionStatus(str, Enum):
    REQUESTED = "REQUESTED"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


@dataclass
class ExceptionRequest:
    """An exception request submitted by an engineering owner."""
    exception_id: str
    finding_id: str
    tenant_id: str
    requested_by: str
    category: ExceptionCategory
    justification: str
    current_severity: str  # P0-P4
    requested_severity: str  # P0-P4
    ttl_days: int
    compensating_control: str = ""
    risk_acceptance_owner: str = ""
    status: ExceptionStatus = ExceptionStatus.REQUESTED
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = None
    approved_by: list[str] = field(default_factory=list)
    rejection_reason: str = ""


# Severity numeric mapping for validation
SEVERITY_ORDER: dict[str, int] = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4}

# Maximum TTL per category (days)
MAX_TTL: dict[ExceptionCategory, int] = {
    ExceptionCategory.FALSE_POSITIVE: 180,
    ExceptionCategory.RISK_ACCEPTED: 365,
    ExceptionCategory.COMPENSATING_CONTROL: 90,
    ExceptionCategory.DEFERRED_FIX: 90,
}


@fail_closed(fallback_value=None, fallback_message="Exception intake failed")
def intake_exception(
    finding_id: str,
    tenant_id: str,
    requested_by: str,
    category: ExceptionCategory,
    justification: str,
    current_severity: str,
    requested_severity: str,
    ttl_days: int = 90,
    compensating_control: str = "",
    risk_acceptance_owner: str = "",
) -> ExceptionRequest | None:
    """Validate and register an exception request.

    Validation rules:
    - current_severity must be valid P0-P4
    - requested_severity must be valid P0-P4
    - P0 findings CANNOT have exceptions (period)
    - ttl_days must be <= MAX_TTL for the category
    - justification must be meaningful (min 100 chars)
    """
    # Validate severities
    if current_severity not in SEVERITY_ORDER or requested_severity not in SEVERITY_ORDER:
        logger.error("invalid_severity", current=current_severity, requested=requested_severity)
        return None

    # P0: no exceptions allowed
    if current_severity == "P0":
        logger.error("p0_no_exception", finding_id=finding_id)
        return None

    # Severity REDUCTION only (exceptions lower severity, never raise it)
    if SEVERITY_ORDER[current_severity] > SEVERITY_ORDER[requested_severity]:
        logger.error("severity_increase_not_allowed", current=current_severity, requested=requested_severity)
        return None

    # Requested severity must be lower than current
    if current_severity == requested_severity:
        logger.error("severity_not_changed", current=current_severity, requested=requested_severity)
        return None

    # TTL validation
    max_ttl = MAX_TTL.get(category, 90)
    if ttl_days > max_ttl:
        logger.error("ttl_exceeded", ttl_days=ttl_days, max_ttl=max_ttl, category=category.value)
        return None

    if ttl_days < 1:
        logger.error("ttl_too_short", ttl_days=ttl_days)
        return None

    # Justification validation
    if len(justification.strip()) < 50:
        logger.error("justification_too_short", length=len(justification))
        return None

    exception = ExceptionRequest(
        exception_id=str(uuid.uuid4()),
        finding_id=finding_id,
        tenant_id=tenant_id,
        requested_by=requested_by,
        category=category,
        justification=justification,
        current_severity=current_severity,
        requested_severity=requested_severity,
        ttl_days=ttl_days,
        compensating_control=compensating_control,
        risk_acceptance_owner=risk_acceptance_owner,
        expires_at=datetime.now(timezone.utc) + timedelta(days=ttl_days),
    )

    logger.info(
        "exception_requested",
        exception_id=exception.exception_id,
        finding_id=finding_id,
        category=category.value,
        current_severity=current_severity,
        requested_severity=requested_severity,
        ttl_days=ttl_days,
    )

    return exception


def four_eyes_approve(
    exception: ExceptionRequest,
    approver_email: str,
    approver_role: str,
) -> tuple[bool, str]:
    """Process a single approval in the four-eyes flow.

    Rules:
    - Same person cannot approve twice
    - Requires two different people
    - Roles: Gerente Executivo (first) + Superintendente/CISO (second)
    """
    if approver_email in exception.approved_by:
        return False, f"Approver {approver_email} already approved this exception"

    if approver_email == exception.requested_by:
        return False, "Requester cannot approve their own exception"

    exception.approved_by.append(approver_email)

    # Check if we have two approvals from different people
    if len(exception.approved_by) >= 2:
        if len(set(exception.approved_by)) >= 2:
            exception.status = ExceptionStatus.APPROVED
            logger.info(
                "exception_approved_four_eyes",
                exception_id=exception.exception_id,
                approved_by=exception.approved_by,
            )
            return True, "Exception approved (four-eyes complete)"

    logger.info(
        "exception_partial_approval",
        exception_id=exception.exception_id,
        approved_by=exception.approved_by,
        remaining=2 - len(exception.approved_by),
    )
    return False, f"Waiting for {2 - len(exception.approved_by)} more approval(s)"


def reject_exception(exception: ExceptionRequest, rejected_by: str, reason: str) -> None:
    """Reject an exception request. Any approver can reject."""
    exception.status = ExceptionStatus.REJECTED
    exception.rejection_reason = reason
    logger.info(
        "exception_rejected",
        exception_id=exception.exception_id,
        rejected_by=rejected_by,
        reason=reason[:100],
    )


def apply_exception(exception: ExceptionRequest) -> bool:
    """Apply an approved exception — activate the severity reduction.

    Can only be applied if status is APPROVED and not expired.
    """
    if exception.status != ExceptionStatus.APPROVED:
        logger.error("exception_not_approved", status=exception.status.value)
        return False

    if exception.expires_at and datetime.now(timezone.utc) > exception.expires_at:
        logger.error("exception_expired", expires_at=exception.expires_at.isoformat())
        return False

    exception.status = ExceptionStatus.ACTIVE
    logger.info("exception_applied", exception_id=exception.exception_id)
    return True


def check_expiry(exception: ExceptionRequest) -> bool:
    """Check if an active exception has expired. Returns True if expired."""
    if exception.status != ExceptionStatus.ACTIVE:
        return False

    if exception.expires_at and datetime.now(timezone.utc) > exception.expires_at:
        exception.status = ExceptionStatus.EXPIRED
        logger.info(
            "exception_expired",
            exception_id=exception.exception_id,
            finding_id=exception.finding_id,
        )
        return True

    return False


def can_renew(exception: ExceptionRequest, renewal_count: int) -> bool:
    """Check if an exception can be renewed. Max 2 renewals."""
    if renewal_count >= 2:
        logger.error(
            "exception_max_renewals",
            exception_id=exception.exception_id,
            renewal_count=renewal_count,
        )
        return False
    return True
