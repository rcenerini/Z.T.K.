"""Tests for Layer 6 — Governance agents.

Covers: L6.01 (policy engine), L6.05-09 (exception flow),
L6.10-12 (audit collector), L6.13-17 (HITL gateway).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from layer6_governance.policy_engine import (
    PolicyDecision,
    PolicyResult,
    evaluate,
    _embedded_evaluate,
)
from layer6_governance.exception_flow import (
    ExceptionCategory,
    ExceptionRequest,
    ExceptionStatus,
    intake_exception,
    four_eyes_approve,
    reject_exception,
    apply_exception,
    check_expiry,
    can_renew,
)
from layer6_governance.audit_collector import (
    RetentionPolicy,
    collect_event,
    forward_to_sentinel,
    get_event_count,
    compute_chain_hash,
)
from layer6_governance.hitl_gateway import (
    HITLPriority,
    HITLStatus,
    EscalationLevel,
    enqueue_item,
    assign_item,
    resolve_item,
    check_sla_breaches,
    escalate_item,
    get_pending_count,
    create_jira_ticket,
)
from shared.schemas.audit_event import (
    AuditAction,
    AuditEvent,
    AuditStage,
)


# ═══════════════════════════════════════════════════════════════════
# L6.01 — Policy Engine
# ═══════════════════════════════════════════════════════════════════

class TestPolicyEngine:
    def test_read_operation_allowed(self) -> None:
        result = _embedded_evaluate("read_code", {}, "deny_by_default")
        assert result.decision == PolicyDecision.ALLOW

    def test_unknown_operation_denied(self) -> None:
        result = _embedded_evaluate("admin_all_things", {}, "deny_by_default")
        assert result.decision == PolicyDecision.DENY

    def test_merge_pr_with_review_allowed(self) -> None:
        result = _embedded_evaluate("merge_pr", {
            "security_review_passed": True,
            "severity": "P2",
        }, "deny_by_default")
        assert result.decision == PolicyDecision.ALLOW

    def test_merge_pr_p0_denied(self) -> None:
        result = _embedded_evaluate("merge_pr", {
            "security_review_passed": True,
            "severity": "P0",
        }, "deny_by_default")
        assert result.decision == PolicyDecision.DENY

    def test_merge_pr_no_review_denied(self) -> None:
        result = _embedded_evaluate("merge_pr", {
            "security_review_passed": False,
            "severity": "P2",
        }, "deny_by_default")
        assert result.decision == PolicyDecision.DENY

    def test_deploy_prod_no_cab_denied(self) -> None:
        result = _embedded_evaluate("deploy", {
            "environment": "production",
            "cab_approved": False,
        }, "deny_by_default")
        assert result.decision == PolicyDecision.DENY

    def test_deploy_prod_cab_allowed(self) -> None:
        result = _embedded_evaluate("deploy", {
            "environment": "production",
            "cab_approved": True,
        }, "deny_by_default")
        assert result.decision == PolicyDecision.ALLOW

    def test_kill_switch_soc_allowed(self) -> None:
        result = _embedded_evaluate("kill_switch", {
            "authority": "SOC",
        }, "deny_by_default")
        assert result.decision == PolicyDecision.ALLOW

    def test_kill_switch_engineering_denied(self) -> None:
        result = _embedded_evaluate("kill_switch", {
            "authority": "ENGINEERING",
        }, "deny_by_default")
        assert result.decision == PolicyDecision.DENY

    def test_containment_dry_run_allowed(self) -> None:
        result = _embedded_evaluate("containment_dry_run", {
            "dry_run": True,
        }, "deny_by_default")
        assert result.decision == PolicyDecision.ALLOW

    def test_containment_no_dry_run_denied(self) -> None:
        result = _embedded_evaluate("containment_dry_run", {
            "dry_run": False,
        }, "deny_by_default")
        assert result.decision == PolicyDecision.DENY

    def test_write_audit_event_always_allowed(self) -> None:
        result = _embedded_evaluate("write_audit_event", {}, "deny_by_default")
        assert result.decision == PolicyDecision.ALLOW


# ═══════════════════════════════════════════════════════════════════
# L6.05-09 — Exception Flow
# ═══════════════════════════════════════════════════════════════════

class TestExceptionFlow:
    def test_valid_exception_intake(self) -> None:
        exc = intake_exception(
            finding_id=str(uuid.uuid4()),
            tenant_id="ztk-proj",
            requested_by="eng@empresa.com.br",
            category=ExceptionCategory.COMPENSATING_CONTROL,
            justification="WAF rule blocks exploitation. Risk accepted for 90 days while patch is developed and tested in staging.",
            current_severity="P1",
            requested_severity="P3",
            ttl_days=90,
        )
        assert exc is not None
        assert exc.status == ExceptionStatus.REQUESTED
        assert exc.ttl_days == 90
        assert exc.expires_at is not None

    def test_p0_no_exception(self) -> None:
        exc = intake_exception(
            finding_id=str(uuid.uuid4()),
            tenant_id="ztk-proj",
            requested_by="eng@empresa.com.br",
            category=ExceptionCategory.FALSE_POSITIVE,
            justification="Detailed justification explaining why this P0 finding is actually a false positive based on extensive manual code review.",
            current_severity="P0",
            requested_severity="P4",
            ttl_days=180,
        )
        assert exc is None

    def test_short_justification_rejected(self) -> None:
        exc = intake_exception(
            finding_id=str(uuid.uuid4()),
            tenant_id="ztk-proj",
            requested_by="eng@empresa.com.br",
            category=ExceptionCategory.FALSE_POSITIVE,
            justification="Short",
            current_severity="P1",
            requested_severity="P4",
        )
        assert exc is None

    def test_ttl_exceeded(self) -> None:
        exc = intake_exception(
            finding_id=str(uuid.uuid4()),
            tenant_id="ztk-proj",
            requested_by="eng@empresa.com.br",
            category=ExceptionCategory.COMPENSATING_CONTROL,
            justification="Detailed justification that meets the minimum length requirement for exception intake processing.",
            current_severity="P1",
            requested_severity="P3",
            ttl_days=365,  # Max for COMPENSATING_CONTROL is 90
        )
        assert exc is None

    def test_severity_increase_rejected(self) -> None:
        exc = intake_exception(
            finding_id=str(uuid.uuid4()),
            tenant_id="ztk-proj",
            requested_by="eng@empresa.com.br",
            category=ExceptionCategory.FALSE_POSITIVE,
            justification="Detailed justification for this finding exception request with sufficient length.",
            current_severity="P3",
            requested_severity="P1",  # Can't increase severity
        )
        assert exc is None

    def test_four_eyes_approval(self) -> None:
        exc = intake_exception(
            finding_id=str(uuid.uuid4()),
            tenant_id="ztk-proj",
            requested_by="eng@empresa.com.br",
            category=ExceptionCategory.RISK_ACCEPTED,
            justification="Business accepts this risk due to compensating controls. Detailed analysis performed by security team.",
            current_severity="P2",
            requested_severity="P4",
            ttl_days=180,
        )
        assert exc is not None

        # First approval
        ok1, msg1 = four_eyes_approve(exc, "gerente@empresa.com.br", "Gerente Executivo")
        assert ok1 is False  # Still need second approval
        assert len(exc.approved_by) == 1

        # Second approval (different person)
        ok2, msg2 = four_eyes_approve(exc, "super@empresa.com.br", "Superintendente")
        assert ok2 is True  # Four-eyes complete
        assert exc.status == ExceptionStatus.APPROVED

    def test_same_person_cannot_approve_twice(self) -> None:
        exc = intake_exception(
            finding_id=str(uuid.uuid4()),
            tenant_id="ztk-proj",
            requested_by="eng@empresa.com.br",
            category=ExceptionCategory.FALSE_POSITIVE,
            justification="Extensive manual analysis confirms this is a false positive due to the specific configuration.",
            current_severity="P1",
            requested_severity="P4",
        )
        assert exc is not None
        four_eyes_approve(exc, "gerente@empresa.com.br", "Gerente Executivo")
        ok, msg = four_eyes_approve(exc, "gerente@empresa.com.br", "Gerente Executivo")
        assert ok is False
        assert "already approved" in msg

    def test_requester_cannot_approve(self) -> None:
        exc = intake_exception(
            finding_id=str(uuid.uuid4()),
            tenant_id="ztk-proj",
            requested_by="eng@empresa.com.br",
            category=ExceptionCategory.FALSE_POSITIVE,
            justification="Detailed explanation of why this specific finding is a false positive in this context.",
            current_severity="P1",
            requested_severity="P4",
        )
        assert exc is not None
        ok, msg = four_eyes_approve(exc, "eng@empresa.com.br", "Gerente Executivo")
        assert ok is False
        assert "cannot approve" in msg.lower()

    def test_reject_exception(self) -> None:
        exc = intake_exception(
            finding_id=str(uuid.uuid4()),
            tenant_id="ztk-proj",
            requested_by="eng@empresa.com.br",
            category=ExceptionCategory.DEFERRED_FIX,
            justification="Fix is deferred due to external dependency update cycle. Will be included in next sprint.",
            current_severity="P1",
            requested_severity="P3",
        )
        assert exc is not None
        reject_exception(exc, "gerente@empresa.com.br", "Not enough justification")
        assert exc.status == ExceptionStatus.REJECTED

    def test_apply_approved_exception(self) -> None:
        exc = intake_exception(
            finding_id=str(uuid.uuid4()),
            tenant_id="ztk-proj",
            requested_by="eng@empresa.com.br",
            category=ExceptionCategory.COMPENSATING_CONTROL,
            justification="Compensating WAF control deployed and verified in production for this specific vulnerability.",
            current_severity="P1",
            requested_severity="P3",
            ttl_days=30,
        )
        assert exc is not None
        four_eyes_approve(exc, "gerente@empresa.com.br", "Gerente Executivo")
        four_eyes_approve(exc, "super@empresa.com.br", "Superintendente")
        assert apply_exception(exc) is True
        assert exc.status == ExceptionStatus.ACTIVE

    def test_apply_unapproved_fails(self) -> None:
        exc = intake_exception(
            finding_id=str(uuid.uuid4()),
            tenant_id="ztk-proj",
            requested_by="eng@empresa.com.br",
            category=ExceptionCategory.FALSE_POSITIVE,
            justification="Repeated scans confirm no actual vulnerability present in this specific code path.",
            current_severity="P2",
            requested_severity="P4",
        )
        assert exc is not None
        assert apply_exception(exc) is False  # Not yet approved

    def test_cannot_renew_more_than_twice(self) -> None:
        exc = intake_exception(
            finding_id=str(uuid.uuid4()),
            tenant_id="ztk-proj",
            requested_by="eng@empresa.com.br",
            category=ExceptionCategory.RISK_ACCEPTED,
            justification="Detailed risk acceptance justification with thorough analysis and documentation.",
            current_severity="P2",
            requested_severity="P4",
        )
        assert can_renew(exc, 0) is True
        assert can_renew(exc, 1) is True
        assert can_renew(exc, 2) is False


# ═══════════════════════════════════════════════════════════════════
# L6.10-12 — Audit Collector
# ═══════════════════════════════════════════════════════════════════

class TestAuditCollector:
    def _make_event(self,) -> AuditEvent:
        fid = uuid.uuid4()
        payload = {"action": "test", "severity": "P2"}
        ph = AuditEvent.compute_payload_hash(payload)
        eid = AuditEvent.compute_event_id(fid, "TESTING", ph)
        return AuditEvent(
            event_id=eid,
            finding_id=fid,
            stage=AuditStage.GOVERNANCE,
            action=AuditAction.VALIDATED,
            agent_id="L6.test",
            tenant_id="ztk-proj",
            payload=payload,
            payload_hash=ph,
        )

    def test_collect_event(self) -> None:
        event = self._make_event()
        assert collect_event(event) is True
        assert get_event_count() >= 1

    def test_duplicate_event_rejected(self) -> None:
        event = self._make_event()
        collect_event(event)
        assert collect_event(event) is False  # Duplicate

    def test_chain_hash_deterministic(self) -> None:
        e1 = self._make_event()
        e2 = self._make_event()
        collect_event(e1)
        collect_event(e2)
        from layer6_governance.audit_collector import get_events_by_finding, _event_store
        events = [c for c in _event_store.values()]
        h1 = compute_chain_hash(events)
        h2 = compute_chain_hash(events)
        assert h1 == h2  # Deterministic

    def test_forward_to_sentinel(self) -> None:
        event = self._make_event()
        collect_event(event)
        assert forward_to_sentinel(event.event_id) is True
        assert forward_to_sentinel("nonexistent") is False


# ═══════════════════════════════════════════════════════════════════
# L6.13-17 — HITL Gateway
# ═══════════════════════════════════════════════════════════════════

class TestHITLGateway:
    def test_enqueue_item(self) -> None:
        item_id = enqueue_item(
            finding_id=str(uuid.uuid4()),
            tenant_id="ztk-proj",
            title="Prompt injection blocked",
            description="Content blocked by L1.03 guard — requires human review",
            priority=HITLPriority.HIGH,
        )
        assert item_id is not None
        assert len(item_id) > 0

    def test_assign_and_resolve(self) -> None:
        item_id = enqueue_item(
            finding_id=str(uuid.uuid4()),
            tenant_id="ztk-proj",
            title="Test HITL item",
            description="Testing HITL workflow",
            priority=HITLPriority.MEDIUM,
        )
        assert item_id is not None
        assert assign_item(item_id, "analyst@empresa.com.br") is True
        assert resolve_item(item_id, "False positive confirmed") is True

    def test_sla_breach_detection(self) -> None:
        from layer6_governance.hitl_gateway import _hitl_queue
        item_id = enqueue_item(
            finding_id=str(uuid.uuid4()),
            tenant_id="ztk-proj",
            title="Urgent item",
            description="Needs immediate attention",
            priority=HITLPriority.CRITICAL,
        )
        assert item_id is not None
        # Force SLA breach by backdating
        if item_id in _hitl_queue:
            _hitl_queue[item_id].sla_deadline = datetime.now(timezone.utc) - timedelta(hours=1)
        breached = check_sla_breaches()
        assert len(breached) >= 1

    def test_escalation_chain(self) -> None:
        item_id = enqueue_item(
            finding_id=str(uuid.uuid4()),
            tenant_id="ztk-proj",
            title="Escalation test",
            description="Testing escalation workflow",
            priority=HITLPriority.HIGH,
        )
        assert item_id is not None
        assert escalate_item(item_id) == EscalationLevel.LEVEL_1
        assert escalate_item(item_id) == EscalationLevel.LEVEL_2
        assert escalate_item(item_id) == EscalationLevel.LEVEL_3
        assert escalate_item(item_id) == EscalationLevel.LEVEL_4

    def test_pending_count(self) -> None:
        from layer6_governance.hitl_gateway import _hitl_queue
        initial = get_pending_count()
        enqueue_item(str(uuid.uuid4()), "ztk-proj", "Test", "Desc", HITLPriority.LOW)
        enqueue_item(str(uuid.uuid4()), "ztk-proj", "Test2", "Desc2", HITLPriority.MEDIUM)
        assert get_pending_count() == initial + 2

    def test_jira_ticket(self) -> None:
        item_id = enqueue_item(
            finding_id=str(uuid.uuid4()),
            tenant_id="ztk-proj",
            title="Jira test",
            description="Testing Jira integration",
            priority=HITLPriority.MEDIUM,
        )
        assert item_id is not None
        ticket = create_jira_ticket(item_id, "ZTK")
        assert ticket.startswith("ZTK-")
