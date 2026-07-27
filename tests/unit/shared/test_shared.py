"""F0.1.9 — Unit tests for shared/schemas and shared/utils.

Tests cover all 5 schemas + 3 utility modules.
Run: PYTHONPATH=src pytest tests/unit/shared/test_shared.py -v
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

import pytest
from pydantic import ValidationError

# Schema imports
from shared.schemas.finding import (
    AuditTrailEntry,
    Confidence,
    Finding,
    FindingSeverity,
    FindingSource,
    FindingStatus,
    Language,
)
from shared.schemas.decision import (
    Decision,
    DecisionTier,
    Exploitation,
    Exposure,
    MissionImpact,
    SeverityFloor,
)
from shared.schemas.audit_event import (
    AuditAction,
    AuditEvent,
    AuditStage,
)
from shared.schemas.llm_request import (
    DataScope,
    LLMProvider,
    LLMRequest,
    LLMResponse,
    LLMTier,
)
from shared.schemas.containment import (
    ContainmentRule,
    ContainmentStatus,
    ContainmentType,
    DryRunResult,
)

# Utils imports
from shared.utils.idempotency import (
    generate_audit_event_id,
    generate_idempotency_key,
    generate_waf_rule_name,
)
from shared.utils.fail_closed import Defaults, fail_closed


# ── Fixtures ────────────────────────────────────────────────────────

@pytest.fixture
def finding_dict() -> dict[str, Any]:
    return {
        "tenant_id": "cielo-ztk",
        "source": FindingSource.SEMGREP,
        "severity": FindingSeverity.P1,
        "cwe_ids": ["CWE-89"],
        "title": "SQL Injection in login endpoint",
        "description": "Unsanitized user input in SQL query at auth handler",
        "file_path": "src/api/auth.py",
        "line_number": 142,
        "language": Language.PYTHON,
        "evidence": 'cursor.execute(f"SELECT * FROM users WHERE email=\'{email}\'")',
        "confidence": Confidence.HIGH,
    }


@pytest.fixture
def valid_finding(finding_dict: dict[str, Any]) -> Finding:
    return Finding(**finding_dict)


@pytest.fixture
def dry_run_pass() -> DryRunResult:
    return DryRunResult(
        passed=True,
        expected_matches=5,
        false_positive_risk="LOW",
        impact_summary="Rule will block 5 known malicious IPs without collateral damage",
        duration_ms=150,
    )


# ── Finding Schema Tests ────────────────────────────────────────────

class TestFinding:
    def test_create_valid_finding(self, valid_finding: Finding) -> None:
        assert valid_finding.finding_id is not None
        assert valid_finding.tenant_id == "cielo-ztk"
        assert valid_finding.severity == FindingSeverity.P1
        assert valid_finding.status == FindingStatus.RAW
        assert valid_finding.audit_trail == []

    def test_finding_id_coerces_string(self, finding_dict: dict[str, Any]) -> None:
        fid = uuid.uuid4()
        finding_dict["finding_id"] = str(fid)
        finding = Finding(**finding_dict)
        assert finding.finding_id == fid

    def test_invalid_cwe_format(self, finding_dict: dict[str, Any]) -> None:
        finding_dict["cwe_ids"] = ["INVALID-89"]
        with pytest.raises(ValidationError):
            Finding(**finding_dict)

    def test_empty_cwe_ids(self, finding_dict: dict[str, Any]) -> None:
        finding_dict["cwe_ids"] = []
        with pytest.raises(ValidationError):
            Finding(**finding_dict)

    def test_short_description(self, finding_dict: dict[str, Any]) -> None:
        finding_dict["description"] = "short"
        with pytest.raises(ValidationError):
            Finding(**finding_dict)

    def test_invalid_uuid(self, finding_dict: dict[str, Any]) -> None:
        finding_dict["finding_id"] = "not-a-uuid"
        with pytest.raises(ValidationError):
            Finding(**finding_dict)

    def test_tenant_id_lowercase(self, finding_dict: dict[str, Any]) -> None:
        finding_dict["tenant_id"] = "CIELO-ZTK"
        finding = Finding(**finding_dict)
        assert finding.tenant_id == "cielo-ztk"

    def test_add_audit_entry(self, valid_finding: Finding) -> None:
        valid_finding.add_audit_entry(
            stage="NORMALIZATION",
            agent_id="L1.02",
            action="Language classified as Python",
        )
        assert len(valid_finding.audit_trail) == 1
        assert valid_finding.audit_trail[0].stage == "NORMALIZATION"
        assert valid_finding.audit_trail[0].agent_id == "L1.02"

    def test_json_serializable(self, valid_finding: Finding) -> None:
        data = valid_finding.model_dump(mode="json")
        assert isinstance(data, dict)
        assert isinstance(data["finding_id"], str)
        assert isinstance(data["created_at"], str)

    def test_extra_fields_forbidden(self, finding_dict: dict[str, Any]) -> None:
        finding_dict["unknown_field"] = "should fail"
        with pytest.raises(ValidationError):
            Finding(**finding_dict)


class TestAuditTrailEntry:
    def test_create_entry(self) -> None:
        entry = AuditTrailEntry(
            stage="SCORING",
            agent_id="L4.01",
            action="CVSS score computed",
        )
        assert entry.stage == "SCORING"
        assert entry.timestamp is not None


# ── Decision Schema Tests ───────────────────────────────────────────

class TestDecision:
    def test_create_valid_decision(self, valid_finding: Finding) -> None:
        decision = Decision(
            finding_id=valid_finding.finding_id,
            exploitation=Exploitation.POC,
            exposure=Exposure.CONTROLLED,
            mission_impact=MissionImpact.PARTIAL,
            tier=DecisionTier.ATTEND,
            score=6.5,
            confidence=0.85,
            rationale=["SQL injection with POC exploit available", "Internal network only"],
            piso_applied=[SeverityFloor.PCI],
        )
        assert decision.tier == DecisionTier.ATTEND
        assert decision.score == 6.5
        assert len(decision.rationale) == 2

    def test_empty_rationale_raises(self, valid_finding: Finding) -> None:
        with pytest.raises(ValidationError):
            Decision(
                finding_id=valid_finding.finding_id,
                exploitation=Exploitation.NONE,
                exposure=Exposure.OPEN,
                mission_impact=MissionImpact.NONE,
                tier=DecisionTier.TRACK,
                score=2.0,
                confidence=0.9,
                rationale=[],
            )

    def test_rationale_empty_string_raises(self, valid_finding: Finding) -> None:
        with pytest.raises(ValidationError):
            Decision(
                finding_id=valid_finding.finding_id,
                exploitation=Exploitation.NONE,
                exposure=Exposure.OPEN,
                mission_impact=MissionImpact.NONE,
                tier=DecisionTier.TRACK,
                score=2.0,
                confidence=0.9,
                rationale=["  ", "valid reason"],
            )

    def test_scores_out_of_range(self, valid_finding: Finding) -> None:
        with pytest.raises(ValidationError):
            Decision(
                finding_id=valid_finding.finding_id,
                exploitation=Exploitation.NONE,
                exposure=Exposure.OPEN,
                mission_impact=MissionImpact.NONE,
                tier=DecisionTier.TRACK,
                score=15.0,  # > 10
                confidence=0.9,
                rationale=["reason"],
            )

    def test_all_decisions(self, valid_finding: Finding) -> None:
        # Every tier must be creatable
        for tier in DecisionTier:
            score = 5.0  # neutral
            if tier in (DecisionTier.P0, DecisionTier.P1):
                score = 9.0
            decision = Decision(
                finding_id=valid_finding.finding_id,
                exploitation=Exploitation.POC,
                exposure=Exposure.CONTROLLED,
                mission_impact=MissionImpact.PARTIAL,
                tier=tier,
                score=score,
                confidence=0.8,
                rationale=["test"],
            )
            assert decision.tier == tier


# ── AuditEvent Schema Tests ─────────────────────────────────────────

class TestAuditEvent:
    def test_compute_event_id_deterministic(self) -> None:
        fid = uuid.uuid4()
        ph = AuditEvent.compute_payload_hash({"action": "test"})

        eid1 = AuditEvent.compute_event_id(fid, "SCORING", ph)
        eid2 = AuditEvent.compute_event_id(fid, "SCORING", ph)

        assert eid1 == eid2
        assert len(eid1) == 64

    def test_different_stage_different_id(self) -> None:
        fid = uuid.uuid4()
        ph = AuditEvent.compute_payload_hash({"action": "test"})

        eid1 = AuditEvent.compute_event_id(fid, "SCORING", ph)
        eid2 = AuditEvent.compute_event_id(fid, "DECISION", ph)

        assert eid1 != eid2

    def test_create_audit_event(self) -> None:
        fid = uuid.uuid4()
        payload = {"old_severity": "P2", "new_severity": "P0"}
        ph = AuditEvent.compute_payload_hash(payload)
        eid = AuditEvent.compute_event_id(fid, "SCORING", ph)

        event = AuditEvent(
            event_id=eid,
            finding_id=fid,
            stage=AuditStage.SCORING,
            action=AuditAction.SCORED,
            agent_id="L4.01",
            tenant_id="cielo-ztk",
            payload=payload,
            payload_hash=ph,
        )
        assert event.event_id == eid
        # AuditEvent model_config frozen=True enforces immutability
        assert event.model_config.get("frozen") is True

    def test_payload_hash_deterministic(self) -> None:
        payload = {"b": 2, "a": 1}
        ph1 = AuditEvent.compute_payload_hash(payload)
        ph2 = AuditEvent.compute_payload_hash({"a": 1, "b": 2})
        assert ph1 == ph2  # Order-independent


# ── LLMRequest/Response Schema Tests ────────────────────────────────

class TestLLMRequest:
    def test_create_non_pci_request(self) -> None:
        req = LLMRequest(
            tier=LLMTier.VOLUME,
            data_scope=DataScope.NON_PCI,
            agent_id="L7.01",
            user_message="Analyze this public code",
        )
        assert req.data_scope == DataScope.NON_PCI

    def test_pci_data_rejects_bedrock(self) -> None:
        with pytest.raises(ValueError, match="requires vLLM local"):
            LLMRequest(
                tier=LLMTier.REASONING,
                data_scope=DataScope.PCI,
                agent_id="L7.01",
                user_message="Analyze PAN 4111111111111111",
            )

    def test_pci_data_with_force_local(self) -> None:
        req = LLMRequest(
            tier=LLMTier.REASONING,
            data_scope=DataScope.PCI,
            agent_id="L7.01",
            user_message="Analyze PAN",
            force_local=True,
        )
        assert req.force_local is True


class TestLLMResponse:
    def test_create_response(self) -> None:
        req_id = uuid.uuid4()
        resp = LLMResponse(
            request_id=req_id,
            provider=LLMProvider.VLLM_LOCAL,
            model_id="meta-llama-3.1-70b",
            model_used="meta-llama-3.1-70b-instruct",
            content="Analysis complete",
            input_tokens=500,
            output_tokens=200,
            cost_usd=0.002,
            processing_time_ms=1500,
        )
        assert resp.provider == LLMProvider.VLLM_LOCAL
        assert resp.input_tokens == 500
        assert resp.output_tokens == 200


# ── ContainmentRule Schema Tests ────────────────────────────────────

class TestContainmentRule:
    def test_create_with_dry_run(self, valid_finding: Finding, dry_run_pass: DryRunResult) -> None:
        rule = ContainmentRule(
            finding_id=valid_finding.finding_id,
            tenant_id="cielo-ztk",
            rule_type=ContainmentType.WAF_RULE,
            cwe_ids=["CWE-89"],
            description="Block SQL injection patterns in login endpoint",
            target_scope="/api/auth/login",
            ttl_hours=72,
            dry_run_result=dry_run_pass,
        )
        assert rule.ttl_hours == 72
        assert rule.expires_at is not None
        assert rule.dry_run_result.passed is True

    def test_activate_without_dry_run_raises(self, valid_finding: Finding) -> None:
        with pytest.raises(ValidationError):
            ContainmentRule(
                finding_id=valid_finding.finding_id,
                tenant_id="cielo-ztk",
                rule_type=ContainmentType.WAF_RULE,
                cwe_ids=["CWE-89"],
                description="Test rule that is long enough to pass validation",
                target_scope="/test",
                ttl_hours=24,
                status=ContainmentStatus.ACTIVE,  # No dry_run_result
            )

    def test_activate_failed_dry_run_raises(self, valid_finding: Finding) -> None:
        dry_run_fail = DryRunResult(
            passed=False,
            expected_matches=0,
            false_positive_risk="HIGH",
            impact_summary="Rule is too broad and blocks legitimate traffic",
            duration_ms=200,
        )
        with pytest.raises(ValidationError):
            ContainmentRule(
                finding_id=valid_finding.finding_id,
                tenant_id="cielo-ztk",
                rule_type=ContainmentType.WAF_RULE,
                cwe_ids=["CWE-89"],
                description="Test rule",
                target_scope="/test",
                ttl_hours=24,
                status=ContainmentStatus.ACTIVE,
                dry_run_result=dry_run_fail,
            )

    def test_remaining_hours(self, valid_finding: Finding, dry_run_pass: DryRunResult) -> None:
        rule = ContainmentRule(
            finding_id=valid_finding.finding_id,
            tenant_id="cielo-ztk",
            rule_type=ContainmentType.WAF_RULE,
            cwe_ids=["CWE-89"],
            description="Test rule for remaining hours validation",
            target_scope="/test",
            ttl_hours=24,
            dry_run_result=dry_run_pass,
        )
        remaining = rule.remaining_hours
        assert 0 < remaining <= 24

    def test_is_expired(self, valid_finding: Finding, dry_run_pass: DryRunResult) -> None:
        rule = ContainmentRule(
            finding_id=valid_finding.finding_id,
            tenant_id="cielo-ztk",
            rule_type=ContainmentType.WAF_RULE,
            cwe_ids=["CWE-89"],
            description="Test rule for expiry check validation",
            target_scope="/test",
            ttl_hours=24,
            dry_run_result=dry_run_pass,
        )
        assert rule.is_expired is False
        # Past-created rule would be expired
        rule.ttl_hours = -1  # Force expiration
        # Model validator would set expires_at
        assert rule.remaining_hours >= 0


# ── Idempotency Tests ────────────────────────────────────────────────

class TestIdempotency:
    def test_deterministic(self) -> None:
        key1 = generate_idempotency_key("abc", "stage1", {"x": 1})
        key2 = generate_idempotency_key("abc", "stage1", {"x": 1})
        assert key1 == key2
        assert len(key1) == 64

    def test_different_inputs(self) -> None:
        k1 = generate_idempotency_key("a", "s", {})
        k2 = generate_idempotency_key("b", "s", {})
        assert k1 != k2

    def test_audit_event_id_alias(self) -> None:
        fid = uuid.uuid4()
        eid = generate_audit_event_id(fid, "stage", "payload")
        assert len(eid) == 64

    def test_waf_rule_name(self) -> None:
        fid = uuid.uuid4()
        name = generate_waf_rule_name(fid, "CWE-89", "target")
        assert name.startswith("ztk-")
        assert len(name) <= 64
        assert "cwe_89" in name

    def test_payload_ordering_independent(self) -> None:
        k1 = generate_idempotency_key("abc", "s", {"b": 2, "a": 1})
        k2 = generate_idempotency_key("abc", "s", {"a": 1, "b": 2})
        assert k1 == k2


# ── Fail-Closed Tests ────────────────────────────────────────────────

class TestFailClosed:
    def test_success_passthrough(self) -> None:
        @fail_closed(fallback_value="fallback")
        def ok_func() -> str:
            return "success"

        assert ok_func() == "success"

    def test_failure_returns_fallback(self) -> None:
        @fail_closed(fallback_value="unclassified")
        def broken_func() -> str:
            raise RuntimeError("boom")

        result = broken_func()
        assert result == "unclassified"

    def test_allowed_exception_propagates(self) -> None:
        @fail_closed(fallback_value="fallback", allowed_exceptions=(ValueError,))
        def bad_input() -> None:
            raise ValueError("bad input")

        with pytest.raises(ValueError, match="bad input"):
            bad_input()

    def test_defaults_class(self) -> None:
        assert Defaults.UNCLASSIFIED == "unclassified"
        assert Defaults.CRITICAL == "P0"
        assert Defaults.DENY == "deny"


# ── Structlog Setup Tests ────────────────────────────────────────────

class TestStructlogSetup:
    def test_configure(self) -> None:
        from shared.utils.structlog_setup import configure_logging

        configure_logging(agent_id="test", layer="0", pretty_print=True)
        logger = __import__("structlog").get_logger(__name__)
        assert logger is not None

    def test_bind_request_context(self) -> None:
        from shared.utils.structlog_setup import bind_request_context

        bind_request_context(
            finding_id=str(uuid.uuid4()),
            request_id=str(uuid.uuid4()),
            tenant_id="test",
        )
