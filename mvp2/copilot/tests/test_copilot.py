"""Tests for the ZTK Copilot module (MVP2 M4).

Tests cover all components: models, config, prompt builder, RAG retriever,
handler (with mocked Claude), and observability.

Run: pytest mvp2/copilot/tests/test_copilot.py -v
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

# Ensure the copilot package is importable
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from copilot.models import (  # type: ignore[import-untyped]
    AmbiguitySignal,
    AmbiguityType,
    AnalysisTier,
    Confidence,
    CopilotAnalysis,
    CopilotRequest,
    CopilotResponse,
    FindingContext,
    Severity,
)
from copilot.config import CopilotSettings, get_settings  # type: ignore[import-untyped]
from copilot.prompt_builder import PromptBuilder  # type: ignore[import-untyped]
from copilot.rag_retriever import RagDocument, RagRetriever  # type: ignore[import-untyped]
from copilot.observability import CopilotMetrics, get_logger  # type: ignore[import-untyped]
from copilot.handler import CopilotHandler  # type: ignore[import-untyped]


# ── Fixtures ────────────────────────────────────────────────────────

@pytest.fixture
def valid_finding() -> FindingContext:
    return FindingContext(
        finding_id=uuid.uuid4(),
        tenant_id="ztk-proj",
        source="Semgrep",
        severity=Severity.P1,
        cwe_ids=["CWE-89"],
        file_path="src/api/auth.py",
        line_number=142,
        description="SQL injection via unsanitized user input in login query",
        evidence='cursor.execute(f"SELECT * FROM users WHERE email=\'{email}\'")',
        decision_tier=AnalysisTier.ATTEND,
        score=7.5,
        cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
        language="python",
    )


@pytest.fixture
def valid_request(valid_finding: FindingContext) -> CopilotRequest:
    return CopilotRequest(finding=valid_finding)


@pytest.fixture
def settings() -> CopilotSettings:
    return CopilotSettings(
        bedrock_region="us-east-1",
        bedrock_haiku_model="anthropic.claude-3-5-haiku-20241022-v1:0",
        bedrock_sonnet_model="anthropic.claude-3-5-sonnet-20241022-v2:0",
        shadow_mode_default=True,
    )


@pytest.fixture
def prompt_builder(settings: CopilotSettings) -> PromptBuilder:
    return PromptBuilder(settings)


@pytest.fixture
def rag_retriever(settings: CopilotSettings) -> RagRetriever:
    return RagRetriever(settings)


# ── Models Tests ─────────────────────────────────────────────────────

class TestFindingContext:
    def test_valid_finding(self, valid_finding: FindingContext) -> None:
        assert valid_finding.finding_id is not None
        assert valid_finding.severity == Severity.P1
        assert "CWE-89" in valid_finding.cwe_ids

    def test_finding_id_coerces_string(self) -> None:
        fid = uuid.uuid4()
        finding = FindingContext(
            finding_id=str(fid),  # type: ignore[arg-type]
            tenant_id="test",
            source="test",
            severity=Severity.P3,
            cwe_ids=["CWE-79"],
            file_path="test.py",
            line_number=1,
            description="Test finding description long enough",
            evidence="some code here",
            decision_tier=AnalysisTier.ATTEND,
            score=5.0,
        )
        assert finding.finding_id == fid

    def test_invalid_uuid_raises(self) -> None:
        with pytest.raises(ValidationError):
            FindingContext(
                finding_id="not-a-uuid",  # type: ignore[arg-type]
                tenant_id="test",
                source="test",
                severity=Severity.P3,
                cwe_ids=["CWE-79"],
                file_path="test.py",
                line_number=1,
                description="Test finding description",
                evidence="code",
                decision_tier=AnalysisTier.ATTEND,
                score=5.0,
            )

    def test_short_description_raises(self) -> None:
        with pytest.raises(ValidationError):
            FindingContext(
                finding_id=uuid.uuid4(),
                tenant_id="test",
                source="test",
                severity=Severity.P3,
                cwe_ids=["CWE-79"],
                file_path="test.py",
                line_number=1,
                description="short",
                evidence="code",
                decision_tier=AnalysisTier.ATTEND,
                score=5.0,
            )

    def test_score_out_of_range_raises(self) -> None:
        with pytest.raises(ValidationError):
            FindingContext(
                finding_id=uuid.uuid4(),
                tenant_id="test",
                source="test",
                severity=Severity.P3,
                cwe_ids=["CWE-79"],
                file_path="test.py",
                line_number=1,
                description="Valid description text",
                evidence="code",
                decision_tier=AnalysisTier.ATTEND,
                score=11.0,  # Out of range
            )

    def test_empty_cwe_ids_raises(self) -> None:
        with pytest.raises(ValidationError):
            FindingContext(
                finding_id=uuid.uuid4(),
                tenant_id="test",
                source="test",
                severity=Severity.P3,
                cwe_ids=[],  # Empty
                file_path="test.py",
                line_number=1,
                description="Valid description text",
                evidence="code",
                decision_tier=AnalysisTier.ATTEND,
                score=5.0,
            )


class TestCopilotAnalysis:
    def test_defaults(self, valid_finding: FindingContext) -> None:
        analysis = CopilotAnalysis(
            finding_id=valid_finding.finding_id,
            tier_requested=AnalysisTier.ATTEND,
            tier_actual=AnalysisTier.ATTEND,
            model_used="claude-3-5-haiku",
            confidence=Confidence.HIGH,
            summary="This is a valid summary of the finding that is long enough",
            recommendation="Apply parameterized queries to fix the SQL injection",
            ambiguity_signals=[],
            rag_hits=3,
            rag_relevant=2,
            prompt_version="1.0.0",
            processing_time_ms=1500,
        )
        assert analysis.analysis_id is not None
        assert analysis.timestamp is not None
        assert analysis.escalation_required is False

    def test_rag_relevant_exceeds_rag_hits_raises(self, valid_finding: FindingContext) -> None:
        with pytest.raises(ValidationError):
            CopilotAnalysis(
                finding_id=valid_finding.finding_id,
                tier_requested=AnalysisTier.ATTEND,
                tier_actual=AnalysisTier.ATTEND,
                model_used="claude-3-5-haiku",
                confidence=Confidence.HIGH,
                summary="Valid summary text that meets minimum length",
                recommendation="Apply fix",
                ambiguity_signals=[],
                rag_hits=1,
                rag_relevant=5,  # > rag_hits
                prompt_version="1.0.0",
                processing_time_ms=1000,
            )


class TestAmbiguitySignal:
    def test_valid_signal(self) -> None:
        signal = AmbiguitySignal(
            signal_type=AmbiguityType.MISSING_CONTEXT,  # type: ignore[arg-type]
            description="No database schema available for SQLi context",
            severity_impact="Cannot confirm actual exploitability",
            suggested_action="Request DB schema from development team",
            confidence=Confidence.MEDIUM,  # type: ignore[arg-type]
        )
        assert signal.signal_type == AmbiguityType.MISSING_CONTEXT

    def test_short_description_raises(self) -> None:
        with pytest.raises(ValidationError):
            AmbiguitySignal(
                signal_type=AmbiguityType.VERSION_CONFLICT,  # type: ignore[arg-type]
                description="short",  # Too short
                severity_impact="Impact",
                suggested_action="Fix it properly now",
                confidence=Confidence.LOW,  # type: ignore[arg-type]
            )


class TestCopilotRequest:
    def test_defaults(self, valid_finding: FindingContext) -> None:
        request = CopilotRequest(finding=valid_finding)
        assert request.shadow_mode is True
        assert request.request_id is not None
        assert request.timestamp is not None

    def test_explicit_shadow_mode(self, valid_finding: FindingContext) -> None:
        request = CopilotRequest(finding=valid_finding, shadow_mode=False)
        assert request.shadow_mode is False


class TestCopilotResponse:
    def test_success_response(self, valid_finding: FindingContext) -> None:
        analysis = CopilotAnalysis(
            finding_id=valid_finding.finding_id,
            tier_requested=AnalysisTier.ATTEND,
            tier_actual=AnalysisTier.ATTEND,
            model_used="claude-3-5-haiku",
            confidence=Confidence.HIGH,
            summary="Valid summary of the SQL injection finding",
            recommendation="Use parameterized queries instead of string formatting",
            ambiguity_signals=[],
            rag_hits=2,
            rag_relevant=2,
            prompt_version="1.0.0",
            processing_time_ms=1000,
        )
        response = CopilotResponse(
            request_id=uuid.uuid4(),
            finding_id=valid_finding.finding_id,
            analysis=analysis,
            error=None,
            shadow_mode=True,
            escalation_triggered=False,
            processing_time_ms=1000,
            timestamp=datetime.now(timezone.utc),
        )
        assert response.analysis is not None
        assert response.error is None

    def test_error_response(self, valid_finding: FindingContext) -> None:
        response = CopilotResponse(
            request_id=uuid.uuid4(),
            finding_id=valid_finding.finding_id,
            analysis=None,
            error="Bedrock unavailable",
            shadow_mode=True,
            escalation_triggered=False,
            processing_time_ms=500,
            timestamp=datetime.now(timezone.utc),
        )
        assert response.analysis is None
        assert response.error == "Bedrock unavailable"


# ── Config Tests ─────────────────────────────────────────────────────

class TestCopilotSettings:
    def test_defaults(self) -> None:
        settings = CopilotSettings()
        assert settings.bedrock_region == "us-east-1"
        assert "haiku" in settings.bedrock_haiku_model
        assert "sonnet" in settings.bedrock_sonnet_model
        assert settings.shadow_mode_default is True
        assert settings.bedrock_temperature == 0.1

    def test_env_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("COPILOT_BEDROCK_REGION", "sa-east-1")
        monkeypatch.setenv("COPILOT_LOG_LEVEL", "DEBUG")
        settings = CopilotSettings()
        assert settings.bedrock_region == "sa-east-1"
        assert settings.log_level == "DEBUG"

    def test_invalid_log_level(self) -> None:
        with pytest.raises(ValidationError):
            CopilotSettings(log_level="TRACE")  # type: ignore[arg-type]

    def test_invalid_temperature(self) -> None:
        with pytest.raises(ValidationError):
            CopilotSettings(bedrock_temperature=1.5)  # type: ignore[arg-type]

    def test_local_dev_detection(self) -> None:
        settings = CopilotSettings()
        # In test environment, AWS_EXECUTION_ENV is typically not set
        assert settings.is_local_development is True

    def test_get_settings_cache(self) -> None:
        s1 = get_settings()
        s2 = get_settings()
        assert s1 is s2


# ── Prompt Builder Tests ─────────────────────────────────────────────

class TestPromptBuilder:
    def test_fixed_context(self, prompt_builder: PromptBuilder) -> None:
        ctx = prompt_builder.fixed_context
        assert "security copilot" in ctx.lower()
        assert "SSVC" in ctx
        assert "Non-Negotiable" in ctx
        assert "PCI" in ctx
        assert "LGPD" in ctx
        assert "ANTIFRAUDE" in ctx

    def test_build_analysis_prompt(self, prompt_builder: PromptBuilder, valid_finding: FindingContext) -> None:
        system, user = prompt_builder.build_analysis_prompt(valid_finding)
        assert len(system) > 100
        assert len(user) > 50
        assert str(valid_finding.finding_id) in user
        assert "CWE-89" in user
        assert "SQL injection" in user
        assert "Output Format (JSON)" in user

    def test_parse_valid_response(self, prompt_builder: PromptBuilder, valid_finding: FindingContext) -> None:
        raw = json.dumps({
            "is_true_positive": True,
            "confidence": "HIGH",
            "severity_assessment": "P1",
            "severity_justification": "SQL injection with clear evidence of unsanitized input",
            "remediation_summary": "Use parameterized queries",
            "remediation_steps": ["Replace f-string with parameterized query"],
            "piso_applied": ["PCI"],
            "ambiguity_signals": [],
            "requires_sonnet_escalation": False,
        })
        signals = prompt_builder.parse_response(raw, valid_finding, "haiku", 1000)
        assert len(signals) == 0

    def test_parse_response_with_signals(self, prompt_builder: PromptBuilder, valid_finding: FindingContext) -> None:
        raw = json.dumps({
            "is_true_positive": True,
            "confidence": "MEDIUM",
            "severity_assessment": "P2",
            "severity_justification": "Possible SQLi but no DB schema available for confirmation",
            "remediation_summary": "Use parameterized queries",
            "remediation_steps": ["Replace f-string"],
            "piso_applied": ["PCI"],
            "ambiguity_signals": [
                {
                    "type": "MISSING_CONTEXT",
                    "description": "No database schema available to confirm table structure",
                    "severity_impact": "Cannot confirm if sensitive columns are accessible",
                    "suggested_action": "Request DB schema from development team",
                }
            ],
            "requires_sonnet_escalation": True,
        })
        signals = prompt_builder.parse_response(raw, valid_finding, "haiku", 1000)
        assert len(signals) == 1
        assert signals[0].signal_type == AmbiguityType.MISSING_CONTEXT

    def test_parse_invalid_json(self, prompt_builder: PromptBuilder, valid_finding: FindingContext) -> None:
        signals = prompt_builder.parse_response("not json", valid_finding, "haiku", 1000)
        assert len(signals) == 1
        assert signals[0].signal_type == AmbiguityType.MISSING_CONTEXT

    def test_parse_skips_malformed_signals(self, prompt_builder: PromptBuilder, valid_finding: FindingContext) -> None:
        raw = json.dumps({
            "is_true_positive": True,
            "confidence": "HIGH",
            "severity_assessment": "P1",
            "severity_justification": "Valid justification for severity assessment",
            "remediation_summary": "Fix it",
            "remediation_steps": ["Step 1"],
            "piso_applied": [],
            "ambiguity_signals": [
                {"type": "INVALID_TYPE", "description": "malformed signal"},
                {
                    "type": "VERSION_CONFLICT",
                    "description": "Dependency version mismatch detected in the affected file",
                    "severity_impact": "May affect remediation applicability",
                    "suggested_action": "Check dependency version compatibility",
                }
            ],
            "requires_sonnet_escalation": False,
        })
        signals = prompt_builder.parse_response(raw, valid_finding, "haiku", 1000)
        # Malformed signal skipped, valid one kept
        assert len(signals) == 1
        assert signals[0].signal_type == AmbiguityType.VERSION_CONFLICT


# ── RAG Retriever Tests ──────────────────────────────────────────────

class TestRagRetriever:
    def test_retrieve_by_cwe(self, rag_retriever: RagRetriever, valid_finding: FindingContext) -> None:
        docs = rag_retriever.retrieve(valid_finding)
        # CWE-89 should match rag-001 (SQL Injection)
        assert len(docs) > 0
        cwe_89_docs = [d for d in docs if "CWE-89" in d.cwe_ids]
        assert len(cwe_89_docs) > 0

    def test_retrieve_no_match(self, rag_retriever: RagRetriever) -> None:
        finding = FindingContext(
            finding_id=uuid.uuid4(),
            tenant_id="test",
            source="test",
            severity=Severity.P4,
            cwe_ids=["CWE-9999"],  # Non-existent CWE
            file_path="test.py",
            line_number=1,
            description="Test finding with no RAG match available",
            evidence="code",
            decision_tier=AnalysisTier.ATTEND,
            score=3.0,
        )
        docs = rag_retriever.retrieve(finding)
        assert len(docs) == 0

    def test_format_context(self, rag_retriever: RagRetriever, valid_finding: FindingContext) -> None:
        docs = rag_retriever.retrieve(valid_finding)
        if docs:
            ctx = rag_retriever.format_context(docs)
            assert "RAG Context" in ctx
            assert "knowledge base" in ctx
        else:
            ctx = rag_retriever.format_context([])
            assert "No relevant context" in ctx

    def test_document_count(self, rag_retriever: RagRetriever) -> None:
        count = rag_retriever.document_count
        assert count > 0

    def test_max_docs_limit(self, rag_retriever: RagRetriever) -> None:
        finding = FindingContext(
            finding_id=uuid.uuid4(),
            tenant_id="test",
            source="test",
            severity=Severity.P2,
            cwe_ids=["CWE-89", "CWE-79", "CWE-78", "CWE-502", "CWE-327", "CWE-798"],
            file_path="test.py",
            line_number=1,
            description="Complex finding with multiple CWE patterns detected",
            evidence="code",
            decision_tier=AnalysisTier.ATTEND,
            score=7.0,
        )
        docs = rag_retriever.retrieve(finding, max_docs=2)
        assert len(docs) <= 2

    def test_relevance_scoring(self, rag_retriever: RagRetriever) -> None:
        finding = FindingContext(
            finding_id=uuid.uuid4(),
            tenant_id="test",
            source="test",
            severity=Severity.P1,
            cwe_ids=["CWE-89"],
            file_path="test.py",
            line_number=1,
            description="SQL injection finding needs RAG context",
            evidence="SELECT * FROM users WHERE id = " + "input",
            decision_tier=AnalysisTier.ATTEND,
            score=8.0,
        )
        docs = rag_retriever.retrieve(finding)
        assert len(docs) > 0
        # All retrieved docs should have score > threshold
        for doc in docs:
            assert doc.score >= 0.65


# ── Handler Tests ────────────────────────────────────────────────────

class TestCopilotHandler:
    def test_handler_initialization(self, settings: CopilotSettings) -> None:
        handler = CopilotHandler(settings)
        assert handler._settings == settings
        assert handler.metrics.total_analyses == 0

    def test_process_with_mock_claude(
        self, settings: CopilotSettings, valid_request: CopilotRequest
    ) -> None:
        handler = CopilotHandler(settings)

        mock_response = json.dumps({
            "is_true_positive": True,
            "confidence": "HIGH",
            "severity_assessment": "P1",
            "severity_justification": "SQL injection confirmed with clear evidence of unsanitized input in the login query",
            "remediation_summary": "Replace f-string with parameterized query using the database driver",
            "remediation_steps": [
                "Replace f-string query with parameterized query",
                "Add input validation for email format",
                "Enable prepared statements at driver level"
            ],
            "piso_applied": ["PCI"],
            "ambiguity_signals": [],
            "requires_sonnet_escalation": False,
        })

        with patch.object(handler._claude, "_get_client", return_value=MagicMock()) as mock_client:
            mock_client.return_value.invoke_model.return_value = {
                "body": MagicMock(read=lambda: json.dumps({
                    "content": [{"type": "text", "text": mock_response}]
                }).encode())
            }

            response = handler.process(valid_request)

        assert response.analysis is not None
        assert response.error is None
        assert response.analysis.confidence == Confidence.HIGH
        assert response.shadow_mode is True
        assert response.escalation_triggered is False

    def test_process_escalation_to_sonnet(
        self, settings: CopilotSettings, valid_request: CopilotRequest
    ) -> None:
        handler = CopilotHandler(settings)

        # Haiku response with 2 ambiguity signals (meets threshold of 2)
        haiku_response = json.dumps({
            "is_true_positive": True,
            "confidence": "MEDIUM",
            "severity_assessment": "P1",
            "severity_justification": "Likely SQLi but evidence is incomplete for full confirmation",
            "remediation_summary": "Use parameterized queries",
            "remediation_steps": ["Replace f-string"],
            "piso_applied": ["PCI"],
            "ambiguity_signals": [
                {
                    "type": "MISSING_CONTEXT",
                    "description": "No database schema available to confirm table structure",
                    "severity_impact": "Cannot confirm which columns are accessible",
                    "suggested_action": "Request DB schema from development team",
                },
                {
                    "type": "VERSION_CONFLICT",
                    "description": "Unclear which SQL driver version is in use",
                    "severity_impact": "May affect remediation approach",
                    "suggested_action": "Check dependency lock file for driver version",
                }
            ],
            "requires_sonnet_escalation": True,
        })

        sonnet_response = json.dumps({
            "is_true_positive": True,
            "confidence": "HIGH",
            "severity_assessment": "P0",
            "severity_justification": "Confirmed SQL injection with high impact. Escalated to P0 due to authentication bypass risk",
            "remediation_summary": "Immediate remediation required: use parameterized queries",
            "remediation_steps": [
                "Replace all f-string queries in auth.py with parameterized queries",
                "Add WAF rule for SQLi patterns as temporary mitigation",
                "Audit all other query construction in the codebase"
            ],
            "piso_applied": ["PCI"],
            "ambiguity_signals": [],
            "requires_sonnet_escalation": False,
        })

        # Mock: first call = Haiku, second call = Sonnet
        responses = [
            json.dumps({
                "content": [{"type": "text", "text": haiku_response}]
            }).encode(),
            json.dumps({
                "content": [{"type": "text", "text": sonnet_response}]
            }).encode(),
        ]
        call_count = 0

        def mock_invoke(*args: Any, **kwargs: Any) -> dict:
            nonlocal call_count
            resp = responses[min(call_count, len(responses) - 1)]
            call_count += 1
            return {"body": MagicMock(read=lambda: resp)}

        with patch.object(handler._claude, "_get_client", return_value=MagicMock()) as mock_client:
            mock_client.return_value.invoke_model.side_effect = mock_invoke

            response = handler.process(valid_request)

        assert response.escalation_triggered is True
        assert response.analysis is not None
        assert response.analysis.model_used == settings.bedrock_sonnet_model

    def test_process_claude_unavailable(
        self, settings: CopilotSettings, valid_request: CopilotRequest
    ) -> None:
        handler = CopilotHandler(settings)

        with patch.object(handler._claude, "_get_client", return_value=None):
            response = handler.process(valid_request)

        assert response.analysis is None
        assert response.error is not None
        assert "Bedrock" in response.error

    def test_metrics_after_analysis(
        self, settings: CopilotSettings, valid_request: CopilotRequest
    ) -> None:
        handler = CopilotHandler(settings)

        mock_response = json.dumps({
            "is_true_positive": True,
            "confidence": "HIGH",
            "severity_assessment": "P1",
            "severity_justification": "SQL injection confirmed with clear evidence",
            "remediation_summary": "Use parameterized queries",
            "remediation_steps": ["Fix it"],
            "piso_applied": ["PCI"],
            "ambiguity_signals": [],
            "requires_sonnet_escalation": False,
        })

        with patch.object(handler._claude, "_get_client", return_value=MagicMock()) as mock_client:
            mock_client.return_value.invoke_model.return_value = {
                "body": MagicMock(read=lambda: json.dumps({
                    "content": [{"type": "text", "text": mock_response}]
                }).encode())
            }

            handler.process(valid_request)

        assert handler.metrics.total_analyses == 1
        assert handler.metrics.errors == 0
        assert handler.metrics.sonnet_escalations == 0

    def test_ready_when_bedrock_available(self, settings: CopilotSettings) -> None:
        handler = CopilotHandler(settings)
        with patch.object(handler._claude, "_get_client", return_value=MagicMock()):
            assert handler.ready is True

    def test_not_ready_when_bedrock_unavailable(self, settings: CopilotSettings) -> None:
        handler = CopilotHandler(settings)
        with patch.object(handler._claude, "_get_client", return_value=None):
            assert handler.ready is False


# ── Observability Tests ──────────────────────────────────────────────

class TestCopilotMetrics:
    def test_initial_state(self) -> None:
        metrics = CopilotMetrics()
        assert metrics.total_analyses == 0
        assert metrics.avg_processing_time_ms == 0.0
        assert metrics.escalation_rate == 0.0

    def test_record_haiku_analysis(self) -> None:
        metrics = CopilotMetrics()
        metrics.record_analysis(
            model_used="claude-3-5-haiku",
            rag_hits=3,
            ambiguity_count=1,
            processing_time_ms=1500,
        )
        assert metrics.total_analyses == 1
        assert metrics.haiku_analyses == 1
        assert metrics.sonnet_escalations == 0
        assert metrics.rag_hits_total == 3
        assert metrics.ambiguity_signals_total == 1

    def test_record_sonnet_escalation(self) -> None:
        metrics = CopilotMetrics()
        metrics.record_analysis(
            model_used="claude-3-5-sonnet",
            rag_hits=2,
            ambiguity_count=0,
            processing_time_ms=3000,
            escalated=True,
        )
        assert metrics.sonnet_escalations == 1
        assert metrics.haiku_analyses == 0

    def test_record_multiple(self) -> None:
        metrics = CopilotMetrics()
        for _ in range(5):
            metrics.record_analysis("haiku", 2, 0, 1000)
        for _ in range(2):
            metrics.record_analysis("sonnet", 3, 3, 3000, escalated=True)
        assert metrics.total_analyses == 7
        assert metrics.haiku_analyses == 5
        assert metrics.sonnet_escalations == 2
        assert metrics.escalation_rate == pytest.approx(2 / 7)
        assert metrics.avg_processing_time_ms > 0

    def test_record_error(self) -> None:
        metrics = CopilotMetrics()
        metrics.record_error()
        metrics.record_error()
        assert metrics.errors == 2

    def test_snapshot(self) -> None:
        metrics = CopilotMetrics()
        metrics.record_analysis("haiku", 3, 1, 1200)
        snap = metrics.snapshot()
        assert snap["total_analyses"] == 1
        assert "avg_processing_time_ms" in snap
        assert "escalation_rate" in snap


class TestStructuredLogger:
    def test_get_logger(self) -> None:
        logger = get_logger("test.copilot")
        assert logger is not None

    def test_get_logger_with_context(self) -> None:
        fid = uuid.uuid4()
        rid = uuid.uuid4()
        logger = get_logger("test.copilot", finding_id=fid, request_id=rid)
        assert logger is not None
        # Verify extra context is set
        assert logger.extra.get("finding_id") == fid  # type: ignore[union-attr]
        assert logger.extra.get("request_id") == rid  # type: ignore[union-attr]


# ── Integration: Full Pipeline ───────────────────────────────────────

class TestFullPipeline:
    """End-to-end test: finding → handler → response (with mocked Bedrock)."""

    def test_full_pipeline_no_signals(
        self, settings: CopilotSettings, valid_request: CopilotRequest
    ) -> None:
        handler = CopilotHandler(settings)

        mock_response = json.dumps({
            "is_true_positive": True,
            "confidence": "HIGH",
            "severity_assessment": "P1",
            "severity_justification": "SQL injection confirmed with clear evidence of unsanitized input in authentication endpoint",
            "remediation_summary": "Replace string interpolation with parameterized query. Add input validation.",
            "remediation_steps": [
                "Replace f-string with parameterized query",
                "Add email format validation",
                "Enable query logging for audit"
            ],
            "piso_applied": ["PCI"],
            "ambiguity_signals": [],
            "requires_sonnet_escalation": False,
        })

        with patch.object(handler._claude, "_get_client", return_value=MagicMock()) as mock_client:
            mock_client.return_value.invoke_model.return_value = {
                "body": MagicMock(read=lambda: json.dumps({
                    "content": [{"type": "text", "text": mock_response}]
                }).encode())
            }

            response = handler.process(valid_request)

        # Verify response structure
        assert response.request_id == valid_request.request_id
        assert response.finding_id == valid_request.finding.finding_id
        assert response.analysis is not None
        assert response.error is None
        assert response.shadow_mode is True

        # Verify analysis content
        analysis = response.analysis
        assert analysis.finding_id == valid_request.finding.finding_id
        assert analysis.model_used == settings.bedrock_haiku_model
        assert analysis.confidence == Confidence.HIGH
        assert len(analysis.summary) >= 20
        assert len(analysis.recommendation) >= 10
        assert analysis.rag_hits > 0  # CWE-89 should match RAG docs
        assert analysis.processing_time_ms >= 0  # May be 0 with mocked Bedrock (instant response)
        assert analysis.escalation_required is False

    def test_full_pipeline_json_serializable(
        self, settings: CopilotSettings, valid_request: CopilotRequest
    ) -> None:
        handler = CopilotHandler(settings)

        mock_response = json.dumps({
            "is_true_positive": True,
            "confidence": "HIGH",
            "severity_assessment": "P1",
            "severity_justification": "SQL injection confirmed with clear evidence of unsanitized input in authentication endpoint",
            "remediation_summary": "Replace string interpolation with parameterized query. Add input validation.",
            "remediation_steps": ["Fix query"],
            "piso_applied": ["PCI"],
            "ambiguity_signals": [],
            "requires_sonnet_escalation": False,
        })

        with patch.object(handler._claude, "_get_client", return_value=MagicMock()) as mock_client:
            mock_client.return_value.invoke_model.return_value = {
                "body": MagicMock(read=lambda: json.dumps({
                    "content": [{"type": "text", "text": mock_response}]
                }).encode())
            }

            response = handler.process(valid_request)

        # Response must be JSON-serializable
        dumped = response.model_dump(mode="json")
        assert isinstance(dumped, dict)
        assert "analysis" in dumped
        assert "processing_time_ms" in dumped
        # Verify UUIDs are serialised as strings
        assert isinstance(dumped["request_id"], str)
        assert isinstance(dumped["finding_id"], str)
