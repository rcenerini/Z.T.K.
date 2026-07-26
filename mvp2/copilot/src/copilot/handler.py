"""Copilot handler — SQS consumer for ATTEND-tier finding analysis.

Reads DecisionRecord from SQS queue, invokes Claude via Bedrock with RAG context,
and returns CopilotResponse. Shadow-mode by default (no side effects).

Flow:
1. Receive CopilotRequest (or construct from FindingContext)
2. Retrieve RAG context documents
3. Build prompt with fixed context + RAG + finding
4. Call Claude Haiku (routine)
5. If ambiguity_signals >= threshold → escalate to Sonnet
6. Parse response, extract AmbiguitySignals
7. Return CopilotResponse
"""

from __future__ import annotations

import json
import time
from typing import Optional
from uuid import UUID

from .claude_client import ClaudeClient
from .config import CopilotSettings, get_settings
from .models import (
    AmbiguitySignal,
    Confidence,
    CopilotAnalysis,
    CopilotRequest,
    CopilotResponse,
    FindingContext,
)
from .observability import CopilotMetrics, get_logger
from .prompt_builder import PromptBuilder
from .rag_retriever import RagRetriever


class CopilotHandler:
    """Main handler for the ATTEND-tier LLM copilot."""

    def __init__(
        self,
        settings: CopilotSettings | None = None,
    ) -> None:
        self._settings = settings or get_settings()
        self._claude = ClaudeClient(self._settings)
        self._rag = RagRetriever(self._settings)
        self._prompt = PromptBuilder(self._settings)
        self._metrics = CopilotMetrics()
        self._logger = get_logger(__name__)

    def process(self, request: CopilotRequest) -> CopilotResponse:
        """Process a single copilot analysis request.

        Args:
            request: CopilotRequest with FindingContext and options.

        Returns:
            CopilotResponse with analysis or error.
        """
        start = time.monotonic()
        finding: FindingContext = request.finding
        fid = finding.finding_id
        rid = request.request_id

        # Per-request logger with correlation IDs
        logger = get_logger(__name__, finding_id=fid, request_id=rid)

        logger.info(
            "copilot_analysis_started",
            tier=finding.decision_tier.value,
            cwe_ids=",".join(finding.cwe_ids),
            score=finding.score,
            shadow_mode=request.shadow_mode,
        )

        try:
            # Step 1: RAG retrieval
            rag_docs = self._rag.retrieve(finding)
            rag_context = self._rag.format_context(rag_docs)
            logger.info(
                "rag_retrieval_complete",
                rag_hits=len(rag_docs),
            )

            # Step 2: Build prompt
            system_prompt, user_message = self._prompt.build_analysis_prompt(finding)
            # Inject RAG context into user message
            user_message = f"{rag_context}\n\n{user_message}"

            # Step 3: Call Claude Haiku (routine)
            response_text, model_used, proc_ms = self._claude.analyse(
                system_prompt=system_prompt,
                user_message=user_message,
                finding=finding,
                prefer_model=request.force_model,
            )

            # Step 4: Parse ambiguity signals
            signals = self._prompt.parse_response(
                raw_response=response_text,
                finding=finding,
                model_used=model_used,
                processing_time_ms=proc_ms,
            )

            escalation_triggered = False

            # Step 5: Check if Sonnet escalation is needed
            if len(signals) >= self._settings.ambiguity_escalation_threshold:
                logger.info(
                    "escalating_to_sonnet",
                    ambiguity_count=len(signals),
                    threshold=self._settings.ambiguity_escalation_threshold,
                )
                escalation_triggered = True

                # Mark RAG context for re-use in escalation prompt
                response_text, model_used, sonnet_ms = self._claude.escalate_to_sonnet(
                    system_prompt=system_prompt,
                    user_message=user_message,
                    finding=finding,
                    signals_count=len(signals),
                )
                proc_ms += sonnet_ms

                # Re-parse signals from Sonnet's response
                signals = self._prompt.parse_response(
                    raw_response=response_text,
                    finding=finding,
                    model_used=model_used,
                    processing_time_ms=proc_ms,
                )

            # Step 6: Build CopilotAnalysis
            analysis = self._build_analysis(
                finding=finding,
                model_used=model_used,
                rag_docs=rag_docs,
                signals=signals,
                response_text=response_text,
                processing_time_ms=proc_ms,
                escalation_triggered=escalation_triggered,
            )

            # Step 7: Record metrics
            self._metrics.record_analysis(
                model_used=model_used,
                rag_hits=len(rag_docs),
                ambiguity_count=len(signals),
                processing_time_ms=proc_ms,
                escalated=escalation_triggered,
            )

            total_ms = int((time.monotonic() - start) * 1000)

            logger.info(
                "copilot_analysis_complete",
                model_used=model_used,
                confidence=analysis.confidence.value if analysis else "NONE",
                ambiguity_count=len(signals),
                escalation_triggered=escalation_triggered,
                processing_time_ms=total_ms,
            )

            return CopilotResponse(
                request_id=rid,
                finding_id=fid,
                analysis=analysis,
                error=None,
                shadow_mode=request.shadow_mode,
                escalation_triggered=escalation_triggered,
                processing_time_ms=total_ms,
                timestamp=type(analysis).model_fields["timestamp"].default_factory()
                if analysis else request.timestamp,
            )

        except Exception as exc:
            self._metrics.record_error()
            logger.error(
                "copilot_analysis_failed",
                error=str(exc),
                exc_info=True,
            )
            total_ms = int((time.monotonic() - start) * 1000)
            return CopilotResponse(
                request_id=rid,
                finding_id=fid,
                analysis=None,
                error=str(exc),
                shadow_mode=request.shadow_mode,
                escalation_triggered=False,
                processing_time_ms=total_ms,
                timestamp=request.timestamp,
            )

    def _build_analysis(
        self,
        finding: FindingContext,
        model_used: str,
        rag_docs: list,
        signals: list[AmbiguitySignal],
        response_text: str,
        processing_time_ms: int,
        escalation_triggered: bool,
    ) -> CopilotAnalysis:
        """Build CopilotAnalysis from LLM response."""
        try:
            data = json.loads(response_text)
        except json.JSONDecodeError:
            data = {}

        confidence_raw = data.get("confidence", "LOW")
        try:
            confidence = Confidence(confidence_raw)
        except ValueError:
            confidence = Confidence.LOW

        return CopilotAnalysis(
            finding_id=finding.finding_id,
            tier_requested=finding.decision_tier,
            tier_actual=finding.decision_tier,
            model_used=model_used,
            confidence=confidence,
            summary=data.get("severity_justification", "No justification provided"),
            recommendation=data.get("remediation_summary", "No recommendation provided"),
            ambiguity_signals=signals,
            rag_hits=len(rag_docs),
            rag_relevant=min(len(rag_docs), len([d for d in rag_docs if d.score > 0.7])),
            prompt_version=self._settings.prompt_version,
            processing_time_ms=processing_time_ms,
            escalation_required=escalation_triggered,
            raw_response=response_text,
        )

    @property
    def metrics(self) -> CopilotMetrics:
        """Access copilot metrics for observability."""
        return self._metrics

    @property
    def ready(self) -> bool:
        """Check if handler is ready to process requests."""
        return self._claude.available


def lambda_handler(event: dict, context: object) -> dict:
    """AWS Lambda entrypoint for SQS-triggered copilot analysis.

    Expects SQS event with CopilotRequest JSON in each record body.
    """
    settings = get_settings()
    handler = CopilotHandler(settings)
    logger = get_logger("copilot.lambda_handler")

    results: list[dict] = []
    records = event.get("Records", [])

    for record in records:
        try:
            body = json.loads(record["body"])
            request = CopilotRequest(**body)
            response = handler.process(request)
            results.append(response.model_dump(mode="json"))
        except Exception as exc:
            logger.error("record_processing_failed", error=str(exc), message_id=record.get("messageId"))
            results.append({
                "error": str(exc),
                "message_id": record.get("messageId"),
            })

    logger.info("batch_complete", total_records=len(records), success=len(results))

    return {
        "statusCode": 200,
        "batchItemFailures": [],
        "results": results,
        "metrics": handler.metrics.snapshot(),
    }
