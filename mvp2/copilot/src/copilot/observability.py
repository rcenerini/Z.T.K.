"""Observability — structured JSON logging for the copilot module.

All logs use key=value structured logging compatible with CloudWatch Logs Insights.
Never logs PAN, CVV, PII, or credentials.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import UUID


class _StructuredFormatter(logging.Formatter):
    """JSON log formatter for CloudWatch Logs Insights compatibility."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Add structured context from extra fields
        for key in ("finding_id", "request_id", "agent_id", "layer", "processing_time_ms",
                     "rag_hits", "rag_relevant", "model_used", "tier", "ambiguity_count",
                     "escalation_triggered", "shadow_mode"):
            value = getattr(record, key, None)
            if value is not None:
                if isinstance(value, UUID):
                    value = str(value)
                log_entry[key] = value

        # Sanitise: remove sensitive fields that might have leaked
        forbidden_keys = {"pan", "cvv", "password", "secret", "token", "credential", "api_key"}
        for key in list(log_entry.keys()):
            if any(forbidden in key.lower() for forbidden in forbidden_keys):
                del log_entry[key]

        if record.exc_info and record.exc_info[1]:
            log_entry["exception"] = str(record.exc_info[1])

        return json.dumps(log_entry, default=str)


class _StructuredAdapter(logging.LoggerAdapter):
    """Custom adapter that injects extra fields as LogRecord attributes.

    Compatible with Python 3.14+ where Logger._log() rejects unexpected kwargs.
    """
    def process(self, msg: str, kwargs: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        # Move structured context from kwargs into extra dict.
        # Use a copy of keys to avoid mutating dict during iteration.
        extra: dict[str, Any] = dict(self.extra) if self.extra else {}
        reserved = {"exc_info", "stack_info", "stacklevel", "extra"}
        for key in list(kwargs.keys()):
            if key not in reserved:
                extra[key] = kwargs.pop(key)
        kwargs["extra"] = extra
        return msg, kwargs


def get_logger(
    name: str,
    level: str | None = None,
    finding_id: Optional[UUID] = None,
    request_id: Optional[UUID] = None,
) -> _StructuredAdapter:
    """Get a structured logger with optional context fields.

    Args:
        name: Logger name (use __name__).
        level: Override log level (default: COPILOT_LOG_LEVEL or INFO).
        finding_id: Current finding ID for correlation.
        request_id: Current request ID for tracing.
    """
    logger = logging.getLogger(name)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(_StructuredFormatter())
        logger.addHandler(handler)

    log_level = level or os.getenv("COPILOT_LOG_LEVEL", "INFO")
    logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    extra: dict[str, Any] = {"agent_id": "copilot", "layer": "mvp2"}
    if finding_id is not None:
        extra["finding_id"] = finding_id
    if request_id is not None:
        extra["request_id"] = request_id

    return _StructuredAdapter(logger, extra)


class CopilotMetrics:
    """Tracks copilot metrics for observability dashboards."""

    def __init__(self) -> None:
        self.total_analyses: int = 0
        self.haiku_analyses: int = 0
        self.sonnet_escalations: int = 0
        self.rag_hits_total: int = 0
        self.ambiguity_signals_total: int = 0
        self.errors: int = 0
        self.total_processing_time_ms: int = 0

    def record_analysis(
        self,
        model_used: str,
        rag_hits: int,
        ambiguity_count: int,
        processing_time_ms: int,
        escalated: bool = False,
    ) -> None:
        self.total_analyses += 1
        self.rag_hits_total += rag_hits
        self.ambiguity_signals_total += ambiguity_count
        self.total_processing_time_ms += processing_time_ms
        # Count only once: model_used determines the bucket.
        # 'escalated' flag is informational (for metrics snapshot), not a counter.
        if "sonnet" in model_used.lower():
            self.sonnet_escalations += 1
        else:
            self.haiku_analyses += 1

    def record_error(self) -> None:
        self.errors += 1

    @property
    def avg_processing_time_ms(self) -> float:
        if self.total_analyses == 0:
            return 0.0
        return self.total_processing_time_ms / self.total_analyses

    @property
    def escalation_rate(self) -> float:
        if self.total_analyses == 0:
            return 0.0
        return self.sonnet_escalations / self.total_analyses

    def snapshot(self) -> dict[str, Any]:
        return {
            "total_analyses": self.total_analyses,
            "haiku_analyses": self.haiku_analyses,
            "sonnet_escalations": self.sonnet_escalations,
            "rag_hits_total": self.rag_hits_total,
            "ambiguity_signals_total": self.ambiguity_signals_total,
            "errors": self.errors,
            "total_processing_time_ms": self.total_processing_time_ms,
            "avg_processing_time_ms": round(self.avg_processing_time_ms, 2),
            "escalation_rate": round(self.escalation_rate, 4),
        }
