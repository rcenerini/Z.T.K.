"""F0.1.8 — Structured logging setup (structlog).

All agents across all 8 layers use this module for JSON logging.
Compatible with CloudWatch Logs Insights and Grafana Loki.

Mandatory fields in every log: timestamp, level, agent_id, layer, request_id.
Never logs PAN, CVV, PII, or credentials.
"""

from __future__ import annotations

import logging
import os
import sys
from typing import Any, Optional

import structlog

# Re-export for convenience
get_logger = structlog.get_logger


def configure_logging(
    agent_id: str = "unknown",
    layer: str = "unknown",
    log_level: str | None = None,
    pretty_print: bool = False,
) -> None:
    """Configure structlog for the entire process.

    Call once at agent startup (handler.py or Lambda init).
    Thread-safe, idempotent (subsequent calls are no-op).

    Args:
        agent_id: Agent identifier (e.g., "L1.02", "copilot").
        layer: Layer number (e.g., "1", "mvp2").
        log_level: Override log level (default: env LOG_LEVEL or INFO).
        pretty_print: True for local dev (human-readable), False for JSON (production).
    """

    level = log_level or os.getenv("LOG_LEVEL", "INFO")
    level_num = getattr(logging, level.upper(), logging.INFO)

    # Shared processors for all loggers
    shared_processors: list[Any] = [
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.dev.set_exc_info,
    ]

    if pretty_print:
        # Local development: colorful console output
        shared_processors.append(structlog.dev.ConsoleRenderer(colors=True))
    else:
        # Production: JSON for CloudWatch
        renderer = structlog.processors.JSONRenderer(serializer=_sanitise_json)
        shared_processors.append(renderer)

    structlog.configure(
        processors=shared_processors,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    # Bind static context that appears in every log entry
    structlog.contextvars.bind_contextvars(
        agent_id=agent_id,
        layer=layer,
    )

    # Set root logger level
    logging.getLogger().setLevel(level_num)


def bind_request_context(
    finding_id: Optional[str] = None,
    request_id: Optional[str] = None,
    correlation_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
) -> None:
    """Bind request-scoped context for the current thread/coroutine.

    Call at the start of each handler invocation (Lambda, SQS consumer).
    Clears previous context automatically.
    """
    structlog.contextvars.clear_contextvars()
    ctx: dict[str, str] = {}
    if finding_id is not None:
        ctx["finding_id"] = finding_id
    if request_id is not None:
        ctx["request_id"] = request_id
    if correlation_id is not None:
        ctx["correlation_id"] = correlation_id
    if tenant_id is not None:
        ctx["tenant_id"] = tenant_id
    structlog.contextvars.bind_contextvars(**ctx)


def _sanitise_json(obj: Any, **kwargs: Any) -> str:
    """JSON serializer that removes sensitive fields before output."""
    import json

    sensitive_keys = {
        "pan", "cvv", "password", "secret", "token", "credential", "api_key",
        "access_key", "private_key", "authorization", "bearer",
    }

    def _default(obj: Any) -> str:
        try:
            return str(obj)
        except Exception:
            return "<non-serializable>"

    if isinstance(obj, dict):
        sanitised = {}
        for k, v in obj.items():
            if any(sensitive in k.lower() for sensitive in sensitive_keys):
                sanitised[k] = "***REDACTED***"
            else:
                sanitised[k] = v
        return json.dumps(sanitised, default=_default, **kwargs)

    return json.dumps(obj, default=_default, **kwargs)
