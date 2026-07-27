"""L8 Orchestrator — Lambda handler for Layer 8 pipeline.

Orchestrates: activation decision → shadow mode → tool lifecycle.
"""
from __future__ import annotations

import json, time
from shared.utils.fail_closed import fail_closed
from shared.utils.structlog_setup import bind_request_context, configure_logging, get_logger
from .activation_engine import AgentActivationRule, should_activate, ActivationDecision

logger = get_logger(__name__)

@fail_closed(fallback_value={"error": "Layer 8 pipeline failed"})
def lambda_handler(event: dict, context: object = None) -> dict:
    body = json.loads(event.get("body", "{}")) if isinstance(event.get("body"), str) else event
    configure_logging(agent_id="L8-orchestrator", layer="8")
    bind_request_context(request_id=body.get("request_id", ""))
    start = time.monotonic()

    agent_id = body.get("agent_id", "")
    language = body.get("language", "")
    budget = body.get("budget_available", 100000)

    rule = AgentActivationRule(agent_id=agent_id, language=language, enabled=True)
    decision = should_activate(rule, language=language, budget_available=budget)

    return {"statusCode": 200, "body": json.dumps({
        "agent_id": agent_id, "decision": decision.value,
        "budget_available": budget,
        "processing_time_ms": int((time.monotonic() - start) * 1000),
    }, default=str)}
