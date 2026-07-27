"""L7 Orchestrator — Lambda handler for Layer 7 pipeline.

Orchestrates: data scope classification → LLM routing → cost tracking.
"""
from __future__ import annotations

import json, time
from shared.utils.fail_closed import fail_closed
from shared.utils.structlog_setup import bind_request_context, configure_logging, get_logger
from .llm_router import route_llm_request, track_cost

logger = get_logger(__name__)

@fail_closed(fallback_value={"error": "Layer 7 pipeline failed — routing to vLLM local"})
def lambda_handler(event: dict, context: object = None) -> dict:
    body = json.loads(event.get("body", "{}")) if isinstance(event.get("body"), str) else event
    configure_logging(agent_id="L7-orchestrator", layer="7")
    bind_request_context(request_id=body.get("request_id", ""))
    start = time.monotonic()
    request_id = body.get("request_id", "")
    content = body.get("content", "")

    routing = route_llm_request(request_id, content, body.get("context"), body.get("force_local", False))
    cost, breaker = track_cost(500, 200, "haiku" if routing.tier.value == "volume" else "sonnet")

    return {"statusCode": 200, "body": json.dumps({
        "request_id": request_id, "provider": routing.provider.value,
        "tier": routing.tier.value, "blocked": routing.blocked,
        "cost_usd": round(cost, 6), "circuit_breaker": breaker,
        "processing_time_ms": int((time.monotonic() - start) * 1000),
    }, default=str)}
