"""L6 Orchestrator — Lambda handler for Layer 6 pipeline.

Orchestrates: policy evaluation → exception flow → HITL gateway.
"""
from __future__ import annotations

import json, time
from shared.utils.fail_closed import fail_closed
from shared.utils.structlog_setup import bind_request_context, configure_logging, get_logger
from .policy_engine import evaluate
from .exception_flow import intake_exception, ExceptionCategory
from .hitl_gateway import enqueue_item, HITLPriority

logger = get_logger(__name__)

@fail_closed(fallback_value={"error": "Layer 6 pipeline failed"})
def lambda_handler(event: dict, context: object = None) -> dict:
    body = json.loads(event.get("body", "{}")) if isinstance(event.get("body"), str) else event
    configure_logging(agent_id="L6-orchestrator", layer="6")
    bind_request_context(request_id=body.get("request_id", ""))
    start = time.monotonic()
    operation = body.get("operation", "read_finding")

    policy = evaluate(operation, body.get("context", {}))
    result = {"operation": operation, "allowed": policy.decision.value == "ALLOW", "violations": policy.violations}

    if operation == "exception_request":
        exc = intake_exception(
            finding_id=body.get("finding_id", ""), tenant_id=body.get("tenant_id", "ztk-proj"),
            requested_by=body.get("requested_by", ""),
            category=ExceptionCategory(body.get("category", "FALSE_POSITIVE")),
            justification=body.get("justification", ""),
            current_severity=body.get("current_severity", "P2"),
            requested_severity=body.get("requested_severity", "P4"),
        )
        result["exception"] = {"id": exc.exception_id if exc else None, "status": exc.status.value if exc else "REJECTED"}

    result["processing_time_ms"] = int((time.monotonic() - start) * 1000)
    return {"statusCode": 200, "body": json.dumps(result, default=str)}
