"""L3 Orchestrator — Lambda handler for Layer 3 pipeline.

Orchestrates: sandbox → PoC → score engine.
"""
from __future__ import annotations

import json, time
from shared.utils.fail_closed import fail_closed
from shared.utils.structlog_setup import bind_request_context, configure_logging, get_logger
from .sandbox_executor import execute_poc, SandboxConfig, ExecutionResult
from .poc_runner import run_poc
from .score_engine import ScoreInput, ExploitabilityLevel, ReachabilityLevel, BusinessImpactLevel, compute_score

logger = get_logger(__name__)

@fail_closed(fallback_value={"error": "Layer 3 pipeline failed"})
def lambda_handler(event: dict, context: object = None) -> dict:
    body = json.loads(event.get("body", "{}")) if isinstance(event.get("body"), str) else event
    configure_logging(agent_id="L3-orchestrator", layer="3")
    bind_request_context(request_id=body.get("request_id", ""))
    start = time.monotonic()
    finding_id = body.get("finding_id", "")
    cwe_id = body.get("cwe_id", "CWE-89")

    poc_result = run_poc(finding_id, cwe_id)
    inp = ScoreInput(
        finding_id=finding_id,
        exploitability=ExploitabilityLevel.CONFIRMED if poc_result.exploitable else ExploitabilityLevel.UNLIKELY,
        reachability=ReachabilityLevel.REACHABLE if poc_result.exploitable else ReachabilityLevel.UNKNOWN,
        business_impact=BusinessImpactLevel.HIGH,
        confidence=0.8 if poc_result.confidence == "HIGH" else 0.5,
        has_poc_evidence=poc_result.exploitable,
    )
    score = compute_score(inp)

    return {"statusCode": 200, "body": json.dumps({
        "finding_id": finding_id, "exploitable": poc_result.exploitable,
        "score": score.composite_score, "severity_floor": score.severity_floor_applied,
        "processing_time_ms": int((time.monotonic() - start) * 1000),
    }, default=str)}
