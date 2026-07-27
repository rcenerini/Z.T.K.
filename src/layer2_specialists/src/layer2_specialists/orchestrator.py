"""L2 — SAST Orchestrator.

Lambda handler that dispatches SAST agents in parallel based on language.
Receives file list from L1, runs all applicable SAST tools, returns findings.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from shared.utils.fail_closed import fail_closed
from shared.utils.structlog_setup import bind_request_context, configure_logging, get_logger

from .sast_executor import run_sast_agent
from .sast_registry import SAST_REGISTRY, get_agents_for_language, get_cross_cutting_agents

logger = get_logger(__name__)


@dataclass
class L2Result:
    """Complete Layer 2 output."""
    request_id: str
    tenant_id: str
    language: str
    agents_run: int = 0
    agents_failed: int = 0
    total_findings: int = 0
    findings: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    processing_time_ms: int = 0


@fail_closed(fallback_value={"error": "Layer 2 pipeline failed"})
def orchestrate_layer2(event: dict) -> dict:
    """Main Lambda handler for Layer 2 pipeline.

    Input: {request_id, tenant_id, language, file_paths[], file_contents{}}
    Output: {findings[], agents_run, total_findings, errors[]}
    """
    import time
    start = time.monotonic()

    body = json.loads(event.get("body", "{}")) if isinstance(event.get("body"), str) else event
    request_id = body.get("request_id", "unknown")
    tenant_id = body.get("tenant_id", "ztk-proj")
    language = body.get("language", "python")
    file_paths = body.get("file_paths", [])
    target_dir = body.get("target_dir", "")

    configure_logging(agent_id="L2-orchestrator", layer="2")
    bind_request_context(request_id=request_id, tenant_id=tenant_id)

    result = L2Result(request_id=request_id, tenant_id=tenant_id, language=language)

    # Get agents for this language
    agents = get_agents_for_language(language)
    # Always include cross-cutting agents (secrets, SCA)
    agents += get_cross_cutting_agents()

    if not agents:
        result.errors.append(f"No SAST agents configured for language: {language}")
        return _serialize_result(result)

    # Determine target
    target = target_dir or (file_paths[0] if file_paths else "")

    if not target:
        result.errors.append("No target directory or file paths provided")
        return _serialize_result(result)

    # Run each agent (sequential in MVP, parallel in production via Step Functions)
    for config in agents:
        try:
            exec_result = run_sast_agent(config, target)
            result.agents_run += 1

            if not exec_result.success:
                result.agents_failed += 1
                if exec_result.errors:
                    result.errors.extend(exec_result.errors)

            # Convert findings to dicts
            for finding in exec_result.output_parsed:
                finding["agent_id"] = config.agent_id
                finding["tool"] = config.tool
                result.findings.append(finding)
                result.total_findings += 1

        except Exception as e:
            result.agents_failed += 1
            result.errors.append(f"Agent {config.agent_id} failed: {str(e)[:200]}")

    result.processing_time_ms = int((time.monotonic() - start) * 1000)

    logger.info(
        "layer2_complete",
        language=language,
        agents_run=result.agents_run,
        total_findings=result.total_findings,
        processing_time_ms=result.processing_time_ms,
    )

    return _serialize_result(result)


def _serialize_result(result: L2Result) -> dict:
    return {
        "statusCode": 200,
        "body": json.dumps({
            "request_id": result.request_id,
            "language": result.language,
            "agents_run": result.agents_run,
            "agents_failed": result.agents_failed,
            "total_findings": result.total_findings,
            "findings": result.findings,
            "errors": result.errors,
            "processing_time_ms": result.processing_time_ms,
        }, default=str),
    }
