"""L5 — Remediation Orchestrator.

Coordinates parallel execution of Trilha A (Patch) + Trilha B (Containment).
Integrates with Kill Switch (SOC can stop either or both tracks).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from shared.utils.fail_closed import fail_closed
from shared.utils.structlog_setup import bind_request_context, configure_logging, get_logger

from .patch_generator import (
    PatchResult,
    generate_patch,
    validate_patch,
    regression_check,
    publish_pr,
)
from .containment_manager import (
    ContainmentRule,
    create_containment_rule,
    run_dry_run,
    apply_containment,
)

logger = get_logger(__name__)


class KillSwitchScope(str):
    NONE = "none"
    PATCH_ONLY = "patch_only"
    CONTAINMENT_ONLY = "containment_only"
    FULL = "full"


@dataclass
class RemediationResult:
    """Complete L5 remediation output."""
    request_id: str
    finding_id: str
    cwe_id: str
    severity: str

    # Track A: Patch
    patch: PatchResult | None = None
    patch_blocked: bool = False

    # Track B: Containment
    containment: ContainmentRule | None = None
    containment_active: bool = False

    # Control
    kill_switch_scope: str = KillSwitchScope.NONE
    errors: list[str] = field(default_factory=list)
    processing_time_ms: int = 0


@fail_closed(fallback_value={"error": "Remediation pipeline failed"})
def orchestrate_remediation(event: dict) -> dict:
    """Main Lambda handler for Layer 5 remediation.

    Input: {finding_id, cwe_id, file_path, original_code, severity,
            target_scope, kill_switch_scope}
    Output: {patch, containment, errors}
    """
    import time
    start = time.monotonic()

    body = json.loads(event.get("body", "{}")) if isinstance(event.get("body"), str) else event
    request_id = body.get("request_id", "unknown")
    finding_id = body.get("finding_id", "")
    cwe_id = body.get("cwe_id", "")
    file_path = body.get("file_path", "")
    original_code = body.get("original_code", "")
    severity = body.get("severity", "P3")
    target_scope = body.get("target_scope", "")
    kill_switch = body.get("kill_switch_scope", KillSwitchScope.NONE)

    configure_logging(agent_id="L5-orchestrator", layer="5")
    bind_request_context(request_id=request_id)

    result = RemediationResult(
        request_id=request_id,
        finding_id=finding_id,
        cwe_id=cwe_id,
        severity=severity,
        kill_switch_scope=kill_switch,
    )

    # ── Track A: Patch Generation ──
    if kill_switch not in (KillSwitchScope.PATCH_ONLY, KillSwitchScope.FULL):
        patch = generate_patch(finding_id, cwe_id, file_path, original_code, severity)

        if not patch.merge_blocked:
            patch = validate_patch(patch)
            patch = regression_check(patch)
            patch = publish_pr(patch)

        result.patch = patch
        result.patch_blocked = patch.merge_blocked
    else:
        result.errors.append("Track A (Patch) blocked by kill switch")

    # ── Track B: Containment ──
    if kill_switch not in (KillSwitchScope.CONTAINMENT_ONLY, KillSwitchScope.FULL):
        rule = create_containment_rule(finding_id, cwe_id, target_scope)
        rule = run_dry_run(rule)

        # Only apply containment for P0/P1 or if patch is blocked
        if severity in ("P0", "P1") or (result.patch_blocked if result.patch else False):
            rule = apply_containment(rule)

        result.containment = rule
        result.containment_active = rule.status.value == "ACTIVE"
    else:
        result.errors.append("Track B (Containment) blocked by kill switch")

    result.processing_time_ms = int((time.monotonic() - start) * 1000)

    logger.info(
        "remediation_complete",
        finding_id=finding_id[:8],
        patch_blocked=result.patch_blocked,
        containment_active=result.containment_active,
        processing_time_ms=result.processing_time_ms,
    )

    return _serialize_result(result)


def _serialize_result(result: RemediationResult) -> dict:
    return {
        "statusCode": 200,
        "body": json.dumps({
            "request_id": result.request_id,
            "finding_id": result.finding_id,
            "cwe_id": result.cwe_id,
            "patch": {
                "generated": result.patch is not None,
                "blocked": result.patch_blocked,
                "status": result.patch.status.value if result.patch else "N/A",
                "pr_url": result.patch.pr_url if result.patch else "",
            } if result.patch else None,
            "containment": {
                "created": result.containment is not None,
                "active": result.containment_active,
                "status": result.containment.status.value if result.containment else "N/A",
                "ttl_hours": result.containment.ttl_hours if result.containment else 0,
            } if result.containment else None,
            "errors": result.errors,
            "processing_time_ms": result.processing_time_ms,
        }, default=str),
    }
