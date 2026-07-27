"""L6.01 — Policy Engine Agent.

Runtime OPA/Rego policy evaluation. All sensitive operations pass through
this engine before execution. Deny-by-default — no implicit permissions.

Evaluates policies loaded from Git (versioned) against input context.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from shared.utils.fail_closed import fail_closed
from shared.utils.structlog_setup import get_logger

logger = get_logger(__name__)

# Path to OPA policies (versioned in Git)
POLICIES_DIR = Path(__file__).resolve().parents[4] / "infra" / "policies"


class PolicyDecision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    ERROR = "ERROR"


@dataclass
class PolicyResult:
    """Result of a policy evaluation."""
    decision: PolicyDecision
    policy_name: str
    violations: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    processing_time_ms: int = 0


@fail_closed(
    fallback_value=PolicyResult(decision=PolicyDecision.DENY, policy_name="fail_closed",
                                 violations=["Policy engine unavailable — denied by fail-closed"]),
    fallback_message="Policy engine failed — denying operation"
)
def evaluate(
    operation: str,
    context: dict[str, Any],
    policy_name: str = "deny_by_default",
) -> PolicyResult:
    """Evaluate an operation against OPA policies.

    Args:
        operation: Operation name (e.g., 'merge_pr', 'deploy', 'containment_dry_run')
        context: Input context for the policy (IAM policies, LLM requests, etc.)
        policy_name: Which policy to evaluate against.

    Returns:
        PolicyResult with decision (ALLOW/DENY) and violations.
    """
    import time
    start = time.monotonic()

    policy_path = POLICIES_DIR / f"{policy_name}.rego"

    # Build OPA input
    opa_input = {
        "input": {
            "operation": operation,
            **context,
        }
    }

    # Build OPA query: data.ztk.<policy_name>.allow
    query = f"data.ztk.{policy_name}.allow"

    try:
        result = subprocess.run(
            ["opa", "eval", "--format", "json", "--data", str(policy_path), "--input", "/dev/stdin", query],
            input=json.dumps(opa_input),
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except FileNotFoundError:
        # OPA CLI not installed — evaluate with embedded logic
        return _embedded_evaluate(operation, context, policy_name)

    processing_time_ms = int((time.monotonic() - start) * 1000)

    if result.returncode != 0:
        logger.error("opa_eval_failed", stderr=result.stderr[:200])
        return PolicyResult(
            decision=PolicyDecision.ERROR,
            policy_name=policy_name,
            violations=[f"OPA evaluation error: {result.stderr[:100]}"],
            processing_time_ms=processing_time_ms,
        )

    try:
        data = json.loads(result.stdout)
        allowed = data[0].get("result", [{}])[0].get("expressions", [{}])[0].get("value", False)
    except (json.JSONDecodeError, IndexError, KeyError):
        allowed = False

    decision = PolicyDecision.ALLOW if allowed else PolicyDecision.DENY

    logger.info(
        "policy_evaluated",
        operation=operation,
        policy=policy_name,
        decision=decision.value,
        processing_time_ms=processing_time_ms,
    )

    return PolicyResult(
        decision=decision,
        policy_name=policy_name,
        processing_time_ms=processing_time_ms,
    )


def _embedded_evaluate(operation: str, context: dict[str, Any], policy_name: str) -> PolicyResult:
    """Fallback evaluator when OPA CLI is not installed.
    Implements deny_by_default logic in pure Python for critical paths.
    """

    # Always-allow read operations
    if operation in ("read_code", "read_finding", "write_audit_event"):
        return PolicyResult(decision=PolicyDecision.ALLOW, policy_name=policy_name,
                           details={"reason": "read-only operation — always allowed"})

    # Kill switch (SOC only)
    if operation == "kill_switch":
        allowed = context.get("authority") == "SOC"
        return PolicyResult(
            decision=PolicyDecision.ALLOW if allowed else PolicyDecision.DENY,
            policy_name=policy_name,
            violations=[] if allowed else ["Kill switch requires SOC authority"],
        )

    # Merge PR
    if operation == "merge_pr":
        review_ok = context.get("security_review_passed", False)
        severity = context.get("severity", "P4")
        if not review_ok:
            return PolicyResult(decision=PolicyDecision.DENY, policy_name=policy_name,
                               violations=["PR requires security review"])
        if severity in ("P0", "P1"):
            return PolicyResult(decision=PolicyDecision.DENY, policy_name=policy_name,
                               violations=[f"Cannot auto-merge {severity} — human approval required"])
        return PolicyResult(decision=PolicyDecision.ALLOW, policy_name=policy_name)

    # Deploy
    if operation == "deploy":
        if context.get("environment") == "production" and not context.get("cab_approved"):
            return PolicyResult(decision=PolicyDecision.DENY, policy_name=policy_name,
                               violations=["Production deploy requires CAB approval"])
        return PolicyResult(decision=PolicyDecision.ALLOW, policy_name=policy_name)

    # Containment dry-run
    if operation == "containment_dry_run":
        if context.get("dry_run", False):
            return PolicyResult(decision=PolicyDecision.ALLOW, policy_name=policy_name)
        return PolicyResult(decision=PolicyDecision.DENY, policy_name=policy_name,
                           violations=["Containment requires dry-run validation"])

    # Default: deny
    return PolicyResult(
        decision=PolicyDecision.DENY,
        policy_name=policy_name,
        violations=[f"Operation '{operation}' not explicitly allowed by policy '{policy_name}'"],
    )
