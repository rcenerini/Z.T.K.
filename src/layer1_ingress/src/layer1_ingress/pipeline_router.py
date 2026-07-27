"""L1.05 — Pipeline Router Agent.

Deterministic YAML-based rules engine that routes findings to downstream agents.
Reads routing rules from a YAML file (versioned in Git).
No LLM — purely declarative.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


@dataclass
class Route:
    """A single routing target."""
    agent_id: str
    layer: int
    reason: str
    priority: int = 0


@dataclass
class RouterResult:
    """Routing decision for a finding."""
    finding_id: str
    routes: list[Route] = field(default_factory=list)
    blocked: bool = False
    block_reason: str = ""


# ── Default Routing Rules (deterministic, versioned in Git) ───────

DEFAULT_ROUTES: dict[str, list[dict[str, Any]]] = {
    # Language → SAST agents (L2)
    "python": [
        {"agent_id": "L2.01-bandit", "layer": 2, "reason": "Python SAST — Bandit"},
        {"agent_id": "L2.02-semgrep-python", "layer": 2, "reason": "Python SAST — Semgrep"},
    ],
    "java": [
        {"agent_id": "L2.03-spotbugs", "layer": 2, "reason": "Java SAST — SpotBugs"},
        {"agent_id": "L2.04-codeql-java", "layer": 2, "reason": "Java SAST — CodeQL"},
    ],
    "javascript": [
        {"agent_id": "L2.05-eslint", "layer": 2, "reason": "JS SAST — ESLint"},
        {"agent_id": "L2.06-semgrep-js", "layer": 2, "reason": "JS SAST — Semgrep"},
    ],
    "typescript": [
        {"agent_id": "L2.05-eslint", "layer": 2, "reason": "TS SAST — ESLint"},
        {"agent_id": "L2.06-semgrep-js", "layer": 2, "reason": "TS SAST — Semgrep"},
    ],
    "go": [
        {"agent_id": "L2.07-gosec", "layer": 2, "reason": "Go SAST — gosec"},
    ],
    "terraform": [
        {"agent_id": "L2.24-checkov", "layer": 2, "reason": "IaC SAST — Checkov"},
        {"agent_id": "L2.25-tfsec", "layer": 2, "reason": "IaC SAST — tfsec"},
    ],
    "dockerfile": [
        {"agent_id": "L2.26-hadolint", "layer": 2, "reason": "Docker SAST — Hadolint"},
    ],
    "kubernetes": [
        {"agent_id": "L2.27-kubesec", "layer": 2, "reason": "K8s SAST — Kubesec"},
    ],

    # Severity → Decision tier (SSVC routing)
    "criticality_critical": [
        {"agent_id": "L4-consensus", "layer": 4, "reason": "Critical finding → Direct to Consensus debate"},
    ],
    "criticality_high": [
        {"agent_id": "L4-consensus", "layer": 4, "reason": "High criticality → Consensus"},
    ],

    # Cross-cutting agents (always included)
    "cross_cutting": [
        {"agent_id": "L2.28-gitleaks", "layer": 2, "reason": "Secrets scan — always run"},
        {"agent_id": "L2.29-trufflehog", "layer": 2, "reason": "Secrets scan — always run"},
        {"agent_id": "L6-audit", "layer": 6, "reason": "Audit — always log"},
    ],
}


def route(
    finding_id: str,
    language: str | None = None,
    criticality: str | None = None,
    blocked_by_guard: bool = False,
) -> RouterResult:
    """Route a finding to downstream agents based on language and criticality.

    Deterministic: same inputs always produce same routes.
    """
    result = RouterResult(finding_id=finding_id)

    # Blocked by prompt-injection guard
    if blocked_by_guard:
        result.blocked = True
        result.block_reason = "Content blocked by L1.03 prompt-injection guard"
        result.routes.append(Route(
            agent_id="L6.13-HITL",
            layer=6,
            reason="Blocked content → Human review required",
            priority=-1,
        ))
        return result

    # Cross-cutting agents (always included)
    for rule in DEFAULT_ROUTES.get("cross_cutting", []):
        result.routes.append(Route(
            agent_id=rule["agent_id"],
            layer=rule["layer"],
            reason=rule["reason"],
        ))

    # Language-based routing
    if language and language in DEFAULT_ROUTES:
        for rule in DEFAULT_ROUTES[language]:
            result.routes.append(Route(
                agent_id=rule["agent_id"],
                layer=rule["layer"],
                reason=rule["reason"],
            ))

    # Criticality-based routing
    if criticality:
        crit_key = f"criticality_{criticality}"
        if crit_key in DEFAULT_ROUTES:
            for rule in DEFAULT_ROUTES[crit_key]:
                result.routes.append(Route(
                    agent_id=rule["agent_id"],
                    layer=rule["layer"],
                    reason=rule["reason"],
                    priority=10 if criticality == "critical" else 5,
                ))

    # Sort by priority (highest first)
    result.routes.sort(key=lambda r: r.priority, reverse=True)

    return result
