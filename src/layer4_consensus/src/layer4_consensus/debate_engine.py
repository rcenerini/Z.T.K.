"""L4 — Debate Engine (Adversarial Consensus).

Three roles: Prosecutor (argues FOR higher severity), Defender (argues FOR lower),
Judge (moderates, applies severity floors, decides final priority).

Only the debate uses LLM (Claude via Bedrock). The scoring and SSVC are
deterministic. The debate resolves ambiguity between the deterministic score
and human intuition about context.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from shared.utils.structlog_setup import get_logger

logger = get_logger(__name__)


class DebateRole(str, Enum):
    PROSECUTOR = "PROSECUTOR"  # Biased: argues for HIGHER severity
    DEFENDER = "DEFENDER"      # Biased: argues for LOWER severity
    JUDGE = "JUDGE"            # Neutral: applies floors, decides final


class FinalPriority(str, Enum):
    P0 = "P0"
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


@dataclass
class Argument:
    """A single argument in the debate."""
    role: DebateRole
    priority: str  # P0-P4
    reasoning: str
    evidence: list[str] = field(default_factory=list)
    confidence: float = 0.5  # 0.0-1.0


@dataclass
class DebateResult:
    """Debate consensus output."""
    finding_id: str
    prosecutor_priority: str
    defender_priority: str
    judge_priority: str
    final_priority: str
    hung_jury: bool = False  # True if no consensus → HITL required
    floor_applied: str = "NONE"
    divergence: float = 0.0  # Priority distance (0-4)
    debate_summary: str = ""
    hitl_required: bool = False


# ── Severity Floors (non-negotiable) ─────────────────────────────

SEVERITY_FLOORS: dict[str, str] = {
    "ANTIFRAUDE": "P0",  # Never below P0
    "PCI": "P1",         # Never below P1
    "LGPD": "P1",        # Never below P1
}

SEVERITY_ORDER: dict[str, int] = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4}


def run_debate(
    finding_id: str,
    deterministic_score: float,
    deterministic_severity: str,
    exploitability: str,
    business_context: str = "",
    pci_scope: bool = False,
    lgpd_scope: bool = False,
    antifraude_scope: bool = False,
) -> DebateResult:
    """Run adversarial debate to reach consensus on final priority.

    The debate has three phases:
    1. Prosecutor: argues why severity should be HIGHER (biased)
    2. Defender: argues why severity should be LOWER (biased)
    3. Judge: reconciles, applies floors, decides final

    Deterministic scoring combined with heuristic argumentation.
    In production, the Prosecutor/Defender use Claude via Bedrock.
    Currently: deterministic heuristic simulation.
    """
    # ── Phase 1: Prosecutor ──
    prosecutor = _prosecute(deterministic_score, exploitability, business_context)

    # ── Phase 2: Defender ──
    defender = _defend(deterministic_score, business_context)

    # ── Phase 3: Judge ──
    judge = _judge(
        deterministic_severity=deterministic_severity,
        prosecutor_priority=prosecutor.priority,
        defender_priority=defender.priority,
        pci_scope=pci_scope,
        lgpd_scope=lgpd_scope,
        antifraude_scope=antifraude_scope,
    )

    # ── Determine if hung jury ──
    divergence = abs(
        SEVERITY_ORDER.get(prosecutor.priority, 2) -
        SEVERITY_ORDER.get(defender.priority, 2)
    )
    hung_jury = divergence >= 3  # 3+ levels apart → HITL

    # ── Floor enforcement ──
    floor = "NONE"
    final_priority = judge.final_priority

    if antifraude_scope:
        floor = "ANTIFRAUDE"
        final_priority = min_priority(final_priority, SEVERITY_FLOORS["ANTIFRAUDE"])
    if pci_scope:
        if floor == "NONE": floor = "PCI"
        final_priority = min_priority(final_priority, SEVERITY_FLOORS["PCI"])
    if lgpd_scope:
        if floor == "NONE": floor = "LGPD"
        final_priority = min_priority(final_priority, SEVERITY_FLOORS["LGPD"])

    logger.info(
        "debate_complete",
        finding_id=finding_id[:8],
        final=final_priority,
        floor=floor,
        hung_jury=hung_jury,
        divergence=divergence,
    )

    return DebateResult(
        finding_id=finding_id,
        prosecutor_priority=prosecutor.priority,
        defender_priority=defender.priority,
            judge_priority=judge.judge_priority,
        final_priority=final_priority,
        hung_jury=hung_jury,
        floor_applied=floor,
        divergence=float(divergence),
        debate_summary=f"Prosecutor: {prosecutor.priority}, Defender: {defender.priority}, Judge: {judge.judge_priority} → Final: {final_priority}",
        hitl_required=hung_jury,
    )


def _prosecute(score: float, exploitability: str, context: str) -> Argument:
    """Prosecutor: biased to argue for HIGHER severity."""
    priority = "P4"
    if score >= 8.0 or exploitability == "active":
        priority = "P0"
    elif score >= 7.0 or exploitability == "poc":
        priority = "P1"
    elif score >= 5.0:
        priority = "P2"
    elif score >= 3.0:
        priority = "P3"

    reasons = []
    if score >= 7.0: reasons.append(f"High CVSS score ({score})")
    if exploitability == "active": reasons.append("Active exploitation observed")
    if exploitability == "poc": reasons.append("Proof-of-concept exists — exploit likely")
    if "auth" in context.lower(): reasons.append("Authentication bypass risk")
    if "payment" in context.lower(): reasons.append("Financial transaction impact")

    return Argument(
        role=DebateRole.PROSECUTOR,
        priority=priority,
        reasoning="; ".join(reasons) or "No mitigating factors — default to higher severity",
        confidence=min(1.0, score / 10.0),
    )


def _defend(score: float, context: str) -> Argument:
    """Defender: biased to argue for LOWER severity."""
    priority = "P0"
    if score < 3.0:
        priority = "P4"
    elif score < 5.0:
        priority = "P3"
    elif score < 7.0:
        priority = "P2"
    elif score < 8.5:
        priority = "P1"

    reasons = []
    if score < 5.0: reasons.append(f"Low CVSS score ({score})")
    if "test" in context.lower(): reasons.append("Test/non-production code")
    if "internal" in context.lower(): reasons.append("Internal network only")
    if "low" in context.lower(): reasons.append("Low business criticality")

    return Argument(
        role=DebateRole.DEFENDER,
        priority=priority,
        reasoning="; ".join(reasons) or "Conservative severity assessment",
        confidence=min(1.0, 1.0 - score / 10.0),
    )


def _judge(
    deterministic_severity: str,
    prosecutor_priority: str,
    defender_priority: str,
    pci_scope: bool,
    lgpd_scope: bool,
    antifraude_scope: bool,
) -> DebateResult:
    """Judge: neutral, applies deterministic score, resolves conflict."""
    # Judge starts from deterministic severity
    judge_priority = deterministic_severity

    # If debate is close (1 level apart), lean toward prosecutor (conservative)
    div = abs(
        SEVERITY_ORDER.get(prosecutor_priority, 2) -
        SEVERITY_ORDER.get(defender_priority, 2)
    )
    if div <= 1:
        # Close debate → use deterministic as tiebreaker
        pass
    elif div == 2:
        # Moderate divergence → lean toward prosecutor
        judge_priority = _one_level_up(deterministic_severity)
    else:
        # High divergence → HITL required (handled by caller)
        pass

    # Safety-critical domains always get prosecutor's view
    if pci_scope or antifraude_scope:
        judge_priority = min_priority(judge_priority, prosecutor_priority)

    return DebateResult(
        finding_id="",
        prosecutor_priority=prosecutor_priority,
        defender_priority=defender_priority,
        judge_priority=judge_priority,
        final_priority=judge_priority,
    )


def min_priority(a: str, b: str) -> str:
    """Return the higher-severity (lower index) priority."""
    order_a = SEVERITY_ORDER.get(a, 4)
    order_b = SEVERITY_ORDER.get(b, 4)
    idx = min(order_a, order_b)
    for k, v in SEVERITY_ORDER.items():
        if v == idx:
            return k
    return a


def _one_level_up(severity: str) -> str:
    """Increase severity by one level (P4→P3→P2→P1→P0)."""
    order = SEVERITY_ORDER.get(severity, 4)
    new_order = max(0, order - 1)
    for k, v in SEVERITY_ORDER.items():
        if v == new_order:
            return k
    return severity
