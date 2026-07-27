"""L3 — Deterministic Score Engine.

Computes a 0-10 composite score for findings based on weighted criteria.
100% deterministic — no LLM. Every weight is versioned in Git.

Scoring factors:
- Exploitability (from PoC): 0-10 weight × 0.40
- Reachability (from analysis): 0-10 weight × 0.25
- Business Impact (from criticality): 0-10 weight × 0.20
- Confidence (from evidence): 0-10 weight × 0.15
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from shared.utils.structlog_setup import get_logger

logger = get_logger(__name__)


class ExploitabilityLevel(str, Enum):
    CONFIRMED = "CONFIRMED"        # PoC succeeded
    LIKELY = "LIKELY"             # Strong indicators, PoC inconclusive
    POSSIBLE = "POSSIBLE"         # Some indicators, no confirmation
    UNLIKELY = "UNLIKELY"         # Theoretical only
    NONE = "NONE"                 # No exploit path exists


class ReachabilityLevel(str, Enum):
    REACHABLE = "REACHABLE"       # Confirmed call path to vulnerable code
    CONDITIONALLY_REACHABLE = "CONDITIONALLY_REACHABLE"  # Requires specific config
    UNREACHABLE = "UNREACHABLE"  # No call path found
    UNKNOWN = "UNKNOWN"           # Analysis incomplete


class BusinessImpactLevel(str, Enum):
    CRITICAL = "CRITICAL"         # Auth, payment, PII, crypto
    HIGH = "HIGH"                 # API handlers, DB, config
    MEDIUM = "MEDIUM"             # Business logic, data processing
    LOW = "LOW"                   # Utilities, tests, docs
    NONE = "NONE"                 # Static assets, generated code


@dataclass
class ScoreInput:
    """Input to the score engine."""
    finding_id: str
    exploitability: ExploitabilityLevel
    reachability: ReachabilityLevel
    business_impact: BusinessImpactLevel
    confidence: float  # 0.0 - 1.0
    has_poc_evidence: bool = False
    has_reachability_evidence: bool = False
    pci_scope: bool = False
    lgpd_scope: bool = False
    antifraude_scope: bool = False


@dataclass
class ScoreResult:
    """Score engine output."""
    finding_id: str
    composite_score: float  # 0.0 - 10.0
    exploitability_score: float
    reachability_score: float
    impact_score: float
    confidence_score: float
    severity_floor_applied: str = "NONE"
    breakdown: dict[str, float] = field(default_factory=dict)


# ── Scoring Weights (versioned in Git) ─────────────────────────────────

WEIGHTS = {
    "exploitability": 0.40,
    "reachability": 0.25,
    "business_impact": 0.20,
    "confidence": 0.15,
}

# Mapping levels to numeric scores (0-10)
EXPLOITABILITY_MAP: dict[ExploitabilityLevel, float] = {
    ExploitabilityLevel.CONFIRMED: 10.0,
    ExploitabilityLevel.LIKELY: 7.5,
    ExploitabilityLevel.POSSIBLE: 5.0,
    ExploitabilityLevel.UNLIKELY: 2.5,
    ExploitabilityLevel.NONE: 0.0,
}

REACHABILITY_MAP: dict[ReachabilityLevel, float] = {
    ReachabilityLevel.REACHABLE: 10.0,
    ReachabilityLevel.CONDITIONALLY_REACHABLE: 5.0,
    ReachabilityLevel.UNREACHABLE: 0.0,
    ReachabilityLevel.UNKNOWN: 3.0,
}

IMPACT_MAP: dict[BusinessImpactLevel, float] = {
    BusinessImpactLevel.CRITICAL: 10.0,
    BusinessImpactLevel.HIGH: 7.5,
    BusinessImpactLevel.MEDIUM: 5.0,
    BusinessImpactLevel.LOW: 2.5,
    BusinessImpactLevel.NONE: 0.0,
}

# Severity floors (non-negotiable minimum scores)
SEVERITY_FLOORS: dict[str, float] = {
    "ANTIFRAUDE": 9.0,  # P0
    "PCI": 7.5,         # P1
    "LGPD": 7.5,        # P1
}


def compute_score(inp: ScoreInput) -> ScoreResult:
    """Compute deterministic composite score.

    Same inputs ALWAYS produce same score. No LLM, no randomness.
    Formula: weighted average of sub-scores + severity floor enforcement.
    """
    # Sub-scores
    exploitability_score = EXPLOITABILITY_MAP.get(inp.exploitability, 0.0)
    reachability_score = REACHABILITY_MAP.get(inp.reachability, 0.0)
    impact_score = IMPACT_MAP.get(inp.business_impact, 0.0)
    confidence_score = inp.confidence * 10.0  # Normalise 0-1 to 0-10

    # Evidence boost
    if inp.has_poc_evidence and inp.exploitability == ExploitabilityLevel.CONFIRMED:
        exploitability_score = min(10.0, exploitability_score + 1.0)
    if inp.has_reachability_evidence and inp.reachability == ReachabilityLevel.REACHABLE:
        reachability_score = min(10.0, reachability_score + 1.0)

    # Weighted composite
    composite = (
        exploitability_score * WEIGHTS["exploitability"] +
        reachability_score * WEIGHTS["reachability"] +
        impact_score * WEIGHTS["business_impact"] +
        confidence_score * WEIGHTS["confidence"]
    )

    # Severity floor — never go below the non-negotiable minimum
    floor_applied = "NONE"
    if inp.antifraude_scope:
        composite = max(composite, SEVERITY_FLOORS["ANTIFRAUDE"])
        floor_applied = "ANTIFRAUDE"
    if inp.pci_scope:
        composite = max(composite, SEVERITY_FLOORS["PCI"])
        if floor_applied == "NONE":
            floor_applied = "PCI"
    if inp.lgpd_scope:
        composite = max(composite, SEVERITY_FLOORS["LGPD"])
        if floor_applied == "NONE":
            floor_applied = "LGPD"

    composite = round(min(10.0, max(0.0, composite)), 1)

    logger.info(
        "score_computed",
        finding_id=inp.finding_id[:8],
        composite=composite,
        floor=floor_applied,
    )

    return ScoreResult(
        finding_id=inp.finding_id,
        composite_score=composite,
        exploitability_score=round(exploitability_score, 1),
        reachability_score=round(reachability_score, 1),
        impact_score=round(impact_score, 1),
        confidence_score=round(confidence_score, 1),
        severity_floor_applied=floor_applied,
        breakdown={
            "exploitability": round(exploitability_score, 1),
            "reachability": round(reachability_score, 1),
            "impact": round(impact_score, 1),
            "confidence": round(confidence_score, 1),
            "weights": WEIGHTS,
        },
    )


def score_to_severity(score: float) -> str:
    """Map composite score to P0-P4 severity."""
    if score >= 8.5: return "P0"
    if score >= 7.0: return "P1"
    if score >= 5.0: return "P2"
    if score >= 3.0: return "P3"
    return "P4"
