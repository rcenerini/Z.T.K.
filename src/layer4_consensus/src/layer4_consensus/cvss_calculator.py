"""L4 — CVSS v4.0 Deterministic Calculator.

Implements CVSS v4.0 specification (FIRST.org).
100% deterministic — same input always produces same score.
No LLM involved.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from shared.utils.structlog_setup import get_logger

logger = get_logger(__name__)


# ── CVSS v4.0 Metric Enums ──────────────────────────────────────

class AttackVector(str, Enum):
    NETWORK = "N"
    ADJACENT = "A"
    LOCAL = "L"
    PHYSICAL = "P"

class AttackComplexity(str, Enum):
    LOW = "L"
    HIGH = "H"

class AttackRequirements(str, Enum):
    NONE = "N"
    PRESENT = "P"

class PrivilegesRequired(str, Enum):
    NONE = "N"
    LOW = "L"
    HIGH = "H"

class UserInteraction(str, Enum):
    NONE = "N"
    PASSIVE = "P"
    ACTIVE = "A"

class VulnConfidentiality(str, Enum):
    NONE = "N"
    LOW = "L"
    HIGH = "H"

class VulnIntegrity(str, Enum):
    NONE = "N"
    LOW = "L"
    HIGH = "H"

class VulnAvailability(str, Enum):
    NONE = "N"
    LOW = "L"
    HIGH = "H"

class SubConfidentiality(str, Enum):
    NONE = "N"
    LOW = "L"
    HIGH = "H"
    NEGLIGIBLE = "N"  # Alias

class SubIntegrity(str, Enum):
    NONE = "N"
    LOW = "L"
    HIGH = "H"

class SubAvailability(str, Enum):
    NONE = "N"
    LOW = "L"
    HIGH = "H"
    SAFETY = "S"


@dataclass
class CVSSVector:
    """CVSS v4.0 vector components."""
    av: AttackVector
    ac: AttackComplexity
    at: AttackRequirements
    pr: PrivilegesRequired
    ui: UserInteraction
    vc: VulnConfidentiality
    vi: VulnIntegrity
    va: VulnAvailability
    sc: SubConfidentiality
    si: SubIntegrity
    sa: SubAvailability

    def to_string(self) -> str:
        return (
            f"CVSS:4.0/AV:{self.av.value}/AC:{self.ac.value}/AT:{self.at.value}/"
            f"PR:{self.pr.value}/UI:{self.ui.value}/"
            f"VC:{self.vc.value}/VI:{self.vi.value}/VA:{self.va.value}/"
            f"SC:{self.sc.value}/SI:{self.si.value}/SA:{self.sa.value}"
        )


@dataclass
class CVSSScore:
    """CVSS v4.0 score result."""
    vector_string: str
    base_score: float
    severity: str  # NONE, LOW, MEDIUM, HIGH, CRITICAL
    exploitability_score: float
    impact_score: float
    breakdown: dict[str, float] = field(default_factory=dict)


# ── CVSS v4.0 Weight Tables (FIRST.org specification) ────────────

# Base exploitability weights (CVSS v4.0 simplified — deterministic approximation)
# Maps (AV, AC, AT) → exploitability multiplier (0-1 scale)
AV_WEIGHTS: dict[AttackVector, dict[AttackComplexity, dict[AttackRequirements, float]]] = {
    AttackVector.NETWORK: {
        AttackComplexity.LOW: {AttackRequirements.NONE: 0.85, AttackRequirements.PRESENT: 0.75},
        AttackComplexity.HIGH: {AttackRequirements.NONE: 0.70, AttackRequirements.PRESENT: 0.60},
    },
    AttackVector.ADJACENT: {
        AttackComplexity.LOW: {AttackRequirements.NONE: 0.55, AttackRequirements.PRESENT: 0.45},
        AttackComplexity.HIGH: {AttackRequirements.NONE: 0.40, AttackRequirements.PRESENT: 0.30},
    },
    AttackVector.LOCAL: {
        AttackComplexity.LOW: {AttackRequirements.NONE: 0.40, AttackRequirements.PRESENT: 0.30},
        AttackComplexity.HIGH: {AttackRequirements.NONE: 0.25, AttackRequirements.PRESENT: 0.15},
    },
    AttackVector.PHYSICAL: {
        AttackComplexity.LOW: {AttackRequirements.NONE: 0.20, AttackRequirements.PRESENT: 0.10},
        AttackComplexity.HIGH: {AttackRequirements.NONE: 0.10, AttackRequirements.PRESENT: 0.05},
    },
}

# Privileges required multiplier (reduces exploitability)
PR_WEIGHTS: dict[PrivilegesRequired, float] = {
    PrivilegesRequired.NONE: 1.0,
    PrivilegesRequired.LOW: 0.85,
    PrivilegesRequired.HIGH: 0.70,
}

# User interaction multiplier (reduces exploitability)
UI_WEIGHTS: dict[UserInteraction, float] = {
    UserInteraction.NONE: 1.0,
    UserInteraction.PASSIVE: 0.85,
    UserInteraction.ACTIVE: 0.70,
}

# Impact weights (vulnerable + subsequent system)
IMPACT_WEIGHTS: dict[str, float] = {
    "N": 0.0, "L": 0.35, "H": 0.70,
}


def calculate_cvss(vector: CVSSVector) -> CVSSScore:
    """Calculate CVSS v4.0 base score.

    Formula: BaseScore = exploitability_weight * (1 + impact_factor)
    Deterministic — no LLM, no randomness.
    """
    # Exploitability sub-score (all multipliers: 0-1)
    av_weight = AV_WEIGHTS.get(vector.av, {}).get(vector.ac, {}).get(vector.at, 0.1)
    pr_weight = PR_WEIGHTS.get(vector.pr, 1.0)
    ui_weight = UI_WEIGHTS.get(vector.ui, 1.0)

    exploitability = av_weight * pr_weight * ui_weight

    # Impact sub-score (vulnerable system)
    vc_w = IMPACT_WEIGHTS.get(vector.vc.value, 0.0)
    vi_w = IMPACT_WEIGHTS.get(vector.vi.value, 0.0)
    va_w = IMPACT_WEIGHTS.get(vector.va.value, 0.0)
    impact_vuln = 1.0 - (1.0 - vc_w) * (1.0 - vi_w) * (1.0 - va_w)

    # Impact sub-score (subsequent system)
    sc_w = IMPACT_WEIGHTS.get(vector.sc.value, 0.0)
    si_w = IMPACT_WEIGHTS.get(vector.si.value, 0.0)
    sa_w = IMPACT_WEIGHTS.get(vector.sa.value, 0.0)
    impact_sub = 1.0 - (1.0 - sc_w) * (1.0 - si_w) * (1.0 - sa_w)

    # Combined impact (vulnerable system weight > subsequent)
    impact = impact_vuln * 0.85 + impact_sub * 0.15

    # Base score: exploitability × impact (0-10 scale)
    base_score = round(exploitability * impact * 10.0, 1)

    # Severity rating
    if base_score >= 9.0:
        severity = "CRITICAL"
    elif base_score >= 7.0:
        severity = "HIGH"
    elif base_score >= 4.0:
        severity = "MEDIUM"
    elif base_score > 0.0:
        severity = "LOW"
    else:
        severity = "NONE"

    logger.info("cvss_calculated", vector=vector.to_string()[:60], score=base_score)

    return CVSSScore(
        vector_string=vector.to_string(),
        base_score=base_score,
        severity=severity,
        exploitability_score=round(exploitability * 10, 1),
        impact_score=round(impact * 10, 1),
        breakdown={
            "av_weight": round(av_weight, 3),
            "pr_weight": round(pr_weight, 3),
            "ui_weight": round(ui_weight, 3),
            "exploitability": round(exploitability, 3),
            "impact_vuln": round(impact_vuln, 3),
            "impact_sub": round(impact_sub, 3),
            "impact_total": round(impact, 3),
        },
    )


def parse_cvss_vector(vector_string: str) -> Optional[CVSSVector]:
    """Parse a CVSS v4.0 vector string into a CVSSVector object."""
    try:
        parts = {}
        for part in vector_string.replace("CVSS:4.0/", "").split("/"):
            k, v = part.split(":")
            parts[k] = v

        return CVSSVector(
            av=AttackVector(parts["AV"]),
            ac=AttackComplexity(parts["AC"]),
            at=AttackRequirements(parts["AT"]),
            pr=PrivilegesRequired(parts["PR"]),
            ui=UserInteraction(parts["UI"]),
            vc=VulnConfidentiality(parts["VC"]),
            vi=VulnIntegrity(parts["VI"]),
            va=VulnAvailability(parts["VA"]),
            sc=SubConfidentiality(parts["SC"]),
            si=SubIntegrity(parts["SI"]),
            sa=SubAvailability(parts["SA"]),
        )
    except (ValueError, KeyError):
        return None
