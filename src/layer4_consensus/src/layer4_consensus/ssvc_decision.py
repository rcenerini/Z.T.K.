"""L4 — SSVC Decision Tree (Stakeholder-Specific Vulnerability Categorization).

Deterministic decision tree based on CISA SSVC v2.0.
Input: exploitation, exposure, mission_impact → Output: decision tier.

Combined with CVSS score to produce final priority.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from shared.utils.structlog_setup import get_logger

logger = get_logger(__name__)


class Exploitation(str, Enum):
    NONE = "none"      # No exploitation activity
    POC = "poc"        # Proof-of-concept exists
    ACTIVE = "active"  # Active exploitation observed


class Exposure(str, Enum):
    NONE = "none"
    CONTROLLED = "controlled"  # Internal network only
    OPEN = "open"              # Internet-facing


class MissionImpact(str, Enum):
    NONE = "none"
    PARTIAL = "partial"
    MISSION_FAILURE = "mission_failure"


class SSVCTier(str, Enum):
    TRACK = "TRACK"           # Monitor only
    TRACK_STAR = "TRACK_STAR" # Enhanced monitoring
    ATTEND = "ATTEND"         # Copilot analysis
    ACT_3 = "ACT_3"          # Act within 3 days
    ACT_14 = "ACT_14"        # Act within 14 days


# ── SSVC v2.0 Decision Matrix ─────────────────────────────────────

# Format: (Exploitation, Exposure, MissionImpact) → SSVCTier
SSVC_MATRIX: dict[tuple[Exploitation, Exposure, MissionImpact], SSVCTier] = {
    # Active exploitation → ACT (urgency depends on exposure + impact)
    (Exploitation.ACTIVE, Exposure.OPEN, MissionImpact.MISSION_FAILURE): SSVCTier.ACT_3,
    (Exploitation.ACTIVE, Exposure.OPEN, MissionImpact.PARTIAL): SSVCTier.ACT_3,
    (Exploitation.ACTIVE, Exposure.OPEN, MissionImpact.NONE): SSVCTier.ACT_14,
    (Exploitation.ACTIVE, Exposure.CONTROLLED, MissionImpact.MISSION_FAILURE): SSVCTier.ACT_3,
    (Exploitation.ACTIVE, Exposure.CONTROLLED, MissionImpact.PARTIAL): SSVCTier.ACT_14,
    (Exploitation.ACTIVE, Exposure.CONTROLLED, MissionImpact.NONE): SSVCTier.TRACK_STAR,
    (Exploitation.ACTIVE, Exposure.NONE, MissionImpact.MISSION_FAILURE): SSVCTier.ACT_14,
    (Exploitation.ACTIVE, Exposure.NONE, MissionImpact.PARTIAL): SSVCTier.TRACK_STAR,
    (Exploitation.ACTIVE, Exposure.NONE, MissionImpact.NONE): SSVCTier.TRACK,

    # PoC exists → ATTEND (analysis needed)
    (Exploitation.POC, Exposure.OPEN, MissionImpact.MISSION_FAILURE): SSVCTier.ATTEND,
    (Exploitation.POC, Exposure.OPEN, MissionImpact.PARTIAL): SSVCTier.ATTEND,
    (Exploitation.POC, Exposure.OPEN, MissionImpact.NONE): SSVCTier.TRACK_STAR,
    (Exploitation.POC, Exposure.CONTROLLED, MissionImpact.MISSION_FAILURE): SSVCTier.ATTEND,
    (Exploitation.POC, Exposure.CONTROLLED, MissionImpact.PARTIAL): SSVCTier.ATTEND,
    (Exploitation.POC, Exposure.CONTROLLED, MissionImpact.NONE): SSVCTier.TRACK,
    (Exploitation.POC, Exposure.NONE, MissionImpact.MISSION_FAILURE): SSVCTier.ATTEND,
    (Exploitation.POC, Exposure.NONE, MissionImpact.PARTIAL): SSVCTier.TRACK_STAR,
    (Exploitation.POC, Exposure.NONE, MissionImpact.NONE): SSVCTier.TRACK,

    # No exploitation → TRACK (monitor)
    (Exploitation.NONE, Exposure.OPEN, MissionImpact.MISSION_FAILURE): SSVCTier.TRACK_STAR,
    (Exploitation.NONE, Exposure.OPEN, MissionImpact.PARTIAL): SSVCTier.TRACK,
    (Exploitation.NONE, Exposure.OPEN, MissionImpact.NONE): SSVCTier.TRACK,
    (Exploitation.NONE, Exposure.CONTROLLED, MissionImpact.MISSION_FAILURE): SSVCTier.TRACK_STAR,
    (Exploitation.NONE, Exposure.CONTROLLED, MissionImpact.PARTIAL): SSVCTier.TRACK,
    (Exploitation.NONE, Exposure.CONTROLLED, MissionImpact.NONE): SSVCTier.TRACK,
    (Exploitation.NONE, Exposure.NONE, MissionImpact.MISSION_FAILURE): SSVCTier.TRACK,
    (Exploitation.NONE, Exposure.NONE, MissionImpact.PARTIAL): SSVCTier.TRACK,
    (Exploitation.NONE, Exposure.NONE, MissionImpact.NONE): SSVCTier.TRACK,
}


@dataclass
class SSVCResult:
    """SSVC decision output."""
    tier: SSVCTier
    exploitation: Exploitation
    exposure: Exposure
    mission_impact: MissionImpact
    rationale: str
    urgency_days: int = 0  # SLA in days


def decide_ssvc(
    exploitation: Exploitation,
    exposure: Exposure,
    mission_impact: MissionImpact,
    cvss_score: float = 5.0,
) -> SSVCResult:
    """Apply SSVC decision tree to determine tier.

    Deterministic — same input always produces same output.
    CVSS score modulates the decision within the same tier.
    """
    key = (exploitation, exposure, mission_impact)
    tier = SSVC_MATRIX.get(key, SSVCTier.TRACK)

    # CVSS modulation: high CVSS can escalate TRACK → TRACK_STAR
    if tier == SSVCTier.TRACK and cvss_score >= 7.0:
        tier = SSVCTier.TRACK_STAR

    # Urgency SLA
    urgency_map = {
        SSVCTier.ACT_3: 3,
        SSVCTier.ACT_14: 14,
        SSVCTier.ATTEND: 30,
        SSVCTier.TRACK_STAR: 90,
        SSVCTier.TRACK: 365,
    }
    urgency_days = urgency_map.get(tier, 365)

    rationale = (
        f"SSVC: exploitation={exploitation.value}, exposure={exposure.value}, "
        f"mission_impact={mission_impact.value}, cvss={cvss_score} → tier={tier.value}"
    )

    logger.info("ssvc_decided", tier=tier.value, exploitation=exploitation.value, cvss=cvss_score)

    return SSVCResult(
        tier=tier,
        exploitation=exploitation,
        exposure=exposure,
        mission_impact=mission_impact,
        rationale=rationale,
        urgency_days=urgency_days,
    )
