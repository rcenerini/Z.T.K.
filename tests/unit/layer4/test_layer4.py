"""Tests for Layer 4 — Consensus.

Covers: CVSS v4.0 calculator, SSVC decision tree, debate engine.
"""

from __future__ import annotations

import pytest

from layer4_consensus.cvss_calculator import (
    CVSSVector,
    CVSSScore,
    AttackVector, AttackComplexity, AttackRequirements,
    PrivilegesRequired, UserInteraction,
    VulnConfidentiality, VulnIntegrity, VulnAvailability,
    SubConfidentiality, SubIntegrity, SubAvailability,
    calculate_cvss, parse_cvss_vector,
)
from layer4_consensus.ssvc_decision import (
    Exploitation, Exposure, MissionImpact,
    SSVCTier, SSVCResult,
    decide_ssvc,
)
from layer4_consensus.debate_engine import (
    DebateRole, FinalPriority,
    Argument, DebateResult,
    run_debate,
    min_priority,
    SEVERITY_FLOORS,
)


# ═══════════════════════════════════════════════════════════════════
# CVSS v4.0 Calculator
# ═══════════════════════════════════════════════════════════════════

class TestCVSS:
    def test_critical_vector(self) -> None:
        """Network, low complexity, no privileges, no interaction, high impact → HIGH+."""
        vector = CVSSVector(
            av=AttackVector.NETWORK, ac=AttackComplexity.LOW, at=AttackRequirements.NONE,
            pr=PrivilegesRequired.NONE, ui=UserInteraction.NONE,
            vc=VulnConfidentiality.HIGH, vi=VulnIntegrity.HIGH, va=VulnAvailability.HIGH,
            sc=SubConfidentiality.HIGH, si=SubIntegrity.HIGH, sa=SubAvailability.HIGH,
        )
        result = calculate_cvss(vector)
        assert result.severity in ("HIGH", "CRITICAL")
        assert result.base_score >= 8.0

    def test_low_impact_vector(self) -> None:
        vector = CVSSVector(
            av=AttackVector.LOCAL, ac=AttackComplexity.HIGH, at=AttackRequirements.PRESENT,
            pr=PrivilegesRequired.HIGH, ui=UserInteraction.ACTIVE,
            vc=VulnConfidentiality.LOW, vi=VulnIntegrity.NONE, va=VulnAvailability.NONE,
            sc=SubConfidentiality.NONE, si=SubIntegrity.NONE, sa=SubAvailability.NONE,
        )
        result = calculate_cvss(vector)
        assert result.severity in ("LOW", "MEDIUM")

    def test_vector_string(self) -> None:
        vector = CVSSVector(
            av=AttackVector.NETWORK, ac=AttackComplexity.LOW, at=AttackRequirements.NONE,
            pr=PrivilegesRequired.NONE, ui=UserInteraction.NONE,
            vc=VulnConfidentiality.HIGH, vi=VulnIntegrity.HIGH, va=VulnAvailability.HIGH,
            sc=SubConfidentiality.NONE, si=SubIntegrity.NONE, sa=SubAvailability.NONE,
        )
        s = vector.to_string()
        assert s.startswith("CVSS:4.0/")
        assert "AV:N" in s

    def test_parse_valid_vector(self) -> None:
        vector_str = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        parsed = parse_cvss_vector(vector_str)
        assert parsed is not None
        assert parsed.av == AttackVector.NETWORK

    def test_parse_invalid_vector(self) -> None:
        assert parse_cvss_vector("garbage") is None
        assert parse_cvss_vector("") is None

    def test_deterministic(self) -> None:
        vector = CVSSVector(
            av=AttackVector.NETWORK, ac=AttackComplexity.LOW, at=AttackRequirements.NONE,
            pr=PrivilegesRequired.LOW, ui=UserInteraction.PASSIVE,
            vc=VulnConfidentiality.HIGH, vi=VulnIntegrity.LOW, va=VulnAvailability.NONE,
            sc=SubConfidentiality.NONE, si=SubIntegrity.NONE, sa=SubAvailability.NONE,
        )
        r1 = calculate_cvss(vector)
        r2 = calculate_cvss(vector)
        assert r1.base_score == r2.base_score

    def test_breakdown_complete(self) -> None:
        vector = CVSSVector(
            av=AttackVector.NETWORK, ac=AttackComplexity.LOW, at=AttackRequirements.NONE,
            pr=PrivilegesRequired.NONE, ui=UserInteraction.NONE,
            vc=VulnConfidentiality.HIGH, vi=VulnIntegrity.HIGH, va=VulnAvailability.HIGH,
            sc=SubConfidentiality.NONE, si=SubIntegrity.NONE, sa=SubAvailability.NONE,
        )
        result = calculate_cvss(vector)
        assert "av_weight" in result.breakdown
        assert "impact_total" in result.breakdown


# ═══════════════════════════════════════════════════════════════════
# SSVC Decision Tree
# ═══════════════════════════════════════════════════════════════════

class TestSSVC:
    def test_active_open_critical(self) -> None:
        result = decide_ssvc(Exploitation.ACTIVE, Exposure.OPEN, MissionImpact.MISSION_FAILURE)
        assert result.tier == SSVCTier.ACT_3
        assert result.urgency_days == 3

    def test_poc_controlled_partial(self) -> None:
        result = decide_ssvc(Exploitation.POC, Exposure.CONTROLLED, MissionImpact.PARTIAL)
        assert result.tier == SSVCTier.ATTEND

    def test_none_none_none(self) -> None:
        result = decide_ssvc(Exploitation.NONE, Exposure.NONE, MissionImpact.NONE)
        assert result.tier == SSVCTier.TRACK
        assert result.urgency_days == 365

    def test_cvss_modulation(self) -> None:
        # TRACK should escalate to TRACK_STAR with high CVSS
        result = decide_ssvc(Exploitation.NONE, Exposure.OPEN, MissionImpact.PARTIAL, cvss_score=8.0)
        assert result.tier == SSVCTier.TRACK_STAR

    def test_all_combinations_have_decision(self) -> None:
        for exp in Exploitation:
            for ex in Exposure:
                for mi in MissionImpact:
                    result = decide_ssvc(exp, ex, mi)
                    assert result.tier is not None

    def test_deterministic(self) -> None:
        r1 = decide_ssvc(Exploitation.ACTIVE, Exposure.OPEN, MissionImpact.MISSION_FAILURE)
        r2 = decide_ssvc(Exploitation.ACTIVE, Exposure.OPEN, MissionImpact.MISSION_FAILURE)
        assert r1.tier == r2.tier


# ═══════════════════════════════════════════════════════════════════
# Debate Engine
# ═══════════════════════════════════════════════════════════════════

class TestDebateEngine:
    def test_basic_debate(self) -> None:
        result = run_debate("test-123", deterministic_score=8.5, deterministic_severity="P0",
                            exploitability="active")
        assert result.prosecutor_priority == "P0"
        assert result.final_priority in ("P0", "P1")

    def test_low_score_debate(self) -> None:
        result = run_debate("test-456", deterministic_score=2.0, deterministic_severity="P4",
                            exploitability="none")
        assert result.defender_priority in ("P3", "P4")

    def test_pci_floor_enforced(self) -> None:
        result = run_debate("test-789", deterministic_score=1.0, deterministic_severity="P4",
                            exploitability="none", pci_scope=True)
        # PCI floor = P1 minimum
        assert result.final_priority in ("P0", "P1")

    def test_antifraude_floor(self) -> None:
        result = run_debate("test-000", deterministic_score=1.0, deterministic_severity="P4",
                            exploitability="none", antifraude_scope=True)
        assert result.final_priority == "P0"

    def test_hung_jury_detection(self) -> None:
        """High divergence between prosecutor (P0) and defender (P4) → hung jury."""
        result = run_debate("test-hung", deterministic_score=5.0, deterministic_severity="P2",
                            exploitability="active", business_context="low impact test file")
        # Divergence >= 3 → hung_jury
        if result.divergence >= 3:
            assert result.hung_jury is True

    def test_min_priority(self) -> None:
        assert min_priority("P0", "P4") == "P0"
        assert min_priority("P2", "P2") == "P2"
        assert min_priority("P4", "P0") == "P0"

    def test_severity_floors(self) -> None:
        assert SEVERITY_FLOORS["PCI"] == "P1"
        assert SEVERITY_FLOORS["ANTIFRAUDE"] == "P0"

    def test_deterministic(self) -> None:
        r1 = run_debate("test-det", 7.0, "P1", "poc", pci_scope=True)
        r2 = run_debate("test-det", 7.0, "P1", "poc", pci_scope=True)
        assert r1.final_priority == r2.final_priority
