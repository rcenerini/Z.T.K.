"""Tests for MITRE catalogs."""
from __future__ import annotations

import pytest

from shared.catalog.mitre_attack import (
    ATTACK_CATALOG, ATTACKTactic, ATTACKTechnique,
    get_techniques_for_cwe, get_techniques_by_tactic, get_severity_boost,
)
from shared.catalog.mitre_atlas import (
    ATLAS_CATALOG, ATLASTactic, ATLASTechnique,
    get_atlas_mitigations, get_p0_atlas_threats,
)


class TestATTACKCatalog:
    def test_catalog_not_empty(self) -> None:
        assert len(ATTACK_CATALOG) >= 25

    def test_all_techniques_have_cwes(self) -> None:
        for tid, tech in ATTACK_CATALOG.items():
            assert tech.technique_id == tid
            assert len(tech.cwe_ids) > 0, f"{tid}: no CWEs mapped"
            assert tech.tactic is not None

    def test_get_techniques_for_cwe(self) -> None:
        techniques = get_techniques_for_cwe("CWE-89")
        assert len(techniques) >= 1
        assert any(t.name == "Exploit Public-Facing Application" for t in techniques)

    def test_cwe_798_credential_access(self) -> None:
        techniques = get_techniques_for_cwe("CWE-798")
        assert len(techniques) >= 2  # T1003 + T1552 + T1555
        tactics = {t.tactic for t in techniques}
        assert ATTACKTactic.CREDENTIAL_ACCESS in tactics

    def test_get_techniques_by_tactic(self) -> None:
        exec_techniques = get_techniques_by_tactic(ATTACKTactic.EXECUTION)
        assert len(exec_techniques) >= 2

    def test_severity_boost_p0(self) -> None:
        boost = get_severity_boost(["CWE-89", "CWE-78"])
        assert boost > 0.5  # Both P0 impact

    def test_severity_boost_capped(self) -> None:
        boost = get_severity_boost(["CWE-89"] * 10)
        assert boost <= 3.0

    def test_all_tactics_covered(self) -> None:
        tactics = {t.tactic for t in ATTACK_CATALOG.values()}
        assert len(tactics) >= 10  # Most of the 14 tactics

    def test_t1190_has_sa_agents(self) -> None:
        t1190 = ATTACK_CATALOG["T1190"]
        assert len(t1190.sa_agents) >= 2


class TestATLASCatalog:
    def test_catalog_not_empty(self) -> None:
        assert len(ATLAS_CATALOG) >= 12

    def test_p0_threats_exist(self) -> None:
        p0 = get_p0_atlas_threats()
        assert len(p0) >= 8

    def test_prompt_injection_mapped(self) -> None:
        t51 = ATLAS_CATALOG.get("AML.T0051")
        assert t51 is not None
        assert "Prompt Guard" in t51.ztk_mitigation

    def test_all_have_mitigations(self) -> None:
        mitigations = get_atlas_mitigations()
        for tid, mit in mitigations.items():
            assert len(mit) > 0, f"{tid}: no mitigation"

    def test_owasp_llm_mapping(self) -> None:
        """Key ATLAS techniques should map to OWASP LLM Top 10."""
        owasp_mapped = [t for t in ATLAS_CATALOG.values() if t.owasp_llm_id]
        assert len(owasp_mapped) >= 4  # LLM01, LLM02, LLM03, LLM05, LLM06, LLM07, LLM08
