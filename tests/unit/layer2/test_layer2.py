"""Tests for Layer 2 — SAST Specialists.

Covers: registry, executor, agents, orchestrator.
Focus: framework correctness, output parsing, registry completeness.
"""

from __future__ import annotations

import json

import pytest

from layer2_specialists.sast_registry import (
    SAST_REGISTRY,
    SASTAgentConfig,
    get_agents_for_language,
    get_cross_cutting_agents,
)
from layer2_specialists.sast_executor import (
    _normalise_json_output,
    _normalise_sarif_output,
    SASTExecutionResult,
)
from layer2_specialists.sast_agents import (
    _map_severity,
    run_bandit,
    run_semgrep,
)
from shared.schemas.finding import FindingSeverity


# ═══════════════════════════════════════════════════════════════════
# SAST Registry
# ═══════════════════════════════════════════════════════════════════

class TestSASTRegistry:
    def test_registry_not_empty(self) -> None:
        assert len(SAST_REGISTRY) >= 20

    def test_all_agents_have_required_fields(self) -> None:
        for agent_id, config in SAST_REGISTRY.items():
            assert config.agent_id == agent_id, f"agent_id mismatch: {agent_id}"
            assert config.tool, f"tool missing: {agent_id}"
            assert config.language, f"language missing: {agent_id}"
            assert len(config.command) > 0, f"command empty: {agent_id}"

    def test_python_agents_exist(self) -> None:
        agents = get_agents_for_language("python")
        agent_ids = [a.agent_id for a in agents]
        assert "L2.01-bandit" in agent_ids
        assert "L2.02-semgrep-python" in agent_ids

    def test_java_agents_exist(self) -> None:
        agents = get_agents_for_language("java")
        agent_ids = [a.agent_id for a in agents]
        assert "L2.03-spotbugs" in agent_ids

    def test_terraform_agents_exist(self) -> None:
        agents = get_agents_for_language("terraform")
        agent_ids = [a.agent_id for a in agents]
        assert "L2.24-checkov" in agent_ids
        assert "L2.25-tfsec" in agent_ids

    def test_cross_cutting_agents(self) -> None:
        agents = get_cross_cutting_agents()
        agent_ids = [a.agent_id for a in agents]
        assert "L2.28-gitleaks" in agent_ids
        assert "L2.29-trufflehog" in agent_ids

    def test_unknown_language_returns_empty(self) -> None:
        agents = get_agents_for_language("brainfuck")
        assert len(agents) == 0

    def test_all_languages_in_scope(self) -> None:
        languages = {c.language for c in SAST_REGISTRY.values()}
        expected = {"python", "java", "javascript", "cpp", "go", "rust", "csharp",
                     "php", "ruby", "kotlin", "swift", "terraform", "dockerfile",
                     "kubernetes", "all"}
        for lang in expected:
            assert lang in languages, f"Missing language: {lang}"


# ═══════════════════════════════════════════════════════════════════
# SAST Output Parser
# ═══════════════════════════════════════════════════════════════════

class TestSASTParser:
    def test_bandit_format(self) -> None:
        raw = json.dumps({
            "results": [{
                "issue_severity": "HIGH",
                "issue_confidence": "HIGH",
                "issue_cwe": {"id": 89, "link": "https://cwe.mitre.org/data/definitions/89.html"},
                "filename": "src/auth/login.py",
                "line_number": 42,
                "issue_text": "Possible SQL injection vector",
                "test_id": "B608",
            }]
        })
        findings = _normalise_json_output(json.loads(raw))
        assert len(findings) == 1
        assert findings[0]["severity"] == "HIGH"
        assert findings[0]["file_path"] == "src/auth/login.py"
        assert findings[0]["line_number"] == 42

    def test_semgrep_format(self) -> None:
        raw = json.dumps({
            "results": [{
                "check_id": "python.lang.security.audit.sql-injection",
                "path": "src/app.py",
                "start": {"line": 10, "col": 5},
                "extra": {
                    "severity": "ERROR",
                    "message": "Detected SQL injection",
                    "metadata": {"cwe": ["CWE-89"]},
                },
            }]
        })
        findings = _normalise_json_output(json.loads(raw))
        assert len(findings) == 1
        assert findings[0]["severity"] == "ERROR"

    def test_checkov_format(self) -> None:
        raw = json.dumps({
            "results": {
                "failed_checks": [{
                    "severity": "CRITICAL",
                    "file_path": "infra/main.tf",
                    "file_line_range": [5, 10],
                    "check_name": "Ensure S3 bucket has block public access",
                    "check_id": "CKV_AWS_21",
                }]
            }
        })
        findings = _normalise_json_output(json.loads(raw))
        assert len(findings) == 1
        assert findings[0]["severity"] == "CRITICAL"

    def test_gosec_format(self) -> None:
        raw = json.dumps({
            "Issues": [{
                "severity": "HIGH",
                "file": "main.go",
                "line": "25",
                "details": "Use of weak cryptographic primitive",
                "rule_id": "G401",
            }]
        })
        findings = _normalise_json_output(json.loads(raw))
        assert len(findings) == 1
        assert findings[0]["severity"] == "HIGH"

    def test_sarif_format(self) -> None:
        raw = json.dumps({
            "runs": [{
                "tool": {"driver": {"name": "CodeQL"}},
                "results": [{
                    "ruleId": "java/sql-injection",
                    "level": "error",
                    "message": {"text": "SQL injection vulnerability"},
                    "locations": [{"physicalLocation": {
                        "artifactLocation": {"uri": "src/Main.java"},
                        "region": {"startLine": 42},
                    }}],
                }],
            }]
        })
        findings = _normalise_sarif_output(json.loads(raw))
        assert len(findings) == 1
        assert findings[0]["severity"] == "error"
        assert findings[0]["file_path"] == "src/Main.java"

    def test_empty_output(self) -> None:
        findings = _normalise_json_output({})
        assert len(findings) == 0

    def test_invalid_json(self) -> None:
        # Should not crash — returns empty
        from layer2_specialists.sast_executor import _parse_output
        from layer2_specialists.sast_registry import SASTOutputFormat
        result = _parse_output("not valid json {", SASTOutputFormat.JSON)
        assert len(result) == 0


# ═══════════════════════════════════════════════════════════════════
# Severity Mapping
# ═══════════════════════════════════════════════════════════════════

class TestSeverityMapping:
    def test_high_maps_to_p0(self) -> None:
        assert _map_severity("HIGH", {"HIGH": "P0"}) == FindingSeverity.P0

    def test_unknown_maps_to_p3(self) -> None:
        assert _map_severity("UNKNOWN", {}) == FindingSeverity.P3

    def test_invalid_maps_to_p3(self) -> None:
        assert _map_severity("INVALID", {"X": "P9"}) == FindingSeverity.P3


# ═══════════════════════════════════════════════════════════════════
# SAST Execution Result
# ═══════════════════════════════════════════════════════════════════

class TestExecutionResult:
    def test_result_defaults(self) -> None:
        result = SASTExecutionResult(agent_id="test", tool="test", success=False, exit_code=1, output_raw="")
        assert result.findings_count == 0
        assert result.errors == []
        assert result.duration_ms == 0

    def test_agent_registry_consistency(self) -> None:
        """All severity maps use valid FindingSeverity values."""
        valid = set(s.value for s in FindingSeverity)
        for config in SAST_REGISTRY.values():
            for mapped in config.severity_map.values():
                assert mapped in valid, f"{config.agent_id}: invalid severity '{mapped}'"
