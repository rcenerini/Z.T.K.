"""L2 — SAST Agent implementations.

Reference implementations for Bandit (Python) and Semgrep (multi-language).
These consume the executor framework and the Finding schema.
"""

from __future__ import annotations

from uuid import uuid4

from shared.schemas.finding import (
    Confidence,
    Finding,
    FindingSeverity,
    FindingSource,
    FindingStatus,
)
from shared.utils.fail_closed import fail_closed
from shared.utils.structlog_setup import get_logger

from .sast_executor import run_sast_agent
from .sast_registry import SAST_REGISTRY

logger = get_logger(__name__)


@fail_closed(fallback_value=[], fallback_message="Bandit agent failed")
def run_bandit(target_path: str, tenant_id: str = "ztk-proj") -> list[Finding]:
    """Run Bandit SAST against a Python target.

    Deterministic: same code always produces same findings.
    """
    config = SAST_REGISTRY["L2.01-bandit"]
    result = run_sast_agent(config, target_path)

    if not result.success and not result.output_parsed:
        return []

    findings: list[Finding] = []
    for raw in result.output_parsed:
        severity = _map_severity(raw.get("severity", "UNKNOWN"), config.severity_map)
        cwe_id = raw.get("cwe_id", "") if raw.get("cwe_id") else "CWE-0"  # Unknown

        finding = Finding(
            finding_id=uuid4(),
            tenant_id=tenant_id,
            source=FindingSource.BANDIT,
            severity=severity,
            cwe_ids=[cwe_id] if cwe_id and cwe_id != "CWE-" else [],
            title=raw.get("test_id", "Bandit finding"),
            description=raw.get("description", "")[:5000],
            file_path=raw.get("file_path", ""),
            line_number=raw.get("line_number", 1),
            confidence=Confidence.HIGH if raw.get("confidence") == "HIGH" else Confidence.MEDIUM,
            status=FindingStatus.RAW,
        )
        findings.append(finding)

    logger.info("bandit_complete", target=target_path[:60], findings=len(findings))
    return findings


@fail_closed(fallback_value=[], fallback_message="Semgrep agent failed")
def run_semgrep(target_path: str, language: str, tenant_id: str = "ztk-proj") -> list[Finding]:
    """Run Semgrep against a target.

    Deterministic: same code + same rules always produces same findings.
    """
    config_key = f"L2.02-semgrep-{language}" if language in ("python",) else "L2.06-semgrep-js"
    config = SAST_REGISTRY.get(config_key) or SAST_REGISTRY["L2.06-semgrep-js"]
    result = run_sast_agent(config, target_path)

    if not result.success and not result.output_parsed:
        return []

    findings: list[Finding] = []
    for raw in result.output_parsed:
        findings.append(Finding(
            finding_id=uuid4(),
            tenant_id=tenant_id,
            source=FindingSource.SEMGREP,
            severity=_map_severity(raw.get("severity", "UNKNOWN"), config.severity_map),
            cwe_ids=[cwe.strip() for cwe in raw.get("cwe_id", "").split(",") if cwe.strip() and cwe.strip() != "N/A"],
            title=raw.get("check_id", "Semgrep finding"),
            description=raw.get("description", "")[:5000],
            file_path=raw.get("file_path", ""),
            line_number=raw.get("line_number", 1),
            confidence=Confidence.MEDIUM,
            status=FindingStatus.RAW,
        ))
        findings.append(finding)

    logger.info("semgrep_complete", target=target_path[:60], language=language, findings=len(findings))
    return findings


def _map_severity(tool_severity: str, severity_map: dict[str, str]) -> FindingSeverity:
    """Map tool-specific severity to Z.T.K. normalised severity."""
    mapped = severity_map.get(tool_severity, "P3")
    try:
        return FindingSeverity(mapped)
    except ValueError:
        return FindingSeverity.P3
