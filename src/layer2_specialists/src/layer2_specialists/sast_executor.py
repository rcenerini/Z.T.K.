"""L2 — SAST Executor Framework.

Generic subprocess wrapper for running any SAST tool.
Handles: execution, timeout, error capture, output normalisation.
No LLM — deterministic execution.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from shared.utils.fail_closed import fail_closed
from shared.utils.structlog_setup import get_logger

from .sast_registry import SASTAgentConfig, SASTOutputFormat

logger = get_logger(__name__)


@dataclass
class SASTExecutionResult:
    """Result of running a single SAST tool."""
    agent_id: str
    tool: str
    success: bool
    exit_code: int
    output_raw: str
    output_parsed: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration_ms: int = 0
    findings_count: int = 0


@fail_closed(
    fallback_value=SASTExecutionResult(agent_id="unknown", tool="unknown", success=False, exit_code=-1, output_raw="",
                                       errors=["SAST execution failed — fail-closed"]),
    fallback_message="SAST tool execution failed"
)
def run_sast_agent(
    config: SASTAgentConfig,
    target_path: str,
    timeout_seconds: int | None = None,
) -> SASTExecutionResult:
    """Run a single SAST agent against a target path.

    Args:
        config: SAST agent configuration from registry.
        target_path: Path to file or directory to scan.
        timeout_seconds: Override default timeout.

    Returns:
        SASTExecutionResult with parsed findings.
    """
    start = time.monotonic()
    timeout = timeout_seconds or config.timeout_seconds

    result = SASTExecutionResult(agent_id=config.agent_id, tool=config.tool, success=False, exit_code=-1, output_raw="")

    # Build command with target substitution
    cmd = []
    output_file = None

    for arg in config.command:
        if arg == "{target}":
            cmd.append(target_path)
        elif arg == "{output_file}":
            output_file = str(Path(tempfile.gettempdir()) / f"ztk-{config.agent_id}-output.json")
            cmd.append(output_file)
        elif arg == "{database}":
            # CodeQL databases are pre-built — use target as-is
            cmd.append(target_path)
        else:
            cmd.append(arg)

    logger.info("sast_execution_started", agent_id=config.agent_id, tool=config.tool, target=target_path[:80])

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        result.exit_code = proc.returncode
        result.success = proc.returncode == 0

        # Collect output (stdout or output file)
        if output_file and Path(output_file).exists():
            result.output_raw = Path(output_file).read_text(encoding="utf-8", errors="replace")
        else:
            result.output_raw = proc.stdout or proc.stderr or ""

        if proc.stderr and proc.returncode != 0:
            result.errors.append(proc.stderr[:500])

    except subprocess.TimeoutExpired:
        result.errors.append(f"SAST tool timed out after {timeout}s")
        logger.error("sast_timeout", agent_id=config.agent_id, timeout=timeout)
    except FileNotFoundError:
        result.errors.append(f"SAST tool '{config.tool}' not installed")
        logger.error("sast_tool_not_found", tool=config.tool)
    except Exception as e:
        result.errors.append(f"SAST execution error: {e}")

    result.duration_ms = int((time.monotonic() - start) * 1000)

    # Parse output if we have it
    if result.output_raw.strip():
        result.output_parsed = _parse_output(result.output_raw, config.output_format)
        result.findings_count = len(result.output_parsed)

    logger.info(
        "sast_execution_complete",
        agent_id=config.agent_id,
        success=result.success,
        findings=result.findings_count,
        duration_ms=result.duration_ms,
    )

    return result


def _parse_output(raw: str, fmt: SASTOutputFormat) -> list[dict[str, Any]]:
    """Parse SAST tool output into a list of finding dicts."""
    try:
        if fmt == SASTOutputFormat.JSON:
            data = json.loads(raw)
            return _normalise_json_output(data)
        elif fmt == SASTOutputFormat.SARIF:
            data = json.loads(raw)
            return _normalise_sarif_output(data)
        elif fmt == SASTOutputFormat.XML:
            # XML parsing stub — implement per-tool
            return [{"source": "xml", "raw": raw[:500]}]
        else:
            # TEXT — stub
            return [{"source": "text", "raw": raw[:500]}]
    except (json.JSONDecodeError, KeyError, IndexError):
        return []


def _normalise_json_output(data: Any) -> list[dict[str, Any]]:
    """Normalise JSON output to a standardised finding dict.

    Handles common formats: Bandit, Semgrep, Checkov, gosec, ESLint.
    """
    findings: list[dict[str, Any]] = []

    # Bandit + Semgrep format: {"results": [...]}
    if isinstance(data, dict) and "results" in data and isinstance(data["results"], list):
        for r in data["results"]:
            if "issue_severity" in r:
                # Bandit format
                findings.append({
                    "severity": r.get("issue_severity", "UNKNOWN"),
                    "confidence": r.get("issue_confidence", "UNKNOWN"),
                    "cwe_id": f"CWE-{r.get('issue_cwe', {}).get('id', '')}" if r.get("issue_cwe") else None,
                    "file_path": r.get("filename", ""),
                    "line_number": r.get("line_number", 0),
                    "description": r.get("issue_text", ""),
                    "test_id": r.get("test_id", ""),
                })
            elif "check_id" in r:
                # Semgrep format
                findings.append({
                    "severity": r.get("extra", {}).get("severity", "UNKNOWN"),
                    "file_path": r.get("path", ""),
                    "line_number": r.get("start", {}).get("line", 0),
                    "description": r.get("extra", {}).get("message", ""),
                    "check_id": r.get("check_id", ""),
                    "cwe_id": ",".join(r.get("extra", {}).get("metadata", {}).get("cwe", [])),
                })

    # Checkov format: {"results": {"failed_checks": [...]}}
    elif isinstance(data, dict) and "results" in data and isinstance(data["results"], dict):
        for r in data["results"].get("failed_checks", []):
            findings.append({
                "severity": r.get("severity", "UNKNOWN"),
                "file_path": r.get("file_path", ""),
                "line_number": r.get("file_line_range", [0])[0] if r.get("file_line_range") else 0,
                "description": r.get("check_name", ""),
                "check_id": r.get("check_id", ""),
            })

    # gosec format: {"Issues": [...]}
    elif isinstance(data, dict) and "Issues" in data:
        for r in data["Issues"]:
            findings.append({
                "severity": r.get("severity", "UNKNOWN"),
                "file_path": r.get("file", ""),
                "line_number": r.get("line", "0"),
                "description": r.get("details", ""),
                "check_id": r.get("rule_id", ""),
            })

    # Generic list
    elif isinstance(data, list):
        findings = data

    return findings


def _normalise_sarif_output(data: dict) -> list[dict[str, Any]]:
    """Normalise SARIF output to standardised finding dict."""
    findings: list[dict[str, Any]] = []

    for run in data.get("runs", []):
        tool_name = run.get("tool", {}).get("driver", {}).get("name", "unknown")

        for result in run.get("results", []):
            loc = result.get("locations", [{}])[0]
            phys = loc.get("physicalLocation", {})

            findings.append({
                "severity": result.get("level", "warning"),
                "file_path": phys.get("artifactLocation", {}).get("uri", ""),
                "line_number": phys.get("region", {}).get("startLine", 0),
                "description": result.get("message", {}).get("text", ""),
                "rule_id": result.get("ruleId", ""),
                "tool": tool_name,
            })

    return findings
