"""L3 — PoC Runner Framework.

CWE-specific PoC templates and execution orchestration.
Each CWE class has a deterministic template for exploit testing.
No LLM — the template library is versioned in Git.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from shared.utils.structlog_setup import get_logger

from .sandbox_executor import (
    ExecutionResult,
    SandboxConfig,
    SandboxResult,
    execute_poc,
)

logger = get_logger(__name__)


class CWEClass(str, Enum):
    """CWE vulnerability classes with PoC templates."""
    SQL_INJECTION = "CWE-89"
    COMMAND_INJECTION = "CWE-78"
    XSS = "CWE-79"
    SSRF = "CWE-918"
    DESERIALIZATION = "CWE-502"
    AUTH_BYPASS = "CWE-287"
    PATH_TRAVERSAL = "CWE-22"
    CRYPTO_WEAKNESS = "CWE-327"
    RACE_CONDITION = "CWE-362"
    MEMORY_UAF = "CWE-416"


@dataclass
class PoCTemplate:
    """A PoC template for a specific CWE class."""
    cwe_id: str
    name: str
    description: str
    target_code: str
    exploit_payload: str
    expected_behavior: str
    false_positive_indicators: list[str] = field(default_factory=list)


# ── PoC Template Library ─────────────────────────────────────────────────

POC_TEMPLATES: dict[str, PoCTemplate] = {
    CWEClass.SQL_INJECTION: PoCTemplate(
        cwe_id="CWE-89",
        name="SQL Injection PoC",
        description="Test if unsanitized input reaches SQL query execution",
        target_code="""
import sqlite3
def vulnerable_function(user_input):
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE users (id INTEGER, name TEXT)")
    query = "SELECT * FROM users WHERE name = '" + user_input + "'"
    try:
        cursor.execute(query)
        return cursor.fetchall()
    except Exception as e:
        return str(e)
""",
        exploit_payload="' OR '1'='1",
        expected_behavior="Query returns all users (bypasses WHERE clause)",
        false_positive_indicators=["syntax error", "no such table"],
    ),

    CWEClass.COMMAND_INJECTION: PoCTemplate(
        cwe_id="CWE-78",
        name="Command Injection PoC",
        description="Test if user input reaches OS command execution",
        target_code="""
import subprocess
def vulnerable_function(user_input):
    try:
        result = subprocess.check_output("echo " + user_input, shell=True, text=True)
        return result
    except Exception as e:
        return str(e)
""",
        exploit_payload="hello; id",
        expected_behavior="Command 'id' executes, returning user information",
    ),

    CWEClass.XSS: PoCTemplate(
        cwe_id="CWE-79",
        name="Cross-Site Scripting PoC",
        description="Test if unescaped input renders as HTML/JavaScript",
        target_code="""
def vulnerable_function(user_input):
    html = "<div>" + user_input + "</div>"
    if "<script>" in html or "onerror" in html:
        return "XSS_EXPLOITABLE"
    return html
""",
        exploit_payload='<img src=x onerror="alert(1)">',
        expected_behavior="JavaScript event handler injected into HTML output",
    ),

    CWEClass.SSRF: PoCTemplate(
        cwe_id="CWE-918",
        name="Server-Side Request Forgery PoC",
        description="Test if attacker-controlled URL is fetched by server",
        target_code="""
import urllib.request
def vulnerable_function(user_input):
    try:
        response = urllib.request.urlopen(user_input, timeout=5)
        return f"SSRF_SUCCESS: HTTP {response.getcode()}"
    except Exception as e:
        return str(e)
""",
        exploit_payload="http://169.254.169.254/latest/meta-data/",
        expected_behavior="Server fetches AWS metadata endpoint (SSRF confirmed)",
    ),

    CWEClass.DESERIALIZATION: PoCTemplate(
        cwe_id="CWE-502",
        name="Insecure Deserialization PoC",
        description="Test if untrusted data is deserialized without validation",
        target_code="""
import json
def vulnerable_function(user_input):
    try:
        data = json.loads(user_input)
        if data.get("__class__"):
            return "DESERIALIZATION_RISK"
        return data
    except Exception as e:
        return str(e)
""",
        exploit_payload='{"__class__": "os.system", "args": ["id"]}',
        expected_behavior="Deserialized object contains class injection indicators",
    ),

    CWEClass.PATH_TRAVERSAL: PoCTemplate(
        cwe_id="CWE-22",
        name="Path Traversal PoC",
        description="Test if file path can escape intended directory",
        target_code="""
import os
def vulnerable_function(user_input):
    base_dir = "/tmp/safe/"
    full_path = os.path.join(base_dir, user_input)
    try:
        with open(full_path, 'r') as f:
            return f.read()[:100]
    except Exception as e:
        return str(e)
""",
        exploit_payload="../../../etc/passwd",
        expected_behavior="File read escapes base_dir to read /etc/passwd",
    ),
}


@dataclass
class PoCResult:
    """Complete PoC analysis result."""
    finding_id: str
    cwe_id: str
    exploitable: bool
    sandbox_result: SandboxResult
    template_used: str
    confidence: str  # HIGH, MEDIUM, LOW
    evidence_summary: str = ""
    false_positive_check: bool = False


def run_poc(
    finding_id: str,
    cwe_id: str,
    target_code: str | None = None,
    exploit_payload: str | None = None,
    sandbox_config: SandboxConfig | None = None,
) -> PoCResult:
    """Run a PoC for a given CWE class.

    If target_code/exploit_payload not provided, uses the template library.
    """
    template = POC_TEMPLATES.get(cwe_id)
    if not template and not target_code:
        return PoCResult(
            finding_id=finding_id, cwe_id=cwe_id, exploitable=False,
            sandbox_result=SandboxResult(execution_id="no-template", result=ExecutionResult.INCONCLUSIVE,
                                          errors=[f"No PoC template for {cwe_id}"]),
            template_used="none", confidence="LOW",
        )

    code = target_code or (template.target_code if template else "")
    payload = exploit_payload or (template.exploit_payload if template else "")

    # Execute in sandbox
    result = execute_poc(code, payload, cwe_id, sandbox_config)

    # Determine exploitability
    exploitable = result.result == ExecutionResult.EXPLOITABLE

    # False positive check
    false_positive = False
    if template and result.stdout:
        for indicator in template.false_positive_indicators:
            if indicator.lower() in result.stdout.lower():
                false_positive = True
                break

    # Confidence assessment
    if exploitable and not false_positive:
        confidence = "HIGH"
    elif exploitable and false_positive:
        confidence = "LOW"
    elif result.result == ExecutionResult.INCONCLUSIVE:
        confidence = "LOW"
    else:
        confidence = "MEDIUM"

    logger.info(
        "poc_executed",
        finding_id=finding_id[:8],
        cwe_id=cwe_id,
        exploitable=exploitable,
        confidence=confidence,
    )

    return PoCResult(
        finding_id=finding_id,
        cwe_id=cwe_id,
        exploitable=exploitable,
        sandbox_result=result,
        template_used=template.name if template else "custom",
        confidence=confidence,
        evidence_summary=result.evidence[:200],
        false_positive_check=not false_positive,
    )


def get_available_templates() -> list[str]:
    """List all available PoC template CWEs."""
    return list(POC_TEMPLATES.keys())
