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
    CWEClass.AUTH_BYPASS: PoCTemplate(
        cwe_id="CWE-287",
        name="Authentication Bypass PoC",
        description="Test if authentication check can be bypassed",
        target_code="""
def vulnerable_function(user_input):
    if user_input.get("admin") == True:
        return "AUTH_BYPASS_SUCCESS"
    return "ACCESS_DENIED"
""",
        exploit_payload='{"admin": true}',
        expected_behavior="Attacker bypasses authentication by setting admin=true",
    ),
    CWEClass.CRYPTO_WEAKNESS: PoCTemplate(
        cwe_id="CWE-327",
        name="Weak Cryptography PoC",
        description="Test if weak cryptographic algorithm is used",
        target_code="""
import hashlib
def vulnerable_function(user_input):
    return hashlib.md5(user_input.encode()).hexdigest()
""",
        exploit_payload="password123",
        expected_behavior="MD5 hash is produced (weak algorithm, vulnerable to collision)",
    ),
    CWEClass.RACE_CONDITION: PoCTemplate(
        cwe_id="CWE-362",
        name="Race Condition PoC",
        description="Test for time-of-check-time-of-use vulnerability",
        target_code="""
import os
def vulnerable_function(user_input):
    if not os.path.exists("/tmp/safe/" + user_input):
        return "safe"
    with open("/tmp/safe/" + user_input) as f:
        return f.read()
""",
        exploit_payload="../../../etc/passwd",
        expected_behavior="TOCTOU: file is created between check and open",
    ),
    CWEClass.MEMORY_UAF: PoCTemplate(
        cwe_id="CWE-416",
        name="Use-After-Free PoC",
        description="Test for memory corruption after free",
        target_code="""
class Resource:
    def __init__(self): self.data = "sensitive"
    def cleanup(self): self.data = None
    def use(self): return self.data

def vulnerable_function(user_input):
    r = Resource()
    r.cleanup()
    return r.use()  # UAF: accessing freed resource
""",
        exploit_payload="use_after_free",
        expected_behavior="Accessing cleaned-up resource returns None (memory safety issue)",
    ),
    "CWE-352": PoCTemplate(
        cwe_id="CWE-352",
        name="CSRF PoC",
        description="Test for Cross-Site Request Forgery",
        target_code="""
def vulnerable_function(user_input):
    token = user_input.get("csrf_token")
    action = user_input.get("action")
    if action == "transfer":
        return f"Transfer approved (no CSRF check)"
    return "Invalid"
""",
        exploit_payload='{"action": "transfer", "amount": 1000}',
        expected_behavior="Transfer executed without CSRF token validation",
    ),
    "CWE-200": PoCTemplate(
        cwe_id="CWE-200",
        name="Information Exposure PoC",
        description="Test if sensitive information is exposed in error messages",
        target_code="""
import os
def vulnerable_function(user_input):
    try:
        with open(user_input) as f:
            return f.read()
    except Exception as e:
        return f"Error: {e} (file: {user_input})"
""",
        exploit_payload="/etc/shadow",
        expected_behavior="Error message exposes file path and system details",
    ),
    "CWE-434": PoCTemplate(
        cwe_id="CWE-434",
        name="Unrestricted File Upload PoC",
        description="Test if file upload accepts dangerous extensions",
        target_code="""
def vulnerable_function(user_input):
    filename = user_input.get("filename", "")
    content = user_input.get("content", "")
    with open("/tmp/uploads/" + filename, "w") as f:
        f.write(content)
    return "Uploaded"
""",
        exploit_payload='{"filename": "shell.php", "content": "<?php system($_GET[cmd]); ?>"}',
        expected_behavior="PHP file accepted without extension validation",
    ),
    "CWE-611": PoCTemplate(
        cwe_id="CWE-611",
        name="XXE Injection PoC",
        description="Test for XML External Entity processing",
        target_code="""
import xml.etree.ElementTree as ET
def vulnerable_function(user_input):
    try:
        root = ET.fromstring(user_input)
        return root.tag
    except Exception as e:
        return str(e)
""",
        exploit_payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        expected_behavior="XML parser resolves external entity (XXE)",
    ),
    "CWE-798": PoCTemplate(
        cwe_id="CWE-798", name="Hardcoded Credentials PoC",
        description="Test if credentials are hardcoded in source code",
        target_code="""
def vulnerable_function(user_input):
    API_KEY = "sk-1234567890abcdef"
    PASSWORD = "admin123"
    return authenticate(API_KEY, PASSWORD)
""",
        exploit_payload="sk-1234567890abcdef",
        expected_behavior="Hardcoded API key and password exposed in source code",
    ),
    "CWE-306": PoCTemplate(
        cwe_id="CWE-306", name="Missing Authentication PoC",
        description="Test if endpoint lacks authentication check",
        target_code="""
def vulnerable_function(user_input):
    data = get_sensitive_data(user_input.get("id"))
    return data
""",
        exploit_payload='{"id": "admin_config"}',
        expected_behavior="Sensitive data returned without authentication check",
    ),
    "CWE-269": PoCTemplate(
        cwe_id="CWE-269", name="Improper Privilege Management PoC",
        description="Test if privileges can be escalated improperly",
        target_code="""
def vulnerable_function(user_input):
    if user_input.get("role") == "user":
        return "user_data"
    if user_input.get("role") == "admin":
        return grant_admin_access()
    return "denied"
""",
        exploit_payload='{"role": "admin"}',
        expected_behavior="Admin access granted without proper privilege validation",
    ),
    "CWE-319": PoCTemplate(
        cwe_id="CWE-319", name="Cleartext Transmission PoC",
        description="Test if sensitive data is sent over HTTP without encryption",
        target_code="""
import requests
def vulnerable_function(user_input):
    return requests.get("http://api.internal/data", auth=(user_input["user"], user_input["pass"]))
""",
        exploit_payload='{"user": "admin", "pass": "secret"}',
        expected_behavior="Credentials sent over HTTP (cleartext) — TLS not enforced",
    ),
    "CWE-400": PoCTemplate(
        cwe_id="CWE-400", name="Uncontrolled Resource Consumption PoC",
        description="Test for denial of service via resource exhaustion",
        target_code="""
def vulnerable_function(user_input):
    size = int(user_input.get("size", "1"))
    data = "x" * size
    return process_data(data)
""",
        exploit_payload='{"size": "999999999"}',
        expected_behavior="Massive memory allocation from user-controlled size (DoS)",
    ),
    "CWE-295": PoCTemplate(
        cwe_id="CWE-295", name="Improper Certificate Validation PoC",
        description="Test if TLS certificate validation is disabled or bypassed",
        target_code="""
import ssl
def vulnerable_function(user_input):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return connect(user_input["host"], ctx)
""",
        exploit_payload='{"host": "malicious.server.com"}',
        expected_behavior="Certificate validation disabled — MITM possible",
    ),
    "CWE-601": PoCTemplate(
        cwe_id="CWE-601", name="Open Redirect PoC",
        description="Test if URL redirection can be manipulated",
        target_code="""
from flask import redirect
def vulnerable_function(user_input):
    return redirect(user_input.get("next", "/"))
""",
        exploit_payload='{"next": "https://evil.com/phishing"}',
        expected_behavior="Redirect to attacker-controlled URL (phishing vector)",
    ),
    "CWE-276": PoCTemplate(
        cwe_id="CWE-276", name="Incorrect Default Permissions PoC",
        description="Test if files are created with overly permissive defaults",
        target_code="""
import os
def vulnerable_function(user_input):
    os.umask(0)
    with open("/etc/app/config.json", "w") as f:
        f.write(user_input)
    return "saved"
""",
        exploit_payload='{"admin": true}',
        expected_behavior="Config file written with world-readable permissions (umask 0)",
    ),
    "CWE-307": PoCTemplate(
        cwe_id="CWE-307", name="Improper Restriction of Auth Attempts PoC",
        description="Test if brute force protection is absent",
        target_code="""
def vulnerable_function(user_input):
    if user_input.get("pass") == "secret123":
        return "authenticated"
    return "try again"
""",
        exploit_payload='{"pass": "attempt"}',
        expected_behavior="No rate limiting or account lockout — brute-force possible",
    ),
    "CWE-522": PoCTemplate(
        cwe_id="CWE-522", name="Insufficiently Protected Credentials PoC",
        description="Test if passwords are stored insecurely",
        target_code="""
import base64
def vulnerable_function(user_input):
    stored_password = base64.b64decode("c2VjcmV0MTIz")
    if user_input.get("pass") == stored_password.decode():
        return "authenticated"
    return "denied"
""",
        exploit_payload='{"pass": "secret123"}',
        expected_behavior="Password stored with reversible encoding (base64, not hashed)",
    ),
}

POC_TEMPLATES = {k.value if hasattr(k, 'value') else k: v for k, v in POC_TEMPLATES.items()}


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
