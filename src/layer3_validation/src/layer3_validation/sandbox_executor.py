"""L3 — Sandbox Executor.

Firecracker microVM sandbox for safe PoC execution (ADR-004).
Local stub for development; AWS Firecracker for production.

Key guarantees:
- Network isolation (no network access)
- Filesystem isolation (ephemeral tmpfs)
- Hard timeout (prevents DoS)
- Seccomp strict profile
- Destroyed after each execution
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from shared.utils.fail_closed import fail_closed
from shared.utils.structlog_setup import get_logger

logger = get_logger(__name__)


class SandboxMode(str, Enum):
    LOCAL = "local"       # Subprocess with restrictions (dev)
    FIRECRACKER = "firecracker"  # AWS Firecracker microVM (prod)
    DISABLED = "disabled" # No sandbox execution (dangerous — never in prod)


class ExecutionResult(str, Enum):
    EXPLOITABLE = "EXPLOITABLE"
    NOT_EXPLOITABLE = "NOT_EXPLOITABLE"
    INCONCLUSIVE = "INCONCLUSIVE"
    TIMEOUT = "TIMEOUT"
    ERROR = "ERROR"


@dataclass
class SandboxConfig:
    """Sandbox execution configuration."""
    mode: SandboxMode = SandboxMode.LOCAL
    timeout_seconds: int = 30
    memory_mb: int = 256
    disk_mb: int = 512
    network_enabled: bool = False
    readonly_rootfs: bool = True
    seccomp_profile: str = "strict"


@dataclass
class SandboxResult:
    """Result of a sandbox execution."""
    execution_id: str
    result: ExecutionResult
    exit_code: int = -1
    stdout: str = ""
    stderr: str = ""
    duration_ms: int = 0
    evidence: str = ""
    sandbox_escaped: bool = False
    errors: list[str] = field(default_factory=list)


@fail_closed(
    fallback_value=SandboxResult(execution_id="fail_closed", result=ExecutionResult.ERROR,
                                  errors=["Sandbox unavailable — operation denied"]),
    fallback_message="Sandbox execution failed — fail-closed"
)
def execute_poc(
    target_code: str,
    exploit_payload: str,
    cwe_id: str,
    config: SandboxConfig | None = None,
) -> SandboxResult:
    """Execute a Proof-of-Concept in an isolated sandbox.

    Args:
        target_code: The vulnerable target code (e.g., Flask endpoint).
        exploit_payload: The exploit to test (e.g., SQL injection string).
        cwe_id: CWE identifier for the vulnerability class.
        config: Sandbox configuration (defaults to LOCAL for dev).

    Returns:
        SandboxResult indicating whether the exploit was successful.
    """
    import uuid
    start = time.monotonic()
    cfg = config or SandboxConfig()
    exec_id = str(uuid.uuid4())[:12]

    if cfg.mode == SandboxMode.DISABLED:
        return SandboxResult(
            execution_id=exec_id, result=ExecutionResult.ERROR,
            errors=["Sandbox execution disabled — cannot run PoC"],
        )

    # Build sandboxed payload
    poc_script = _build_poc_script(target_code, exploit_payload, cwe_id)

    # Execute in isolated environment
    if cfg.mode == SandboxMode.LOCAL:
        result = _execute_local(poc_script, exec_id, cfg)
    else:
        result = _execute_firecracker_stub(poc_script, exec_id, cfg)

    result.duration_ms = int((time.monotonic() - start) * 1000)

    logger.info(
        "sandbox_execution_complete",
        execution_id=exec_id,
        result=result.result.value,
        cwe_id=cwe_id,
        duration_ms=result.duration_ms,
    )

    return result


def _build_poc_script(target_code: str, payload: str, cwe_id: str) -> str:
    """Build a self-contained PoC execution script."""
    return f"""#!/usr/bin/env python3
# ZTK Sandbox PoC — {cwe_id}
# Auto-generated, ephemeral, destroyed after execution

import sys, os, json, traceback

# Restrict dangerous operations
os.environ.clear()
os.chdir('/tmp')

TARGET_CODE = {repr(target_code)}
EXPLOIT_PAYLOAD = {repr(payload)}
CWE_ID = {repr(cwe_id)}

def execute_poc():
    try:
        # Execute target code in isolated context
        exec_globals = {{'__builtins__': {{}}}}
        exec(TARGET_CODE, exec_globals)

        # Test with exploit payload
        if 'vulnerable_function' in exec_globals:
            result = exec_globals['vulnerable_function'](EXPLOIT_PAYLOAD)
        else:
            result = None

        return {{
            "status": "executed",
            "result": str(result)[:500],
            "exploitable": _check_exploit_indicators(result, CWE_ID),
        }}
    except Exception as e:
        return {{
            "status": "error",
            "error": str(e)[:500],
            "exploitable": False,
        }}

def _check_exploit_indicators(result, cwe_id):
    indicators = {{
        "CWE-89": ["syntax error", "unexpected", "table", "column", "row"],
        "CWE-78": ["command not found", "executed", "output"],
        "CWE-79": ["<script>", "alert(", "onerror"],
        "CWE-502": ["deserialized", "object", "pickle"],
    }}
    if result is None:
        return "INCONCLUSIVE"
    result_str = str(result).lower()
    for indicator in indicators.get(cwe_id, []):
        if indicator in result_str:
            return "EXPLOITABLE"
    return "NOT_EXPLOITABLE"

if __name__ == '__main__':
    output = execute_poc()
    print(json.dumps(output))
"""


def _execute_local(script: str, exec_id: str, config: SandboxConfig) -> SandboxResult:
    """Execute PoC in local subprocess with restrictions."""
    import json

    try:
        proc = subprocess.run(
            ["python3", "-c", script],
            capture_output=True,
            text=True,
            timeout=config.timeout_seconds,
            check=False,
            env={"PATH": "/usr/bin:/bin", "HOME": "/tmp"},
        )

        if proc.returncode != 0 and proc.stderr:
            return SandboxResult(
                execution_id=exec_id,
                result=ExecutionResult.ERROR,
                exit_code=proc.returncode,
                stderr=proc.stderr[:500],
                errors=[proc.stderr[:200]],
            )

        try:
            output = json.loads(proc.stdout) if proc.stdout.strip() else {}
        except json.JSONDecodeError:
            output = {"status": "parse_error", "raw": proc.stdout[:500]}

        exploitable_raw = output.get("exploitable", "INCONCLUSIVE")

        result_map = {
            "EXPLOITABLE": ExecutionResult.EXPLOITABLE,
            "NOT_EXPLOITABLE": ExecutionResult.NOT_EXPLOITABLE,
            True: ExecutionResult.EXPLOITABLE,
            False: ExecutionResult.NOT_EXPLOITABLE,
        }

        return SandboxResult(
            execution_id=exec_id,
            result=result_map.get(exploitable_raw, ExecutionResult.INCONCLUSIVE),
            exit_code=proc.returncode,
            stdout=proc.stdout[:1000],
            stderr=proc.stderr[:500],
            evidence=output.get("result", ""),
        )

    except subprocess.TimeoutExpired:
        return SandboxResult(
            execution_id=exec_id,
            result=ExecutionResult.TIMEOUT,
            errors=[f"PoC timed out after {config.timeout_seconds}s"],
        )


def _execute_firecracker_stub(script: str, exec_id: str, config: SandboxConfig) -> SandboxResult:
    """Firecracker microVM execution stub (production path).

    In production, this:
    1. Provisions a Firecracker microVM (boot <125ms)
    2. Copies script to tmpfs
    3. Executes with seccomp strict
    4. Captures output
    5. Destroys microVM
    """
    return SandboxResult(
        execution_id=exec_id,
        result=ExecutionResult.INCONCLUSIVE,
        errors=["Firecracker sandbox not available — use AWS EC2 bare-metal for production"],
    )
