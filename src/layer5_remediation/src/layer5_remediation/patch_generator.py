"""L5 — Patch Generator (Trilha A).

Generates code fixes for confirmed vulnerabilities. Flow:
1. Generate patch (LLM — deterministic template for simple CWEs)
2. Validate in sandbox (build + tests)
3. Regression guard (ensure no existing tests break)
4. Publish PR (auto for P2-P4, human-required for P0-P1)
5. Merge guardrail (block auto-merge for P0/P1)
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum

from shared.utils.structlog_setup import get_logger

logger = get_logger(__name__)


class PatchStatus(str, Enum):
    GENERATED = "GENERATED"
    VALIDATED = "VALIDATED"
    REGRESSION_PASSED = "REGRESSION_PASSED"
    REGRESSION_FAILED = "REGRESSION_FAILED"
    PR_OPENED = "PR_OPENED"
    PR_MERGED = "PR_MERGED"
    PR_CLOSED = "PR_CLOSED"
    BLOCKED = "BLOCKED"


@dataclass
class PatchResult:
    """Complete patch generation result."""
    patch_id: str
    finding_id: str
    cwe_id: str
    file_path: str
    original_code: str
    patched_code: str
    description: str
    status: PatchStatus = PatchStatus.GENERATED
    pr_url: str = ""
    sandbox_passed: bool = False
    regression_passed: bool = False
    merge_blocked: bool = False
    block_reason: str = ""
    errors: list[str] = field(default_factory=list)


# ── Patch Templates (deterministic for common CWEs) ──────────────

PATCH_TEMPLATES: dict[str, str] = {
    "CWE-89": """
# FIX: SQL Injection — Replace string concatenation with parameterized query
# BEFORE: cursor.execute(f"SELECT * FROM users WHERE email='{email}'")
# AFTER:  cursor.execute("SELECT * FROM users WHERE email=?", (email,))
""",
    "CWE-79": """
# FIX: Cross-Site Scripting — Apply output encoding
# BEFORE: html += user_input
# AFTER:  html += html.escape(user_input)
""",
    "CWE-78": """
# FIX: Command Injection — Use library API instead of shell
# BEFORE: subprocess.run("echo " + user_input, shell=True)
# AFTER:  print(user_input)  # or use shlex.quote() if shell is required
""",
    "CWE-327": """
# FIX: Weak Cryptography — Replace broken algorithm
# BEFORE: hashlib.md5(data)
# AFTER:  hashlib.sha256(data)
""",
    "CWE-502": """
# FIX: Insecure Deserialization — Use safe parser
# BEFORE: pickle.loads(data)
# AFTER:  json.loads(data)
""",
    "CWE-22": """
# FIX: Path Traversal — Validate and sanitize file path
# BEFORE: open(os.path.join(base, user_input))
# AFTER:  safe_path = os.path.realpath(os.path.join(base, user_input))
#         assert safe_path.startswith(base)
#         open(safe_path)
""",
    "CWE-352": """
# FIX: CSRF Protection — Add anti-CSRF token
# BEFORE: def transfer(): process(request.form['amount'])
# AFTER:  def transfer(): validate_csrf(request); process(request.form['amount'])
""",
    "CWE-287": """
# FIX: Authentication Bypass — Enforce auth check
# BEFORE: if user.is_admin: grant_access()
# AFTER:  if session.authenticated and user.is_admin: grant_access()
""",
    "CWE-200": """
# FIX: Information Exposure — Sanitize error messages
# BEFORE: return f"Error: {str(e)}"
# AFTER:  logger.error(str(e)); return "An error occurred"
""",
    "CWE-434": """
# FIX: Unrestricted File Upload — Validate file type and extension
# BEFORE: file.save("/uploads/" + filename)
# AFTER:  validate_extension(filename); file.save("/uploads/" + safe_name)
""",
    "CWE-918": """
# FIX: SSRF Protection — Block internal URLs
# BEFORE: requests.get(user_url)
# AFTER:  validate_url(user_url, allow_internal=False); requests.get(user_url)
""",
    "CWE-611": """
# FIX: XXE Protection — Disable external entities
# BEFORE: ET.fromstring(xml_input)
# AFTER:  parser = ET.XMLParser(resolve_entities=False); ET.fromstring(xml_input, parser)
""",
    "CWE-362": """
# FIX: Race Condition — Use atomic operations
# BEFORE: if not exists: create_file()
# AFTER:  try: os.open(path, os.O_CREAT | os.O_EXCL); ...
""",
    "CWE-862": """
# FIX: Missing Authorization — Add access control check
# BEFORE: def get_data(id): return db.query(id)
# AFTER:  def get_data(id): verify_access(current_user, id); return db.query(id)
""",
}


def generate_patch(
    finding_id: str,
    cwe_id: str,
    file_path: str,
    original_code: str,
    severity: str,
    exploit_confirmed: bool = False,
) -> PatchResult:
    """Generate a code patch for a confirmed vulnerability.

    Uses deterministic templates for common CWEs.
    In production: Claude via Bedrock for complex/uncommon CWEs.

    Args:
        finding_id: The finding being fixed.
        cwe_id: CWE identifier (e.g., "CWE-89").
        file_path: Path to the vulnerable file.
        original_code: The original vulnerable code snippet.
        severity: Finding severity (P0-P4).
        exploit_confirmed: Whether PoC confirmed exploitability.

    Returns:
        PatchResult with generated patch.
    """
    patch_id = str(uuid.uuid4())[:12]

    # Get template
    template = PATCH_TEMPLATES.get(cwe_id)
    if template:
        patched_code = f"{template}\n\n# Original (vulnerable) code:\n# {original_code.strip()}"
        description = f"Fix {cwe_id} in {file_path}"
    else:
        patched_code = f"# TODO: Generate patch for {cwe_id} in {file_path}\n# Original: {original_code[:200]}"
        description = f"Patch for {cwe_id} (no template — requires LLM for complex CWE)"

    result = PatchResult(
        patch_id=patch_id,
        finding_id=finding_id,
        cwe_id=cwe_id,
        file_path=file_path,
        original_code=original_code,
        patched_code=patched_code,
        description=description,
    )

    # Merge guardrail: P0/P1 always require human approval
    if severity in ("P0", "P1"):
        result.merge_blocked = True
        result.block_reason = f"Auto-merge blocked for {severity} — human approval required"
        result.status = PatchStatus.BLOCKED

    logger.info(
        "patch_generated",
        patch_id=patch_id,
        finding_id=finding_id[:8],
        cwe_id=cwe_id,
        blocked=result.merge_blocked,
    )

    return result


def validate_patch(patch: PatchResult) -> PatchResult:
    """Validate a patch in sandbox (build + test simulation).

    In production: runs in Firecracker sandbox (L3).
    """
    # Simulate sandbox validation
    patch.sandbox_passed = True
    patch.status = PatchStatus.VALIDATED
    logger.info("patch_validated", patch_id=patch.patch_id)
    return patch


def regression_check(patch: PatchResult) -> PatchResult:
    """Run regression tests against the patched code.

    In production: runs existing test suite in sandbox.
    """
    # Simulate regression check
    patch.regression_passed = True
    patch.status = PatchStatus.REGRESSION_PASSED
    logger.info("patch_regression_passed", patch_id=patch.patch_id)
    return patch


def publish_pr(patch: PatchResult, repo_url: str = "", branch: str = "") -> PatchResult:
    """Publish patch as a Pull Request.

    Blocked for P0/P1 (requires human approval before PR creation).
    """
    if patch.merge_blocked:
        logger.info("patch_pr_blocked", patch_id=patch.patch_id, reason=patch.block_reason)
        return patch

    # Simulate PR creation
    pr_number = abs(hash(patch.patch_id)) % 10000
    patch.pr_url = f"https://github.com/{repo_url or 'repo'}/pull/{pr_number}"
    patch.status = PatchStatus.PR_OPENED

    logger.info("patch_pr_opened", patch_id=patch.patch_id, pr=patch.pr_url)
    return patch


def get_available_templates() -> list[str]:
    """List CWE IDs with available patch templates."""
    return list(PATCH_TEMPLATES.keys())
