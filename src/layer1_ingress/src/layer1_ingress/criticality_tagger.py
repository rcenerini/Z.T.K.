"""L1.04 — Business Criticality Tagger Agent.

Maps file paths to business criticality scores based on:
1. CODEOWNERS-like path patterns
2. File content heuristics (auth, payment, pii, crypto)
3. Configuration-based scoring matrix
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from shared.utils.fail_closed import fail_closed
from shared.utils.structlog_setup import get_logger

logger = get_logger(__name__)


class CriticalityLevel(str, Enum):
    CRITICAL = "CRITICAL"   # P0 — auth, payments, PII, crypto
    HIGH = "HIGH"           # P1 — API handlers, DB access, config
    MEDIUM = "MEDIUM"       # P2 — business logic, data processing
    LOW = "LOW"             # P3 — utilities, tests, docs
    NONE = "NONE"           # P4 — static assets, generated code


@dataclass
class CriticalityResult:
    """Criticality assessment for a file."""
    file_path: str
    level: CriticalityLevel
    reasons: list[str]
    score: float  # 0.0 (low) — 10.0 (critical)


# ── Criticality Rules ─────────────────────────────────────────────

# Path patterns → CriticalityLevel (ordered by priority)
PATH_RULES: list[tuple[str, CriticalityLevel, str]] = [
    # 🟢 LOW — must come before specific patterns to override them
    ("**/test/**", CriticalityLevel.LOW, "Test file"),
    ("**/tests/**", CriticalityLevel.LOW, "Test directory"),
    ("**/spec/**", CriticalityLevel.LOW, "Spec file"),
    ("**/mock/**", CriticalityLevel.LOW, "Mock/stub"),
    ("**/fixture/**", CriticalityLevel.LOW, "Test fixture"),

    # ⚪ NONE — must come before path patterns to override (e.g. docs/auth.md → NONE, not CRITICAL)
    ("**/*.md", CriticalityLevel.NONE, "Markdown file"),
    ("**/*.txt", CriticalityLevel.NONE, "Text file"),
    ("**/*.json", CriticalityLevel.NONE, "JSON file"),
    ("**/*.yaml", CriticalityLevel.NONE, "YAML file"),
    ("**/*.yml", CriticalityLevel.NONE, "YAML file"),
    ("**/*.svg", CriticalityLevel.NONE, "SVG asset"),
    ("**/*.png", CriticalityLevel.NONE, "Image asset"),
    ("**/*.css", CriticalityLevel.NONE, "Stylesheet"),
    ("**/*.html", CriticalityLevel.NONE, "HTML template"),
    ("**/.gitignore", CriticalityLevel.NONE, "Git ignore"),
    ("**/dist/**", CriticalityLevel.NONE, "Distribution artifact"),
    ("**/build/**", CriticalityLevel.NONE, "Build artifact"),
    ("**/node_modules/**", CriticalityLevel.NONE, "Dependency"),
    ("**/vendor/**", CriticalityLevel.NONE, "Vendor dependency"),

    # 🔴 CRITICAL
    ("**/auth/**", CriticalityLevel.CRITICAL, "Authentication module"),
    ("**/login/**", CriticalityLevel.CRITICAL, "Login flow"),
    ("**/oauth/**", CriticalityLevel.CRITICAL, "OAuth integration"),
    ("**/sso/**", CriticalityLevel.CRITICAL, "Single Sign-On"),
    ("**/payment/**", CriticalityLevel.CRITICAL, "Payment processing"),
    ("**/transaction/**", CriticalityLevel.CRITICAL, "Financial transaction"),
    ("**/checkout/**", CriticalityLevel.CRITICAL, "Checkout flow"),
    ("**/crypto/**", CriticalityLevel.CRITICAL, "Cryptographic module"),
    ("**/encryption/**", CriticalityLevel.CRITICAL, "Encryption logic"),
    ("**/certificate/**", CriticalityLevel.CRITICAL, "Certificate management"),
    ("**/pii/**", CriticalityLevel.CRITICAL, "PII processing"),
    ("**/gdpr/**", CriticalityLevel.CRITICAL, "GDPR compliance"),

    # 🟠 HIGH
    ("**/api/**", CriticalityLevel.HIGH, "API handler"),
    ("**/handler/**", CriticalityLevel.HIGH, "Request handler"),
    ("**/controller/**", CriticalityLevel.HIGH, "Controller"),
    ("**/middleware/**", CriticalityLevel.HIGH, "Middleware"),
    ("**/database/**", CriticalityLevel.HIGH, "Database access"),
    ("**/repository/**", CriticalityLevel.HIGH, "Data repository"),
    ("**/dao/**", CriticalityLevel.HIGH, "Data Access Object"),
    ("**/config/**", CriticalityLevel.HIGH, "Configuration"),
    ("**/settings/**", CriticalityLevel.HIGH, "Application settings"),
    ("**/secrets/**", CriticalityLevel.HIGH, "Secrets management"),
    ("**/iam/**", CriticalityLevel.HIGH, "IAM module"),
    ("**/rbac/**", CriticalityLevel.HIGH, "Role-based access control"),
    ("**/session/**", CriticalityLevel.HIGH, "Session management"),

    # 🟡 MEDIUM
    ("**/service/**", CriticalityLevel.MEDIUM, "Service layer"),
    ("**/business/**", CriticalityLevel.MEDIUM, "Business logic"),
    ("**/domain/**", CriticalityLevel.MEDIUM, "Domain logic"),
    ("**/model/**", CriticalityLevel.MEDIUM, "Data model"),
    ("**/dto/**", CriticalityLevel.MEDIUM, "Data Transfer Object"),
    ("**/mapper/**", CriticalityLevel.MEDIUM, "Object mapper"),
    ("**/validator/**", CriticalityLevel.MEDIUM, "Validation logic"),

    # 🟢 LOW
    ("**/test/**", CriticalityLevel.LOW, "Test file"),
    ("**/tests/**", CriticalityLevel.LOW, "Test directory"),
    ("**/spec/**", CriticalityLevel.LOW, "Spec file"),
    ("**/mock/**", CriticalityLevel.LOW, "Mock/stub"),
    ("**/fixture/**", CriticalityLevel.LOW, "Test fixture"),
    ("**/docs/**", CriticalityLevel.LOW, "Documentation"),
    ("**/README*", CriticalityLevel.LOW, "README file"),
    ("**/example/**", CriticalityLevel.LOW, "Example code"),
    ("**/sample/**", CriticalityLevel.LOW, "Sample code"),
    ("**/util/**", CriticalityLevel.LOW, "Utility code"),
    ("**/helper/**", CriticalityLevel.LOW, "Helper function"),
    ("**/logging/**", CriticalityLevel.LOW, "Logging module"),
]

# Content-based heuristics (regex patterns → score boost)
CONTENT_RULES: list[tuple[str, float, str]] = [
    (r"(?i)\b(password|passwd|pwd|secret|token|api_key|private_key)\s*[:=]", 2.0, "Hardcoded credential pattern"),
    (r"(?i)\b(SELECT|INSERT|UPDATE|DELETE|MERGE)\s+.*\b(FROM|INTO|SET)\b", 2.0, "SQL query"),
    (r"(?i)\b(bcrypt|scrypt|argon2|pbkdf2|sha256|sha512|aes|rsa|ecdsa|ed25519)\b", 2.0, "Cryptographic primitive"),
    (r"(?i)\b(AccessToken|RefreshToken|JWT|OAuth|Bearer)\b", 1.5, "Auth token reference"),
    (r"(?i)\b(PAN|CHD|cardholder|primary.account.number)\b", 3.0, "PCI data reference"),
    (r"(?i)\b(XSS|CSRF|CORS|CSP|HSTS)\b", 1.0, "Security header reference"),
    (r"(?i)\bimport\s+(os|subprocess|socket|ctypes)\b", 1.0, "Dangerous import"),
]


def _match_path(file_path: str, pattern: str) -> bool:
    """Match a file path against a glob pattern with **/ support."""
    import re

    normalised = file_path.replace("\\", "/")
    pattern_normalised = pattern.replace("\\", "/")

    segments = pattern_normalised.split("/")
    regex_parts: list[str] = ["^"]

    for i, seg in enumerate(segments):
        is_last = (i == len(segments) - 1)
        is_first = (i == 0)

        if seg == "**":
            if is_last:
                # Final **: match any remaining path including filename
                regex_parts.append(r"(?:.+/)?[^/]+")
            elif is_first:
                # First **/ : match optional directory prefix
                regex_parts.append(r"(?:.+/)?")
            else:
                # Middle **/ : already included in previous segment's /
                regex_parts.append(r"(?:.+/)?")
        elif seg.startswith("*."):
            regex_parts.append(r"[^/]*" + re.escape(seg[1:]))
        elif "*" in seg:
            regex_parts.append(re.escape(seg).replace(r"\*", r"[^/]*"))
        else:
            regex_parts.append(re.escape(seg))

        if not is_last and seg != "**":
            regex_parts.append(r"/")

    regex_parts.append("$")
    full_regex = "".join(regex_parts)
    return bool(re.match(full_regex, normalised))


@fail_closed(fallback_value=CriticalityResult(file_path="", level=CriticalityLevel.HIGH, reasons=["fail_closed"], score=7.0))
def assess_file(file_path: str, content: str = "") -> CriticalityResult:
    """Assess the business criticality of a file.

    Returns CriticalityResult with level, reasons, and score.
    Deterministic: same path + content always produces same result.
    """
    reasons: list[str] = []
    score: float = 5.0  # Default: medium

    # Step 1: Path-based rules (first match wins, ordered by priority)
    matched = False
    for pattern, level, reason in PATH_RULES:
        if _match_path(file_path, pattern):
            reasons.append(reason)
            score = _level_to_base_score(level)
            matched = True
            break  # First match wins

    if not matched:
        reasons.append("No specific path rule matched")

    # Step 2: Content-based heuristics (boosts score)
    if content:
        for pattern, boost, reason in CONTENT_RULES:
            if __import__("re").search(pattern, content, __import__("re").MULTILINE):
                reasons.append(reason)
                score = min(10.0, score + boost)

    # Step 3: Map score to level
    level = _score_to_level(score)

    logger.info(
        "criticality_assessed",
        file_path=file_path,
        level=level.value,
        score=score,
        reasons_count=len(reasons),
    )

    return CriticalityResult(file_path=file_path, level=level, reasons=reasons, score=score)


def _level_to_base_score(level: CriticalityLevel) -> float:
    return {
        CriticalityLevel.CRITICAL: 9.0,
        CriticalityLevel.HIGH: 7.0,
        CriticalityLevel.MEDIUM: 5.0,
        CriticalityLevel.LOW: 3.0,
        CriticalityLevel.NONE: 1.0,
    }[level]


def _score_to_level(score: float) -> CriticalityLevel:
    if score >= 8.5:
        return CriticalityLevel.CRITICAL
    if score >= 6.5:
        return CriticalityLevel.HIGH
    if score >= 4.5:
        return CriticalityLevel.MEDIUM
    if score >= 2.5:
        return CriticalityLevel.LOW
    return CriticalityLevel.NONE
