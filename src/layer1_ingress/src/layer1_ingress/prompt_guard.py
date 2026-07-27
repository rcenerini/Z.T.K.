"""L1.03 — Prompt-Injection Guard Agent.

Two-layer defense:
1. Regex patterns (deterministic, blocking)
2. Content envelopment (wrapping in delimiters)

Follows ADR-003 strategy. 100% deterministic — no LLM.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum

from shared.utils.fail_closed import fail_closed
from shared.utils.structlog_setup import get_logger

logger = get_logger(__name__)


class GuardDecision(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    WARN = "WARN"


@dataclass
class GuardResult:
    """Result of prompt-injection guard analysis."""
    decision: GuardDecision
    blocked_patterns: list[str] = field(default_factory=list)
    warned_patterns: list[str] = field(default_factory=list)
    sanitized_content: str = ""
    enveloped_content: str = ""


# ── Regex Patterns (ADR-003, Camada 1) ────────────────────────────

# BLOCK: patterns that indicate a clear injection attempt
BLOCK_PATTERNS: list[tuple[str, str]] = [
    # Direct system prompt override
    (r"(?i)ignore\s+.*\binstructions?\b", "prompt_override_ignore"),
    (r"(?i)(you\s+are\s+(now|no\s+longer)\s+.*)(security\s+(analyst|copilot))", "role_redefinition"),
    (r"(?i)forget\s+(your|all)\s+(training|instructions|rules|system\s+prompt)", "training_override"),
    (r"(?i)system\s*prompt\s*[:=]\s*", "system_prompt_injection"),
    (r"(?i)you\s+must\s+(always\s+)?respond\s+with\s+['\"]", "forced_output_pattern"),

    # DAN / jailbreak patterns
    (r"(?i)\bDAN\b.*\b(do\s+anything|no\s+restrictions|ignore\s+limits)\b", "dan_jailbreak"),
    (r"(?i)pretend\s+(you\s+are|to\s+be)\s+(not?\s+an?\s+)?ai", "pretend_jailbreak"),

    # Output manipulation
    (r"(?i)output\s+(only|exactly|just)\s+['\"](safe|clean|no\s+issue|no\s+vuln)", "output_manipulation"),
    (r"(?i)(always|never)\s+(say|claim|report)\s+(this\s+is|it\s+is)\s+(safe|secure|clean)", "claim_manipulation"),

    # Severity manipulation
    (r"(?i)severity\s*(must|should|has\s+to)\s*(be|stay)\s*(low|p4|p3|informational)", "severity_override"),
    (r"(?i)this\s+(code|finding|vuln)\s+is\s+(definitely|absolutely|100%)\s+(safe|harmless|benign)", "certainty_claim"),
]

# WARN: patterns that are suspicious but could be legitimate code
WARN_PATTERNS: list[tuple[str, str]] = [
    (r"(?i)\bplease\s+(ignore|skip|bypass)\b", "suspicious_please"),
    (r"(?i)\bthis\s+is\s+(not|never)\s+a\s+(vuln|bug|issue)\b", "suspicious_denial"),
    (r"(?i)\bno\s+need\s+to\s+(check|scan|analyse|review)\b", "suspicious_skip"),
    (r"(?i)\bhidden\s+(instruction|message|prompt)\b", "hidden_instruction"),
]

# Compile regex patterns once
_block_regexes: list[tuple[re.Pattern, str]] = [
    (re.compile(p, re.MULTILINE | re.DOTALL), name) for p, name in BLOCK_PATTERNS
]
_warn_regexes: list[tuple[re.Pattern, str]] = [
    (re.compile(p, re.MULTILINE | re.DOTALL), name) for p, name in WARN_PATTERNS
]

# Unicode normalisation table (homoglyph detection)
HOMOGLYPH_MAP: dict[int, int] = {
    0x0430: 0x0061,  # Cyrillic 'a' → Latin 'a'
    0x0435: 0x0065,  # Cyrillic 'e' → Latin 'e'
    0x043E: 0x006F,  # Cyrillic 'o' → Latin 'o'
    0x0440: 0x0070,  # Cyrillic 'r' → Latin 'p'
    0x0441: 0x0063,  # Cyrillic 's' → Latin 'c'
    0x0455: 0x0073,  # Cyrillic 's' → Latin 's'
    0x04BB: 0x0068,  # Cyrillic 'h' → Latin 'h'
    0x0391: 0x0041,  # Greek 'A' → Latin 'A'
    0x0395: 0x0045,  # Greek 'E' → Latin 'E'
    0x039D: 0x0048,  # Greek 'N' → Latin 'H'
    0x039F: 0x004F,  # Greek 'O' → Latin 'O'
    0x03A1: 0x0050,  # Greek 'P' → Latin 'P'
    0x03A5: 0x0059,  # Greek 'Y' → Latin 'Y'
    0x03A7: 0x0058,  # Greek 'X' → Latin 'X'
}


def scan_content(content: str) -> GuardResult:
    """Scan content for prompt injection patterns.

    Deterministic: same input always produces same result.
    Performs Unicode normalisation before scanning (homoglyph detection).
    """
    # Step 1: Unicode normalisation (NFKC — compatibility decomposition)
    import unicodedata
    normalized = unicodedata.normalize("NFKC", content)

    # Step 2: Homoglyph normalisation
    normalized = normalized.translate(HOMOGLYPH_MAP)

    result = GuardResult(decision=GuardDecision.ALLOW, sanitized_content=content)

    # Step 3: Check BLOCK patterns
    for regex, name in _block_regexes:
        if regex.search(normalized):
            result.blocked_patterns.append(name)

    # Step 4: Check WARN patterns
    for regex, name in _warn_regexes:
        if regex.search(normalized):
            result.warned_patterns.append(name)

    # Step 5: Decision
    if result.blocked_patterns:
        result.decision = GuardDecision.BLOCK
        result.sanitized_content = _sanitize_content(content, result.blocked_patterns)
    elif result.warned_patterns:
        result.decision = GuardDecision.WARN

    # Step 6: Envelopment (always applied — ADR-003 Camada 2)
    result.enveloped_content = _envelop_content(
        result.sanitized_content, result.decision
    )

    logger.info(
        "prompt_guard_scan_complete",
        decision=result.decision.value,
        blocked_count=len(result.blocked_patterns),
        warned_count=len(result.warned_patterns),
    )

    return result


def _sanitize_content(content: str, blocked_patterns: list[str]) -> str:
    """Redact blocked content sections. Content is preserved but marked."""
    sanitized = content
    for pattern_name in blocked_patterns:
        for pattern_str, name in BLOCK_PATTERNS:
            if name == pattern_name:
                sanitized = re.sub(
                    pattern_str,
                    f"[CONTENT REDACTED — {pattern_name}]",
                    sanitized,
                    flags=re.MULTILINE | re.DOTALL | re.IGNORECASE,
                )
    return sanitized


def _envelop_content(content: str, decision: GuardDecision) -> str:
    """Wrap content in trust delimiters (ADR-003 Camada 2)."""
    trust_level = "BLOCKED" if decision == GuardDecision.BLOCK else "UNVERIFIED"
    return (
        f"--- BEGIN USER CODE (TRUST: {trust_level}) ---\n"
        f"{content}\n"
        f"--- END USER CODE ---"
    )


@fail_closed(fallback_value=GuardResult(decision=GuardDecision.BLOCK, blocked_patterns=["fail_closed"]))
def guard_file(file_path: str, content: str) -> GuardResult:
    """Guard a single file against prompt injection."""
    return scan_content(content)
