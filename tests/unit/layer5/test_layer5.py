"""Tests for Layer 5 — Remediation.

Covers: Patch Generator (Trilha A), Containment Manager (Trilha B),
Orchestrator.
"""

from __future__ import annotations

import pytest

from layer5_remediation.patch_generator import (
    PatchStatus,
    PatchResult,
    generate_patch,
    validate_patch,
    regression_check,
    publish_pr,
    get_available_templates,
    PATCH_TEMPLATES,
)
from layer5_remediation.containment_manager import (
    ContainmentType,
    ContainmentStatus,
    ContainmentRule,
    create_containment_rule,
    run_dry_run,
    apply_containment,
    rollback_containment,
    is_expired,
    remaining_hours,
    CONTAINMENT_TEMPLATES,
)


# ═══════════════════════════════════════════════════════════════════
# Patch Generator — Trilha A
# ═══════════════════════════════════════════════════════════════════

class TestPatchGenerator:
    def test_generate_sqli_patch(self) -> None:
        result = generate_patch("f1", "CWE-89", "src/auth/login.py",
                                 'cursor.execute(f"SELECT * FROM users")', "P2")
        assert result.cwe_id == "CWE-89"
        assert "parameterized" in result.patched_code.lower()
        assert result.status == PatchStatus.GENERATED

    def test_generate_xss_patch(self) -> None:
        result = generate_patch("f2", "CWE-79", "src/app.py",
                                 'html += user_input', "P1")
        assert "encoding" in result.patched_code.lower() or "escape" in result.patched_code.lower()

    def test_generate_cmdi_patch(self) -> None:
        result = generate_patch("f3", "CWE-78", "src/util.py",
                                 'os.system("echo " + x)', "P3")
        assert result.cwe_id == "CWE-78"

    def test_p0_merge_blocked(self) -> None:
        result = generate_patch("f4", "CWE-89", "file.py", "code", "P0")
        assert result.merge_blocked is True
        assert "P0" in result.block_reason

    def test_p1_merge_blocked(self) -> None:
        result = generate_patch("f5", "CWE-89", "file.py", "code", "P1")
        assert result.merge_blocked is True
        assert "P1" in result.block_reason

    def test_p2_not_blocked(self) -> None:
        result = generate_patch("f6", "CWE-89", "file.py", "code", "P2")
        assert result.merge_blocked is False

    def test_p4_not_blocked(self) -> None:
        result = generate_patch("f7", "CWE-89", "file.py", "code", "P4")
        assert result.merge_blocked is False

    def test_validate_patch(self) -> None:
        patch = generate_patch("f8", "CWE-89", "file.py", "code", "P2")
        result = validate_patch(patch)
        assert result.sandbox_passed is True
        assert result.status == PatchStatus.VALIDATED

    def test_regression_check(self) -> None:
        patch = generate_patch("f9", "CWE-89", "file.py", "code", "P2")
        patch = validate_patch(patch)
        result = regression_check(patch)
        assert result.regression_passed is True

    def test_publish_pr(self) -> None:
        patch = generate_patch("f10", "CWE-89", "file.py", "code", "P2")
        patch = validate_patch(patch)
        patch = regression_check(patch)
        result = publish_pr(patch, "org/repo")
        assert result.pr_url != ""
        assert "pull" in result.pr_url

    def test_publish_pr_blocked_for_p0(self) -> None:
        patch = generate_patch("f11", "CWE-89", "file.py", "code", "P0")
        result = publish_pr(patch)
        assert result.merge_blocked is True

    def test_unknown_cwe_has_generic_template(self) -> None:
        result = generate_patch("f12", "CWE-9999", "file.py", "code", "P3")
        assert result.patch_id is not None
        assert "TODO" in result.patched_code or "no template" in result.patched_code.lower() or "requires LLM" in result.patched_code

    def test_templates_cover_top_cwes(self) -> None:
        templates = get_available_templates()
        assert "CWE-89" in templates
        assert "CWE-79" in templates
        assert "CWE-78" in templates
        assert len(templates) >= 5


# ═══════════════════════════════════════════════════════════════════
# Containment Manager — Trilha B
# ═══════════════════════════════════════════════════════════════════

class TestContainmentManager:
    def test_create_sqli_containment(self) -> None:
        rule = create_containment_rule("f1", "CWE-89", "/api/auth/login")
        assert rule.cwe_id == "CWE-89"
        assert rule.rule_type == ContainmentType.WAF_RULE
        assert rule.ttl_hours == 72
        assert rule.expires_at is not None

    def test_dry_run_passes(self) -> None:
        rule = create_containment_rule("f2", "CWE-79")
        rule = run_dry_run(rule)
        assert rule.status == ContainmentStatus.DRY_RUN_PASSED
        assert rule.dry_run is not None
        assert rule.dry_run.passed is True

    def test_apply_after_dry_run(self) -> None:
        rule = create_containment_rule("f3", "CWE-78")
        rule = run_dry_run(rule)
        rule = apply_containment(rule)
        assert rule.status == ContainmentStatus.ACTIVE
        assert rule.applied_at is not None

    def test_apply_without_dry_run_fails(self) -> None:
        rule = create_containment_rule("f4", "CWE-89")
        # Status is still DRAFT — apply should skip
        rule = apply_containment(rule)
        assert rule.status != ContainmentStatus.ACTIVE

    def test_rollback(self) -> None:
        rule = create_containment_rule("f5", "CWE-79")
        rule = run_dry_run(rule)
        rule = apply_containment(rule)
        rule = rollback_containment(rule)
        assert rule.status == ContainmentStatus.ROLLED_BACK

    def test_is_expired_false_for_new_rule(self) -> None:
        rule = create_containment_rule("f6", "CWE-89")
        assert is_expired(rule) is False

    def test_remaining_hours_positive(self) -> None:
        rule = create_containment_rule("f7", "CWE-89")
        hours = remaining_hours(rule)
        assert hours > 0

    def test_unknown_cwe_fallback(self) -> None:
        rule = create_containment_rule("f8", "CWE-9999")
        assert rule.rule_type is not None
        assert rule.ttl_hours == 72

    def test_containment_templates_cover_top_cwes(self) -> None:
        assert "CWE-89" in CONTAINMENT_TEMPLATES
        assert "CWE-79" in CONTAINMENT_TEMPLATES
        assert "CWE-78" in CONTAINMENT_TEMPLATES
