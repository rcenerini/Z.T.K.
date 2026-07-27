"""L1.06 — Scope & Budget Planner Agent.

Plans the scope (which files to analyse) and budget (max tokens/cost) for a finding.
Prevents DoS and cost explosion before downstream LLM consumption.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from shared.utils.structlog_setup import get_logger

logger = get_logger(__name__)


@dataclass
class BudgetPlan:
    """Budget allocation for LLM consumption."""
    max_tokens: int = 0
    max_cost_usd: float = 0.0
    estimated_tokens: int = 0
    estimated_cost_usd: float = 0.0
    tier: str = "volume"  # volume | reasoning | generation
    warnings: list[str] = field(default_factory=list)


@dataclass
class ScopePlan:
    """Scope plan for a finding pipeline execution."""
    finding_id: str
    files_to_analyse: list[str] = field(default_factory=list)
    files_skipped: list[str] = field(default_factory=list)
    total_lines: int = 0
    total_files: int = 0
    budget: BudgetPlan = field(default_factory=BudgetPlan)
    estimated_duration_seconds: float = 0.0


# ── Token estimation constants ────────────────────────────────────

TOKENS_PER_LINE = 5  # ~5 tokens per line of code (heuristic)
COST_PER_1K_TOKENS_HAIKU = 0.00025  # $0.00025/1K input tokens
COST_PER_1K_TOKENS_SONNET = 0.003    # $0.003/1K input tokens
MAX_TOKENS_PER_FINDING = 100_000    # Hard cap per finding
MAX_COST_PER_FINDING_USD = 5.0      # Hard budget cap per finding


def plan_scope(
    finding_id: str,
    file_paths: list[str],
    file_contents: dict[str, str] | None = None,
    criticality_score: float = 5.0,
) -> ScopePlan:
    """Plan scope and budget for a finding.

    Deterministic: same inputs always produce same plan.
    """
    plan = ScopePlan(finding_id=finding_id, total_files=len(file_paths))

    # Step 1: Count total lines
    total_lines = 0
    files_to_keep: list[str] = []
    files_skipped: list[str] = []

    for fp in file_paths:
        content = (file_contents or {}).get(fp, "")
        lines = content.count("\n") + 1 if content else 100  # estimate if no content
        total_lines += lines

        # Skip files that would exceed budget
        if total_lines > MAX_TOKENS_PER_FINDING / TOKENS_PER_LINE:
            files_skipped.append(fp)
        else:
            files_to_keep.append(fp)

    plan.files_to_analyse = files_to_keep
    plan.files_skipped = files_skipped
    plan.total_lines = total_lines

    # Step 2: Estimate tokens
    est_tokens = min(
        plan.total_lines * TOKENS_PER_LINE,
        MAX_TOKENS_PER_FINDING,
    )

    # Step 3: Estimate cost (Haiku as baseline for volume tier)
    est_cost = est_tokens / 1000 * COST_PER_1K_TOKENS_HAIKU
    max_cost = min(MAX_COST_PER_FINDING_USD, est_cost * 2.0)

    # Step 4: Determine tier based on criticality
    tier = "volume"
    if criticality_score >= 7.0:
        tier = "reasoning"
        est_cost = est_tokens / 1000 * COST_PER_1K_TOKENS_SONNET
    if criticality_score >= 9.0:
        tier = "generation"

    plan.budget = BudgetPlan(
        max_tokens=MAX_TOKENS_PER_FINDING,
        max_cost_usd=max_cost,
        estimated_tokens=est_tokens,
        estimated_cost_usd=est_cost,
        tier=tier,
    )

    # Step 5: Warnings
    if files_skipped:
        plan.budget.warnings.append(f"{len(files_skipped)} files skipped (budget cap)")
    if est_tokens > 50000:
        plan.budget.warnings.append("High token estimate (>50K) — review scope")
    if total_lines > 10000:
        plan.budget.warnings.append("Large diff (>10K lines) — consider splitting")

    # Step 6: Estimate duration
    # ~100ms per file for SAST + 2s per LLM call if needed
    plan.estimated_duration_seconds = len(files_to_keep) * 0.1 + 2.0

    logger.info(
        "scope_planned",
        finding_id=finding_id,
        files_to_analyse=len(files_to_keep),
        total_lines=total_lines,
        estimated_tokens=est_tokens,
        tier=tier,
    )

    return plan
