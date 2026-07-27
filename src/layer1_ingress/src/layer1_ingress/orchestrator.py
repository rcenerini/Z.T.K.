"""L1 Orchestrator — Lambda handler for the entire Layer 1 pipeline.

Orchestrates all 7 L1 agents sequentially:
  L1.01 → L1.02 → L1.03 → L1.04 → L1.05 → L1.06 → L1.07

Input: SQS message with {repo_url, commit_sha, tenant_id}
Output: SQS message to L2 queue with full pipeline context
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

from shared.utils.fail_closed import fail_closed
from shared.utils.structlog_setup import bind_request_context, configure_logging, get_logger

from .criticality_tagger import CriticalityResult, assess_file
from .dedup_generator import DedupResult, generate_dedup_keys
from .language_classifier import Language, classify_file
from .pipeline_router import RouterResult, route
from .prompt_guard import GuardResult, guard_file
from .repo_ingestion import FileContext, ingest_diff
from .scope_planner import ScopePlan, plan_scope

logger = get_logger(__name__)


@dataclass
class Layer1Context:
    """Complete context produced by Layer 1 pipeline."""
    request_id: str
    tenant_id: str
    repo_url: str
    commit_sha: str
    branch: str

    # Agent outputs
    ingestion: dict[str, Any] = field(default_factory=dict)
    classification: dict[str, Any] = field(default_factory=dict)
    prompt_guard_results: list[dict[str, Any]] = field(default_factory=list)
    criticality: list[dict[str, Any]] = field(default_factory=list)
    routing: dict[str, Any] = field(default_factory=dict)
    scope: dict[str, Any] = field(default_factory=dict)
    dedup: dict[str, Any] = field(default_factory=dict)

    # Metadata
    errors: list[str] = field(default_factory=list)
    total_files: int = 0
    files_blocked: int = 0
    processing_time_ms: int = 0


@fail_closed(fallback_value={"error": "Layer 1 pipeline failed — fail-closed"})
def orchestrate_layer1(event: dict) -> dict:
    """Main Lambda handler for Layer 1 pipeline.

    Orchestrates all 7 agents in sequence. Idempotent via dedup key.
    """
    import time
    start = time.monotonic()

    # Parse input
    body = json.loads(event.get("body", "{}")) if isinstance(event.get("body"), str) else event
    repo_url = body.get("repo_url", "")
    commit_sha = body.get("commit_sha", "")
    branch = body.get("branch", "main")
    tenant_id = body.get("tenant_id", "ztk-proj")
    request_id = body.get("request_id", str(UUID(bytes=bytes(16))))

    configure_logging(agent_id="L1-orchestrator", layer="1")
    bind_request_context(request_id=request_id, tenant_id=tenant_id)

    ctx = Layer1Context(
        request_id=request_id,
        tenant_id=tenant_id,
        repo_url=repo_url,
        commit_sha=commit_sha,
        branch=branch,
    )

    # ── L1.01: Ingestion ──
    ingestion = ingest_diff(repo_url, commit_sha, branch, tenant_id)
    ctx.ingestion = {
        "files_count": len(ingestion.files),
        "total_lines_added": ingestion.total_lines_added,
        "total_lines_removed": ingestion.total_lines_removed,
        "errors": ingestion.errors,
    }
    ctx.total_files = len(ingestion.files)
    if ingestion.errors:
        ctx.errors.extend(ingestion.errors)

    # ── L1.02: Language Classification ──
    file_languages: dict[str, str] = {}
    for f in ingestion.files:
        lang = classify_file(f.file_path, content_hint=f.content[:200] if f.content else "")
        file_languages[f.file_path] = lang.value
    ctx.classification = {"languages": file_languages, "repo_languages": ingestion.repo_languages}

    # ── L1.03: Prompt-Injection Guard ──
    blocked_files: list[str] = []
    for f in ingestion.files:
        result = guard_file(f.file_path, f.content)
        ctx.prompt_guard_results.append({
            "file_path": f.file_path,
            "decision": result.decision.value,
            "blocked_patterns": result.blocked_patterns,
            "warned_patterns": result.warned_patterns,
        })
        if result.decision.value == "BLOCK":
            blocked_files.append(f.file_path)
    ctx.files_blocked = len(blocked_files)

    # ── L1.04: Criticality ──
    for f in ingestion.files:
        crit = assess_file(f.file_path, f.content)
        ctx.criticality.append({
            "file_path": f.file_path,
            "level": crit.level.value,
            "score": crit.score,
            "reasons": crit.reasons,
        })

    # ── L1.05: Routing ──
    primary_lang = max(ingestion.repo_languages, key=ingestion.repo_languages.get) if ingestion.repo_languages else None
    max_crit = max((c["score"] for c in ctx.criticality), default=5.0)
    crit_level = "critical" if max_crit >= 8.5 else "high" if max_crit >= 6.5 else "medium"
    routing = route(
        finding_id=request_id,
        language=primary_lang,
        criticality=crit_level,
        blocked_by_guard=bool(blocked_files),
    )
    ctx.routing = {
        "routes": [{"agent_id": r.agent_id, "layer": r.layer, "reason": r.reason} for r in routing.routes],
        "blocked": routing.blocked,
        "block_reason": routing.block_reason,
    }

    # ── L1.06: Scope Planning ──
    file_paths = [f.file_path for f in ingestion.files]
    file_contents = {f.file_path: f.content for f in ingestion.files}
    scope = plan_scope(request_id, file_paths, file_contents, max_crit)
    ctx.scope = {
        "files_to_analyse": len(scope.files_to_analyse),
        "files_skipped": len(scope.files_skipped),
        "total_lines": scope.total_lines,
        "budget_tokens": scope.budget.estimated_tokens,
        "budget_usd": scope.budget.estimated_cost_usd,
        "tier": scope.budget.tier,
    }

    # ── L1.07: Dedup ──
    file_hashes = [f.content_hash for f in ingestion.files if f.content_hash]
    dedup = generate_dedup_keys(
        finding_id=UUID(request_id) if len(request_id) == 36 else UUID(bytes=bytes(16)),
        file_hashes=file_hashes,
        commit_sha=commit_sha,
    )
    ctx.dedup = {
        "idempotency_key": dedup.idempotency_key,
        "file_hash": dedup.file_hash,
        "stage_keys": dedup.stage_keys,
    }

    ctx.processing_time_ms = int((time.monotonic() - start) * 1000)

    logger.info("layer1_pipeline_complete", processing_time_ms=ctx.processing_time_ms)

    return {
        "statusCode": 200,
        "body": json.dumps(_serialize_context(ctx), default=str),
    }


def _serialize_context(ctx: Layer1Context) -> dict:
    """Serialize Layer1Context to JSON-safe dict."""
    return {
        "request_id": ctx.request_id,
        "tenant_id": ctx.tenant_id,
        "repo_url": ctx.repo_url,
        "commit_sha": ctx.commit_sha,
        "ingestion": ctx.ingestion,
        "classification": ctx.classification,
        "prompt_guard": {"results": ctx.prompt_guard_results, "files_blocked": ctx.files_blocked},
        "criticality": ctx.criticality,
        "routing": ctx.routing,
        "scope": ctx.scope,
        "dedup": ctx.dedup,
        "errors": ctx.errors,
        "processing_time_ms": ctx.processing_time_ms,
    }
