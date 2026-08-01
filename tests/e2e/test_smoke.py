"""E2E Smoke Test — Full Pipeline: Git Repo -> Patch + Containment.

Simulates a complete finding lifecycle without AWS:
  1. Git repo with vulnerable code
  2. L1 Ingest -> Classify -> Guard -> Tagger -> Router
  3. L3 PoC validation
  4. L4 Score + Debate
  5. L5 Patch + Containment

Requires: Git CLI (available). No AWS, no Bedrock, no external APIs.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path


def test_e2e_pipeline() -> None:
    """Full E2E: SQL injection finding -> patch + containment rule."""

    # ═══════════════════════════════════════════════════════════════
    # 0. Setup: Create mock Git repo with vulnerable code
    # ═══════════════════════════════════════════════════════════════
    tmp = tempfile.mkdtemp(prefix="ztk-e2e-")
    repo = Path(tmp) / "repo"
    repo.mkdir()
    (repo / "src" / "auth").mkdir(parents=True)
    (repo / "src" / "api").mkdir(parents=True)

    vulnerable_code = '''
import sqlite3

def login(email, password):
    """Vulnerable: SQL injection via string concatenation."""
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE email = '" + email + "'"
    cursor.execute(query)
    return cursor.fetchall()
'''
    (repo / "src" / "auth" / "login.py").write_text(vulnerable_code)
    (repo / "src" / "api" / "handler.py").write_text(
        'import hashlib\n'
        'API_KEY = "sk-1234567890abcdef"\n'
        'def process(data): return hashlib.md5(data.encode()).hexdigest()\n'
    )

    subprocess.run(["git", "init", "-b", "main"], cwd=repo, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo, capture_output=True)
    subprocess.run(["git", "config", "user.name", "ZTK E2E Test"], cwd=repo, capture_output=True)
    subprocess.run(["git", "add", "-A"], cwd=repo, capture_output=True)
    subprocess.run(["git", "commit", "-m", "initial"], cwd=repo, capture_output=True)
    r = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True)
    sha = r.stdout.strip()

    finding_id = str(uuid.uuid4())
    print(f"E2E: Commit {sha[:8]}, Finding {finding_id[:8]}")
    print(f"E2E: Repo at {repo}")

    # ═══════════════════════════════════════════════════════════════
    # 1. L1 — Entrada & Triagem
    # ═══════════════════════════════════════════════════════════════
    print("\n--- L1: Entrada & Triagem ---")

    # L1.01: Ingestion
    from layer1_ingress.repo_ingestion import ingest_diff
    ingestion = ingest_diff(str(repo), sha, "main", "ztk-proj")
    print(f"  L1.01 Ingestion: {len(ingestion.files)} files")

    # L1.02: Classification
    from layer1_ingress.language_classifier import classify_file
    for f in ingestion.files:
        lang = classify_file(f.file_path, f.content[:200])
        print(f"  L1.02 {f.file_path} -> {lang.value}")

    # L1.03: Prompt Guard
    from layer1_ingress.prompt_guard import guard_file, GuardDecision
    blocked = 0
    for f in ingestion.files:
        gr = guard_file(f.file_path, f.content)
        if gr.decision == GuardDecision.BLOCK:
            blocked += 1
    print(f"  L1.03 Guard: {blocked} blocked (0 = safe)")

    # L1.04: Criticality
    from layer1_ingress.criticality_tagger import assess_file
    for f in ingestion.files:
        crit = assess_file(f.file_path, f.content)
        print(f"  L1.04 {f.file_path} -> {crit.level.value} (score={crit.score})")

    # L1.05: Router
    from layer1_ingress.pipeline_router import route
    routing = route(finding_id, language="python", criticality="high", blocked_by_guard=(blocked > 0))
    agent_list = [r.agent_id for r in routing.routes if r.layer == 2]
    print(f"  L1.05 Router: {len(agent_list)} SAST agents -> {agent_list[:3]}")

    # L1.06: Scope
    from layer1_ingress.scope_planner import plan_scope
    paths = [f.file_path for f in ingestion.files]
    contents = {f.file_path: f.content for f in ingestion.files}
    scope = plan_scope(finding_id, paths, contents, criticality_score=8.0)
    print(f"  L1.06 Scope: {scope.budget.estimated_tokens} tokens, tier={scope.budget.tier}")

    # L1.07: Dedup
    from layer1_ingress.dedup_generator import generate_dedup_keys
    hashes = [f.content_hash for f in ingestion.files if f.content_hash]
    dedup = generate_dedup_keys(uuid.UUID(finding_id), hashes, sha)
    print(f"  L1.07 Dedup: key={dedup.idempotency_key[:16]}...")

    assert len(ingestion.files) > 0, "E2E FAIL: No files ingested"
    assert blocked == 0, "E2E FAIL: Clean code blocked by prompt guard"
    assert len(agent_list) >= 2, "E2E FAIL: No SAST agents routed"
    print("  PASS L1 pipeline: PASS")

    # ═══════════════════════════════════════════════════════════════
    # 2. L3 — Validação (PoC)
    # ═══════════════════════════════════════════════════════════════
    print("\n--- L3: Validacao ---")

    from layer3_validation.poc_runner import run_poc
    poc = run_poc(finding_id, "CWE-89", ingestion.files[0].content[:500], "' OR '1'='1")
    print(f"  L3.01 PoC: exploitable={poc.exploitable}, confidence={poc.confidence}")

    from layer3_validation.score_engine import (
        ScoreInput, ExploitabilityLevel, ReachabilityLevel, BusinessImpactLevel, compute_score,
    )
    inp = ScoreInput(
        finding_id=finding_id,
        exploitability=ExploitabilityLevel.CONFIRMED if poc.exploitable else ExploitabilityLevel.UNLIKELY,
        reachability=ReachabilityLevel.REACHABLE,
        business_impact=BusinessImpactLevel.CRITICAL,
        confidence=0.9 if poc.confidence == "HIGH" else 0.5,
        has_poc_evidence=poc.exploitable,
        pci_scope=True,
    )
    score = compute_score(inp)
    print(f"  L3.02 Score: {score.composite_score}/10, floor={score.severity_floor_applied}")
    assert score.composite_score >= 7.5, "E2E FAIL: PCI floor not enforced"
    print("  PASS L3 pipeline: PASS")

    # ═══════════════════════════════════════════════════════════════
    # 3. L4 — Consenso (Debate)
    # ═══════════════════════════════════════════════════════════════
    print("\n--- L4: Consenso ---")

    from layer4_consensus.ssvc_decision import decide_ssvc, Exploitation, Exposure, MissionImpact
    ssvc = decide_ssvc(Exploitation.POC, Exposure.OPEN, MissionImpact.MISSION_FAILURE, cvss_score=score.composite_score)
    print(f"  L4.01 SSVC: tier={ssvc.tier.value}, urgency={ssvc.urgency_days}d")

    from layer4_consensus.debate_engine import run_debate
    debate = run_debate(finding_id, score.composite_score, "P1", "poc", pci_scope=True)
    print(f"  L4.02 Debate: final={debate.final_priority}, hung_jury={debate.hung_jury}")
    assert debate.final_priority in ("P0", "P1"), "E2E FAIL: PCI floor not respected by debate"
    print("  PASS L4 pipeline: PASS")

    # ═══════════════════════════════════════════════════════════════
    # 4. L5 — Remediação (Patch + Containment)
    # ═══════════════════════════════════════════════════════════════
    print("\n--- L5: Remediacao ---")

    # Track A: Patch
    from layer5_remediation.patch_generator import generate_patch, PatchStatus
    patch = generate_patch(finding_id, "CWE-89", "src/auth/login.py", ingestion.files[0].content[:500], debate.final_priority)
    print(f"  L5.A Patch: status={patch.status.value}, blocked={patch.merge_blocked}")

    # Track B: Containment
    from layer5_remediation.containment_manager import (
        create_containment_rule, run_dry_run, apply_containment, ContainmentStatus,
    )
    rule = create_containment_rule(finding_id, "CWE-89", "/api/auth/login")
    rule = run_dry_run(rule)
    rule = apply_containment(rule)
    print(f"  L5.B Containment: status={rule.status.value}, ttl={rule.ttl_hours}h")

    assert patch.status != PatchStatus.BLOCKED or debate.final_priority in ("P0", "P1"), "E2E FAIL: Patch blocked inconsistently"
    assert rule.status == ContainmentStatus.ACTIVE, "E2E FAIL: Containment not applied after dry-run"
    print("  PASS L5 pipeline: PASS")

    # ═══════════════════════════════════════════════════════════════
    # 5. Cleanup
    # ═══════════════════════════════════════════════════════════════
    shutil.rmtree(tmp, ignore_errors=True)

    print(f"\n{'='*50}")
    print(f"  E2E SMOKE TEST: PASS PASS")
    print(f"  Pipeline: L1 -> L3 -> L4 -> L5")
    print(f"  Output: Patch ({patch.status.value}) + Containment ({rule.status.value})")
    print(f"{'='*50}")


if __name__ == "__main__":
    sys.path.insert(0, "src/layer1_ingress/src")
    sys.path.insert(0, "src/layer3_validation/src")
    sys.path.insert(0, "src/layer4_consensus/src")
    sys.path.insert(0, "src/layer5_remediation/src")
    sys.path.insert(0, "src")
    test_e2e_pipeline()
