"""Batch Performance Test — 1000 findings stress test.

Simulates pipeline throughput for N findings through the deterministic
layers (L1 classification + guard + criticality + routing + dedup).
No AWS, no external APIs — pure Python performance.

Measures: throughput, latency (p50/p95/p99), memory usage.
"""

from __future__ import annotations

import json
import os
import sys
import time
import uuid
from pathlib import Path

# Add source paths
sys.path.insert(0, "src/layer1_ingress/src")
sys.path.insert(0, "src/layer3_validation/src")
sys.path.insert(0, "src/layer4_consensus/src")
sys.path.insert(0, "src/layer5_remediation/src")
sys.path.insert(0, "src/layer6_governance/src")
sys.path.insert(0, "src/layer7_model_ensemble/src")
sys.path.insert(0, "src/layer8_scale/src")
sys.path.insert(0, "src")

from layer1_ingress.language_classifier import classify_file
from layer1_ingress.prompt_guard import guard_file
from layer1_ingress.criticality_tagger import assess_file
from layer1_ingress.pipeline_router import route
from layer1_ingress.scope_planner import plan_scope
from layer1_ingress.dedup_generator import generate_dedup_keys
from layer3_validation.score_engine import (
    ScoreInput, ExploitabilityLevel, ReachabilityLevel,
    BusinessImpactLevel, compute_score,
)
from layer6_governance.policy_engine import _embedded_evaluate
from layer6_governance.audit_collector import collect_event
from shared.schemas.audit_event import AuditEvent, AuditAction, AuditStage


# Sample findings simulating real-world scenarios
SAMPLE_FILES = [
    ("src/auth/login.py", "SELECT * FROM users WHERE email = '{}' AND password = '{}'".format("test", "pass")),
    ("src/api/handler.py", "def process(data): return eval(data)"),
    ("src/payment/processor.py", "API_KEY = 'sk-live-1234567890abcdef'"),
    ("src/utils/crypto.py", "import hashlib\ndef hash(p): return hashlib.md5(p).hexdigest()"),
    ("tests/test_auth.py", "def test_login(): assert login('admin', 'admin')"),
    ("src/config/settings.py", "DATABASE_URL = 'postgresql://user:pass@localhost/db'"),
    ("src/email/sender.py", 'msg = "<html>" + user_input + "</html>"'),
    ("README.md", "# Project Documentation\nSetup: pip install -r requirements.txt"),
    ("src/data/models.py", "import pickle\ndef load(data): return pickle.loads(data)"),
    ("src/network/client.py", "import requests\nrequests.get('http://api.internal/data', verify=False)"),
]


def run_batch(count: int = 1000) -> dict:
    """Run batch performance test."""
    print(f"Batch Performance Test — {count} findings")
    print("=" * 60)

    times: list[float] = []
    find_id = uuid.uuid4()
    total_classified = 0
    total_blocked = 0
    total_warned = 0
    total_audit_events = 0

    for i in range(count):
        file_path, content = SAMPLE_FILES[i % len(SAMPLE_FILES)]
        fid = str(uuid.uuid4())

        start = time.perf_counter()

        # L1.02: Classification
        lang = classify_file(file_path, content[:200])
        total_classified += 1

        # L1.03: Prompt Guard
        gr = guard_file(file_path, content)
        if gr.decision.value == "BLOCK":
            total_blocked += 1
        elif gr.decision.value == "WARN":
            total_warned += 1

        # L1.04: Criticality
        crit = assess_file(file_path, content)

        # L1.05: Router
        routing = route(fid, language=lang.value, criticality=crit.level.value.lower())

        # L1.07: Dedup (lightweight)
        dedup = generate_dedup_keys(uuid.UUID(fid), [f"hash_{i}"], "sha_test")

        # L3: Score (lightweight calc)
        score_in = ScoreInput(
            finding_id=fid,
            exploitability=ExploitabilityLevel.POSSIBLE,
            reachability=ReachabilityLevel.CONDITIONALLY_REACHABLE,
            business_impact=BusinessImpactLevel(crit.level.value),
            confidence=0.7,
        )
        score = compute_score(score_in)

        # L6: Policy check
        policy = _embedded_evaluate("read_finding", {"finding_id": fid}, "deny_by_default")

        # L6: Audit event
        payload = {"stage": "benchmark", "finding_id": fid}
        ph = AuditEvent.compute_payload_hash(payload)
        eid = AuditEvent.compute_event_id(uuid.UUID(fid), "BENCHMARK", ph)
        event = AuditEvent(
            event_id=eid, finding_id=uuid.UUID(fid), stage=AuditStage.SYSTEM,
            action=AuditAction.VALIDATED, agent_id="batch-test", tenant_id="ztk-proj",
            payload=payload, payload_hash=ph,
        )
        collect_event(event)
        total_audit_events += 1

        elapsed = (time.perf_counter() - start) * 1000  # ms
        times.append(elapsed)

        if (i + 1) % 200 == 0:
            print(f"  Processed {i + 1}/{count}...")

    # Statistics
    times.sort()
    total_ms = sum(times)
    avg = total_ms / len(times)
    p50 = times[len(times) // 2]
    p95 = times[int(len(times) * 0.95)]
    p99 = times[int(len(times) * 0.99)]

    throughput = count / (total_ms / 1000)

    results = {
        "count": count,
        "total_ms": round(total_ms, 1),
        "avg_ms": round(avg, 2),
        "p50_ms": round(p50, 2),
        "p95_ms": round(p95, 2),
        "p99_ms": round(p99, 2),
        "min_ms": round(times[0], 2),
        "max_ms": round(times[-1], 2),
        "throughput_per_sec": round(throughput, 1),
        "classified": total_classified,
        "blocked": total_blocked,
        "warned": total_warned,
        "audit_events": total_audit_events,
    }

    return results


if __name__ == "__main__":
    # Support env var override
    n = int(os.environ.get("BATCH_COUNT", "1000"))
    results = run_batch(n)

    print(f"\n{'='*60}")
    print("RESULTS")
    print(f"{'='*60}")
    print(f"  Count:           {results['count']}")
    print(f"  Total time:      {results['total_ms']} ms ({results['total_ms']/1000:.1f}s)")
    print(f"  Throughput:      {results['throughput_per_sec']} findings/sec")
    print(f"  Avg latency:     {results['avg_ms']} ms")
    print(f"  P50 latency:     {results['p50_ms']} ms")
    print(f"  P95 latency:     {results['p95_ms']} ms")
    print(f"  P99 latency:     {results['p99_ms']} ms")
    print(f"  Min/Max:         {results['min_ms']}/{results['max_ms']} ms")
    print(f"  Classified:      {results['classified']}")
    print(f"  Blocked:         {results['blocked']}")
    print(f"  Warned:          {results['warned']}")
    print(f"  Audit events:    {results['audit_events']}")
    print(f"{'='*60}")

    # Write results to JSON for CI
    output = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        **results,
    }
    Path("reports").mkdir(exist_ok=True)
    Path("reports/benchmark.json").write_text(json.dumps(output, indent=2))
    print(f"\nResults saved to reports/benchmark.json")
