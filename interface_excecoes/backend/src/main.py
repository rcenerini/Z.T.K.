"""M9 — Interface de Excecoes: Backend API.

FastAPI REST API for:
- Exception management (CRUD + four-eyes approval)
- Kill switch status/activation
- HITL queue management
- Audit timeline
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

app = FastAPI(
    title="ZTK — Exception Dashboard API",
    version="1.0.0",
    description="API REST para gestao de excecoes, kill switch, fila HITL e auditoria do sistema Z.T.K.",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_tags=[
        {"name": "dashboard", "description": "Metricas agregadas"},
        {"name": "exceptions", "description": "Gestao de excecoes four-eyes"},
        {"name": "kill-switch", "description": "Controle de emergencia (SOC)"},
        {"name": "hitl", "description": "Fila Human-in-the-Loop"},
        {"name": "audit", "description": "Timeline de eventos"},
    ],
)

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ── In-memory stores (production: DynamoDB) ───────────────────────
_exceptions: dict[str, dict] = {}
_hitl_items: dict[str, dict] = {}
_kill_switch_status: dict = {"active": False, "scope": "none", "activated_by": "", "activated_at": None, "reason": ""}
_audit_log: list[dict] = []


# ── Pydantic Models ────────────────────────────────────────────────

class ExceptionCreate(BaseModel):
    finding_id: str = Field(min_length=1)
    tenant_id: str = "ztk-proj"
    requested_by: str = Field(min_length=1)
    category: str = Field(pattern="^(FALSE_POSITIVE|RISK_ACCEPTED|COMPENSATING_CONTROL|DEFERRED_FIX)$")
    justification: str = Field(min_length=50)
    current_severity: str = Field(pattern="^P[0-4]$")
    requested_severity: str = Field(pattern="^P[0-4]$")
    ttl_days: int = Field(ge=1, le=365)


class ApprovalRequest(BaseModel):
    exception_id: str
    approver_email: str
    approver_role: str


class KillSwitchRequest(BaseModel):
    scope: str = Field(pattern="^(full|patch_only|containment_only)$")
    reason: str = Field(min_length=20)
    operator: str = Field(min_length=1)


class HITLCreate(BaseModel):
    finding_id: str
    title: str = Field(min_length=5)
    description: str = Field(min_length=20)
    priority: str = Field(pattern="^(CRITICAL|HIGH|MEDIUM|LOW)$")


# ── API Endpoints ──────────────────────────────────────────────────

@app.get("/api/health", tags=["dashboard"])
def health() -> dict:
    return {"status": "ok", "service": "exception-dashboard", "version": "1.0.0"}


# ── Exceptions ─────────────────────────────────────────────────────

@app.get("/api/exceptions", tags=["exceptions"])
def list_exceptions(status: Optional[str] = None) -> dict:
    items = list(_exceptions.values())
    if status:
        items = [e for e in items if e.get("status") == status]
    return {"total": len(items), "exceptions": sorted(items, key=lambda e: e.get("created_at", ""), reverse=True)}


@app.post("/api/exceptions", tags=["exceptions"])
def create_exception(req: ExceptionCreate) -> dict:
    exc_id = str(uuid.uuid4())[:12]
    now = datetime.now(timezone.utc).isoformat()
    exc = {
        "exception_id": exc_id, "status": "REQUESTED",
        "approved_by": [], "rejection_reason": "",
        "created_at": now, **req.model_dump(),
    }
    _exceptions[exc_id] = exc
    _audit_log.append({"event": "exception_created", "exception_id": exc_id, "timestamp": now})
    return exc


@app.post("/api/exceptions/{exc_id}/approve", tags=["exceptions"])
def approve_exception(exc_id: str, req: ApprovalRequest) -> dict:
    if exc_id not in _exceptions:
        raise HTTPException(404, "Exception not found")
    exc = _exceptions[exc_id]
    if req.approver_email in exc["approved_by"]:
        raise HTTPException(400, "Approver already approved")
    exc["approved_by"].append(req.approver_email)
    if len(exc["approved_by"]) >= 2 and len(set(exc["approved_by"])) >= 2:
        exc["status"] = "APPROVED"
    if req.approver_role == "CISO":
        exc["status"] = "APPROVED"  # CISO override
    _audit_log.append({"event": "exception_approved", "exception_id": exc_id, "by": req.approver_email,
                        "timestamp": datetime.now(timezone.utc).isoformat()})
    return exc


@app.post("/api/exceptions/{exc_id}/reject")
def reject_exception(exc_id: str, reason: str = Query(min_length=10)) -> dict:
    if exc_id not in _exceptions:
        raise HTTPException(404, "Exception not found")
    _exceptions[exc_id]["status"] = "REJECTED"
    _exceptions[exc_id]["rejection_reason"] = reason
    return _exceptions[exc_id]


@app.post("/api/exceptions/{exc_id}/apply")
def apply_exception(exc_id: str) -> dict:
    if exc_id not in _exceptions:
        raise HTTPException(404, "Exception not found")
    exc = _exceptions[exc_id]
    if exc["status"] != "APPROVED":
        raise HTTPException(400, f"Cannot apply exception in status: {exc['status']}")
    exc["status"] = "ACTIVE"
    return exc


# ── Kill Switch ────────────────────────────────────────────────────

@app.get("/api/kill-switch")
def get_kill_switch() -> dict:
    return _kill_switch_status


@app.post("/api/kill-switch")
def activate_kill_switch(req: KillSwitchRequest) -> dict:
    if req.operator != "SOC":
        raise HTTPException(403, "Only SOC can activate kill switch")
    _kill_switch_status.update({
        "active": True, "scope": req.scope, "activated_by": req.operator,
        "activated_at": datetime.now(timezone.utc).isoformat(), "reason": req.reason,
    })
    _audit_log.append({"event": "kill_switch_activated", "scope": req.scope, "by": req.operator,
                        "timestamp": datetime.now(timezone.utc).isoformat()})
    return _kill_switch_status


@app.delete("/api/kill-switch")
def deactivate_kill_switch(operator: str = Query(min_length=1)) -> dict:
    if operator != "SOC":
        raise HTTPException(403, "Only SOC can deactivate kill switch")
    _kill_switch_status.update({"active": False, "scope": "none", "activated_by": "", "reason": ""})
    return _kill_switch_status


# ── HITL Queue ─────────────────────────────────────────────────────

@app.get("/api/hitl")
def list_hitl(status: Optional[str] = None) -> dict:
    items = list(_hitl_items.values())
    if status:
        items = [i for i in items if i.get("status") == status]
    return {"total": len(items), "items": sorted(items, key=lambda i: i.get("created_at", ""), reverse=True)}


@app.post("/api/hitl")
def create_hitl(req: HITLCreate) -> dict:
    item_id = str(uuid.uuid4())[:12]
    item = {"item_id": item_id, "status": "PENDING", "assigned_to": "",
            "created_at": datetime.now(timezone.utc).isoformat(), **req.model_dump()}
    _hitl_items[item_id] = item
    return item


@app.post("/api/hitl/{item_id}/resolve")
def resolve_hitl(item_id: str, resolution: str = Query(min_length=10)) -> dict:
    if item_id not in _hitl_items:
        raise HTTPException(404, "HITL item not found")
    _hitl_items[item_id]["status"] = "RESOLVED"
    _hitl_items[item_id]["resolution"] = resolution
    _hitl_items[item_id]["resolved_at"] = datetime.now(timezone.utc).isoformat()
    return _hitl_items[item_id]


# ── Audit ──────────────────────────────────────────────────────────

@app.get("/api/audit")
def get_audit_timeline(limit: int = Query(default=50, le=200)) -> dict:
    return {"total": len(_audit_log), "events": list(reversed(_audit_log))[:limit]}


# ── Dashboard Summary ──────────────────────────────────────────────

@app.get("/api/dashboard/summary", tags=["dashboard"])
def dashboard_summary() -> dict:
    return {
        "exceptions": {
            "total": len(_exceptions),
            "active": sum(1 for e in _exceptions.values() if e["status"] == "ACTIVE"),
            "pending": sum(1 for e in _exceptions.values() if e["status"] in ("REQUESTED",)),
            "approved": sum(1 for e in _exceptions.values() if e["status"] == "APPROVED"),
        },
        "hitl": {
            "total": len(_hitl_items),
            "pending": sum(1 for i in _hitl_items.values() if i["status"] == "PENDING"),
            "resolved": sum(1 for i in _hitl_items.values() if i["status"] == "RESOLVED"),
        },
        "kill_switch": _kill_switch_status,
    }


# ── Admin: Project Scores ──────────────────────────────────────────

_project_scores: dict = {}
_project_blocks: dict = {}
_agent_metrics: dict = {
    "L1.01": {"status": "healthy", "throughput": 120, "errors_24h": 0, "avg_ms": 320},
    "L1.02": {"status": "healthy", "throughput": 120, "errors_24h": 0, "avg_ms": 5},
    "L1.03": {"status": "healthy", "throughput": 120, "errors_24h": 0, "avg_ms": 2},
    "L2.01-bandit": {"status": "healthy", "throughput": 85, "errors_24h": 1, "avg_ms": 820},
    "L2.02-semgrep": {"status": "healthy", "throughput": 85, "errors_24h": 0, "avg_ms": 600},
    "L3.01-sandbox": {"status": "healthy", "throughput": 40, "errors_24h": 2, "avg_ms": 890},
    "L4.01-debate": {"status": "healthy", "throughput": 35, "errors_24h": 0, "avg_ms": 180},
    "L5.A-patch": {"status": "healthy", "throughput": 30, "errors_24h": 1, "avg_ms": 260},
    "L5.B-containment": {"status": "healthy", "throughput": 30, "errors_24h": 0, "avg_ms": 320},
    "L6-policy": {"status": "healthy", "throughput": 200, "errors_24h": 0, "avg_ms": 1},
    "L7-router": {"status": "healthy", "throughput": 150, "errors_24h": 0, "avg_ms": 2},
    "L8-scale": {"status": "healthy", "throughput": 200, "errors_24h": 0, "avg_ms": 1},
}


@app.get("/api/admin/projects", tags=["admin"])
def get_projects() -> dict:
    """List all projects with compliance scores."""
    projects = [
        {"id": "proj-api-gateway", "name": "API Gateway", "score": 92, "compliance": "HIGH",
         "findings_open": 3, "findings_blocked": 0, "last_scan": "2026-07-27T14:30:00Z",
         "cwes_found": ["CWE-89", "CWE-327"], "failing_checks": []},
        {"id": "proj-payment-svc", "name": "Payment Service", "score": 78, "compliance": "MEDIUM",
         "findings_open": 12, "findings_blocked": 2, "last_scan": "2026-07-27T12:15:00Z",
         "cwes_found": ["CWE-89", "CWE-798", "CWE-327", "CWE-200"],
         "failing_checks": ["auth/login.py: CWE-89 SQL Injection", "config/secrets.py: CWE-798 Hardcoded Key"]},
        {"id": "proj-auth-module", "name": "Auth Module", "score": 45, "compliance": "LOW",
         "findings_open": 28, "findings_blocked": 5, "last_scan": "2026-07-27T10:00:00Z",
         "cwes_found": ["CWE-287", "CWE-306", "CWE-307", "CWE-522", "CWE-798"],
         "failing_checks": ["login/handler.go: CWE-287 Auth Bypass", "auth/token.go: CWE-522 Weak Hash",
                            "middleware/auth.go: CWE-306 Missing Check", "config/secrets.yml: CWE-798 Hardcoded"]},
        {"id": "proj-frontend", "name": "Frontend App", "score": 85, "compliance": "HIGH",
         "findings_open": 5, "findings_blocked": 1, "last_scan": "2026-07-27T11:45:00Z",
         "cwes_found": ["CWE-79", "CWE-352"],
         "failing_checks": ["components/Form.tsx: CWE-79 XSS"]},
    ]
    return {"total": len(projects), "projects": projects}


@app.get("/api/admin/metrics", tags=["admin"])
def get_agent_metrics() -> dict:
    """Agent health and throughput metrics."""
    return {"agents": _agent_metrics, "total_agents": len(_agent_metrics)}


@app.get("/api/admin/blocks", tags=["admin"])
def get_blocks() -> dict:
    """What is being blocked and why."""
    blocks = [
        {"id": "B-001", "project": "Payment Service", "target": "config/secrets.py",
         "cwe": "CWE-798", "reason": "Hardcoded credentials — must use Secrets Manager",
         "status": "BLOCKED", "since": "2026-07-26T08:00:00Z", "owner": "eng-payments"},
        {"id": "B-002", "project": "Payment Service", "target": "auth/login.py",
         "cwe": "CWE-89", "reason": "P1 requires human approval before merge",
         "status": "BLOCKED", "since": "2026-07-27T09:30:00Z", "owner": "eng-payments"},
        {"id": "B-003", "project": "Auth Module", "target": "login/handler.go",
         "cwe": "CWE-287", "reason": "P0 — auto-merge denied, CAB approval required",
         "status": "BLOCKED", "since": "2026-07-25T14:00:00Z", "owner": "eng-auth"},
        {"id": "B-004", "project": "Auth Module", "target": "auth/token.go",
         "cwe": "CWE-522", "reason": "Weak credential storage — needs bcrypt migration",
         "status": "IN_REMEDIATION", "since": "2026-07-26T11:00:00Z", "owner": "eng-auth"},
        {"id": "B-005", "project": "Frontend App", "target": "components/Form.tsx",
         "cwe": "CWE-79", "reason": "XSS via user input in form component",
         "status": "IN_REMEDIATION", "since": "2026-07-27T07:00:00Z", "owner": "eng-frontend"},
    ]
    return {"total": len(blocks), "blocks": blocks}


@app.get("/api/admin/compliance", tags=["admin"])
def get_compliance_overview() -> dict:
    """Compliance status overview."""
    return {
        "pci_dss": {"coverage": 45, "controls_mapped": 38, "controls_implemented": 17, "target": "90% pos-deploy IaC"},
        "lgpd": {"coverage": 84, "items_conforme": 16, "items_pendentes": 3, "pendentes": ["DPO externo", "Comunicacao titular", "Fiscalizacao"]},
        "iso_27001": {"status": "alinhado", "threat_model": "completo", "revisao": "anual"},
        "cis_benchmarks": {"vllm": "CIS Level 1", "aurora": "CIS PostgreSQL", "containers": "distroless + readonly"},
        "opa_policies": {"total": 3, "passing": 30, "deny_by_default": True},
    }


@app.get("/api/admin/throughput", tags=["admin"])
def get_throughput() -> dict:
    """Pipeline throughput by hour (last 24h)."""
    return {
        "hours": [
            {"hour": "08h", "findings": 45, "patched": 12, "blocked": 3},
            {"hour": "09h", "findings": 68, "patched": 22, "blocked": 5},
            {"hour": "10h", "findings": 72, "patched": 28, "blocked": 4},
            {"hour": "11h", "findings": 55, "patched": 18, "blocked": 2},
            {"hour": "12h", "findings": 48, "patched": 15, "blocked": 3},
            {"hour": "13h", "findings": 62, "patched": 20, "blocked": 6},
            {"hour": "14h", "findings": 70, "patched": 25, "blocked": 4},
            {"hour": "15h", "findings": 58, "patched": 19, "blocked": 3},
        ],
        "total_24h": {"findings": 478, "patched": 159, "blocked": 30},
    }
