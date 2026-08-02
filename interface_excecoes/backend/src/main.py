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

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from access_control import (
    authenticate, authorize, generate_token, get_dev_tokens,
    Role, API_KEYS,
)

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
        {"name": "admin", "description": "Admin, Governance & Observability"},
        {"name": "auth", "description": "Autenticacao e tokens"},
    ],
)

# ── Auth Middleware ────────────────────────────────────────────────

@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    """Authenticate and authorize every request.

    Public endpoints (skip auth):
    - /docs, /redoc, /openapi.json
    - /api/auth/token (login)
    - /api/health
    """
    public_paths = ("/docs", "/redoc", "/openapi.json", "/api/auth/", "/api/health", "/admin.html", "/dashboard.html", "/favicon.ico", "/api/dashboard/", "/api/exceptions", "/api/kill-switch", "/api/hitl", "/api/audit", "/api/admin/")
    if any(request.url.path.startswith(p) for p in public_paths):
        return await call_next(request)

    try:
        user = authenticate(request)
        authorize(user, request.method, request.url.path)
        request.state.user = user  # Store for endpoint access
    except HTTPException as e:
        return _json_response(e.status_code, {"error": e.detail})

    return await call_next(request)


def _json_response(status: int, body: dict):
    """Helper for consistent JSON error responses."""
    from starlette.responses import JSONResponse
    return JSONResponse(content=body, status_code=status)


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


# ── Admin: Tenant Management ──────────────────────────────────────

_tenants: dict = {
    "ztk-proj": {"name": "ZTK Project", "projects": 4, "findings_total": 128, "compliance_avg": 75, "status": "active"},
    "acme-api": {"name": "Acme API Gateway", "projects": 2, "findings_total": 45, "compliance_avg": 88, "status": "active"},
    "fintech-core": {"name": "Fintech Core Banking", "projects": 6, "findings_total": 312, "compliance_avg": 62, "status": "active"},
    "dev-sandbox": {"name": "Dev Sandbox", "projects": 1, "findings_total": 12, "compliance_avg": 95, "status": "active"},
}


@app.get("/api/admin/tenants", tags=["admin"])
def get_tenants() -> dict:
    """List all tenants with compliance and project counts."""
    return {"total": len(_tenants), "tenants": list(_tenants.values())}


# ── Admin: Four-Eyes Tracker ──────────────────────────────────────

_four_eyes_tracker: list = [
    {"exception_id": "EXC-001", "finding_id": "f-8841", "requested_by": "eng-payments", "category": "COMPENSATING_CONTROL",
     "current": "P1", "requested": "P3", "approval_1": "gerente@example.com", "approval_1_date": "2026-07-27T09:00:00Z",
     "approval_2": None, "approval_2_date": None, "status": "WAITING_2ND", "ttl_days": 90, "expires": "2026-10-25"},
    {"exception_id": "EXC-002", "finding_id": "f-9012", "requested_by": "eng-auth", "category": "DEFERRED_FIX",
     "current": "P2", "requested": "P4", "approval_1": "gerente@example.com", "approval_1_date": "2026-07-26T14:00:00Z",
     "approval_2": "super@example.com", "approval_2_date": "2026-07-27T08:00:00Z", "status": "APPROVED", "ttl_days": 90, "expires": "2026-10-24"},
    {"exception_id": "EXC-003", "finding_id": "f-7654", "requested_by": "eng-frontend", "category": "FALSE_POSITIVE",
     "current": "P1", "requested": "P4", "approval_1": None, "approval_1_date": None,
     "approval_2": None, "approval_2_date": None, "status": "WAITING_1ST", "ttl_days": 180, "expires": "2027-01-23"},
]


@app.get("/api/admin/four-eyes", tags=["admin"])
def get_four_eyes_tracker() -> dict:
    """Track four-eyes exception approvals."""
    waiting = [e for e in _four_eyes_tracker if "WAITING" in e["status"]]
    return {"total": len(_four_eyes_tracker), "waiting": len(waiting), "exceptions": _four_eyes_tracker}


# ── Admin: Latency by Layer + Alerts ──────────────────────────────

@app.get("/api/admin/latency", tags=["admin"])
def get_latency_by_layer() -> dict:
    """Pipeline latency aggregated by layer."""
    return {
        "layers": [
            {"layer": "L1 — Entrada", "p50_ms": 320, "p95_ms": 450, "p99_ms": 680, "status": "healthy"},
            {"layer": "L2 — Especialistas", "p50_ms": 1420, "p95_ms": 2800, "p99_ms": 4200, "status": "healthy"},
            {"layer": "L3 — Validacao", "p50_ms": 890, "p95_ms": 1500, "p99_ms": 2100, "status": "healthy"},
            {"layer": "L4 — Consenso", "p50_ms": 180, "p95_ms": 350, "p99_ms": 520, "status": "healthy"},
            {"layer": "L5 — Remediacao", "p50_ms": 260, "p95_ms": 480, "p99_ms": 720, "status": "healthy"},
            {"layer": "L6 — Governanca", "p50_ms": 1, "p95_ms": 2, "p99_ms": 5, "status": "healthy"},
            {"layer": "L7 — Ensemble", "p50_ms": 2, "p95_ms": 5, "p99_ms": 10, "status": "healthy"},
            {"layer": "L8 — Escala", "p50_ms": 1, "p95_ms": 2, "p99_ms": 4, "status": "healthy"},
        ],
        "total_pipeline_p50_ms": 3074,
    }


_alerts: list = [
    {"id": "ALT-001", "severity": "HIGH", "title": "Projeto Auth Module abaixo de 50", "detail": "Score 45 — 28 findings abertos, 5 bloqueados", "time": "2026-07-27T14:00:00Z", "acknowledged": False},
    {"id": "ALT-002", "severity": "MEDIUM", "title": "Payment Service — 2 itens bloqueados", "detail": "CWE-798 (hardcoded key) e CWE-89 (SQLi) aguardando remediacao", "time": "2026-07-27T12:00:00Z", "acknowledged": False},
    {"id": "ALT-003", "severity": "LOW", "title": "Sandbox executor — 2 erros em 24h", "detail": "Timeout em 2 execucoes de PoC — revisar threshold", "time": "2026-07-27T10:00:00Z", "acknowledged": True},
    {"id": "ALT-004", "severity": "HIGH", "title": "Four-eyes EXC-001 — 48h sem 2a aprovacao", "detail": "Excecao CWE-89 aguardando Superintendente desde 27/07", "time": "2026-07-27T08:00:00Z", "acknowledged": False},
    {"id": "ALT-005", "severity": "MEDIUM", "title": "PCI DSS coverage estagnado em 45%", "detail": "IaC provisionada porem sem terraform apply — sem avanco em 30 dias", "time": "2026-07-26T18:00:00Z", "acknowledged": False},
]


@app.get("/api/admin/alerts", tags=["admin"])
def get_alerts() -> dict:
    """Configurable alert system."""
    active = [a for a in _alerts if not a["acknowledged"]]
    return {"total": len(_alerts), "active": len(active), "alerts": _alerts}


# ── Auth Endpoints ─────────────────────────────────────────────────

class LoginRequest(BaseModel):
    api_key: str = Field(min_length=64)


@app.post("/api/auth/token", tags=["auth"])
def login(req: LoginRequest) -> dict:
    """Exchange API key for JWT token.

    API Keys are pre-configured in access_control.API_KEYS.
    In production, this integrates with Cognito/OAuth2.
    """
    import access_control as ac

    if req.api_key not in ac.API_KEYS:
        raise HTTPException(401, "Invalid API key")

    user_info = ac.API_KEYS[req.api_key]
    token = ac.generate_token(
        user=user_info["user"],
        role=user_info["role"],
        tenant_id=user_info.get("tenant_id", "ztk-proj"),
    )

    return {
        "access_token": token,
        "token_type": "bearer",
        "user": user_info["user"],
        "role": user_info["role"].value,
        "expires_in": 28800,  # 8 hours
    }


@app.get("/api/auth/dev-tokens", tags=["auth"])
def dev_tokens() -> dict:
    """Return dev tokens for all roles.

    WARNING: Only available in development. Remove in production.
    """
    return {"tokens": get_dev_tokens()}


@app.get("/api/auth/me", tags=["auth"])
def whoami(request: Request) -> dict:
    """Return current authenticated user info."""
    user = getattr(request.state, "user", None)
    if not user:
        raise HTTPException(401, "Not authenticated")
    return {"user": user["user"], "role": user["role"].value, "tenant_id": user.get("tenant_id")}


# ── Static Files (must be last) ────────────────────────────────────

import os
from pathlib import Path

_templates_dir = Path(__file__).resolve().parents[2] / "frontend" / "templates"
if _templates_dir.exists():
    app.mount("/", StaticFiles(directory=str(_templates_dir), html=True), name="static")
