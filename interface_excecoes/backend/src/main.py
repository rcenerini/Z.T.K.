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
