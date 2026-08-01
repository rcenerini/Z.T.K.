"""M9 — Integration tests for Exception Dashboard API."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import sys
sys.path.insert(0, "interface_excecoes/backend/src")

from main import app
from access_control import API_KEYS

client = TestClient(app)

# Use admin API key for all tests
_admin_headers = {"X-API-Key": next(k for k, v in API_KEYS.items() if v["role"].value == "ADMIN")}
_soc_headers = {"X-API-Key": next(k for k, v in API_KEYS.items() if v["role"].value == "SOC")}


class TestDashboardAPI:
    def test_health(self) -> None:
        r = client.get("/api/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_create_exception(self) -> None:
        r = client.post("/api/exceptions", headers=_admin_headers, json={
            "finding_id": "test-123", "tenant_id": "ztk-proj",
            "requested_by": "eng@example.com",
            "category": "COMPENSATING_CONTROL",
            "justification": "WAF rule blocks the exploit. This is a valid compensating control for the SQL injection vulnerability.",
            "current_severity": "P1", "requested_severity": "P3", "ttl_days": 90,
        })
        assert r.status_code == 200
        assert r.json()["status"] == "REQUESTED"

    def test_list_exceptions(self) -> None:
        r = client.get("/api/exceptions", headers=_admin_headers)
        assert r.status_code == 200

    def test_dashboard_summary(self) -> None:
        r = client.get("/api/dashboard/summary", headers=_admin_headers)
        assert r.status_code == 200
        assert "exceptions" in r.json()

    def test_kill_switch_soc(self) -> None:
        r = client.post("/api/kill-switch", headers=_soc_headers, json={
            "scope": "full", "reason": "Test activation — emergency drill with documented justification",
            "operator": "SOC",
        })
        assert r.status_code == 200
        assert r.json()["active"] is True

    def test_kill_switch_denied_non_soc(self) -> None:
        r = client.post("/api/kill-switch", headers=_admin_headers, json={
            "scope": "full", "reason": "Test unauthorized activation",
            "operator": "ENGINEERING",
        })
        assert r.status_code == 403

    def test_create_hitl(self) -> None:
        r = client.post("/api/hitl", headers=_admin_headers, json={
            "finding_id": "test-456", "title": "Prompt injection blocked",
            "description": "Content blocked by L1.03 guard requires human review and analysis",
            "priority": "HIGH",
        })
        assert r.status_code == 200

    def test_audit_timeline(self) -> None:
        r = client.get("/api/audit", headers=_admin_headers)
        assert r.status_code == 200
        assert r.json()["total"] > 0

    def test_admin_projects(self) -> None:
        r = client.get("/api/admin/projects", headers=_admin_headers)
        assert r.status_code == 200
        assert r.json()["total"] >= 4

    def test_admin_metrics(self) -> None:
        r = client.get("/api/admin/metrics", headers=_admin_headers)
        assert r.status_code == 200
        assert r.json()["total_agents"] >= 10

    def test_admin_blocks(self) -> None:
        r = client.get("/api/admin/blocks", headers=_admin_headers)
        assert r.status_code == 200
        assert r.json()["total"] >= 3

    def test_admin_compliance(self) -> None:
        r = client.get("/api/admin/compliance", headers=_admin_headers)
        assert r.status_code == 200
        assert "pci_dss" in r.json()

    def test_admin_throughput(self) -> None:
        r = client.get("/api/admin/throughput", headers=_admin_headers)
        assert r.status_code == 200
        assert r.json()["total_24h"]["findings"] > 0

    def test_admin_tenants(self) -> None:
        r = client.get("/api/admin/tenants", headers=_admin_headers)
        assert r.status_code == 200
        assert r.json()["total"] >= 3

    def test_admin_four_eyes(self) -> None:
        r = client.get("/api/admin/four-eyes", headers=_admin_headers)
        assert r.status_code == 200
        assert r.json()["total"] >= 2

    def test_admin_latency(self) -> None:
        r = client.get("/api/admin/latency", headers=_admin_headers)
        assert r.status_code == 200
        assert len(r.json()["layers"]) == 8

    def test_admin_alerts(self) -> None:
        r = client.get("/api/admin/alerts", headers=_admin_headers)
        assert r.status_code == 200
        assert r.json()["total"] >= 3


# ═══════════════════════════════════════════════════════════════════
# Access Control
# ═══════════════════════════════════════════════════════════════════

class TestAccessControl:
    def test_health_no_auth_required(self) -> None:
        r = client.get("/api/health")
        assert r.status_code == 200

    def test_admin_projects_requires_auth(self) -> None:
        """Without auth header, should get 401."""
        r = client.get("/api/admin/projects")
        assert r.status_code == 401

    def test_admin_with_valid_api_key(self) -> None:
        from access_control import API_KEYS
        # Find an admin key
        admin_key = next(k for k, v in API_KEYS.items() if v["role"].value == "ADMIN")
        r = client.get("/api/admin/projects", headers={"X-API-Key": admin_key})
        assert r.status_code == 200

    def test_viewer_cannot_access_admin(self) -> None:
        """Viewer role should not access admin endpoints."""
        # Create a viewer token
        from access_control import generate_token, Role
        token = generate_token("viewer", Role.VIEWER)
        r = client.get("/api/admin/projects", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 403

    def test_kill_switch_requires_soc(self) -> None:
        """Admin should not be able to POST kill-switch."""
        from access_control import API_KEYS
        admin_key = next(k for k, v in API_KEYS.items() if v["role"].value == "ADMIN")
        r = client.post("/api/kill-switch", headers={"X-API-Key": admin_key}, json={
            "scope": "full", "reason": "Test activation — access control validation test run.",
            "operator": "ADMIN",
        })
        assert r.status_code == 403

    def test_soc_can_kill_switch(self) -> None:
        from access_control import API_KEYS
        soc_key = next(k for k, v in API_KEYS.items() if v["role"].value == "SOC")
        r = client.post("/api/kill-switch", headers={"X-API-Key": soc_key}, json={
            "scope": "full", "reason": "Test activation — SOC access control validation test.",
            "operator": "SOC",
        })
        assert r.status_code == 200

    def test_token_login(self) -> None:
        from access_control import API_KEYS
        admin_key = next(k for k, v in API_KEYS.items() if v["role"].value == "ADMIN")
        r = client.post("/api/auth/token", json={"api_key": admin_key})
        assert r.status_code == 200
        assert "access_token" in r.json()

    def test_invalid_key_rejected(self) -> None:
        r = client.post("/api/auth/token", json={"api_key": "x" * 64})
        assert r.status_code == 401
