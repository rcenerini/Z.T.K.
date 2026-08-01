"""M9 — Integration tests for Exception Dashboard API."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import sys
sys.path.insert(0, "interface_excecoes/backend/src")

from main import app

client = TestClient(app)


class TestDashboardAPI:
    def test_health(self) -> None:
        r = client.get("/api/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_create_exception(self) -> None:
        r = client.post("/api/exceptions", json={
            "finding_id": "test-123", "tenant_id": "ztk-proj",
            "requested_by": "eng@example.com",
            "category": "COMPENSATING_CONTROL",
            "justification": "WAF rule blocks the exploit. This is a valid compensating control for the SQL injection vulnerability.",
            "current_severity": "P1", "requested_severity": "P3", "ttl_days": 90,
        })
        assert r.status_code == 200
        assert r.json()["status"] == "REQUESTED"

    def test_list_exceptions(self) -> None:
        r = client.get("/api/exceptions")
        assert r.status_code == 200

    def test_dashboard_summary(self) -> None:
        r = client.get("/api/dashboard/summary")
        assert r.status_code == 200
        assert "exceptions" in r.json()

    def test_kill_switch_soc(self) -> None:
        r = client.post("/api/kill-switch", json={
            "scope": "full", "reason": "Test activation — emergency drill with documented justification",
            "operator": "SOC",
        })
        assert r.status_code == 200
        assert r.json()["active"] is True

    def test_kill_switch_denied_non_soc(self) -> None:
        r = client.post("/api/kill-switch", json={
            "scope": "full", "reason": "Test unauthorized activation",
            "operator": "ENGINEERING",
        })
        assert r.status_code == 403

    def test_create_hitl(self) -> None:
        r = client.post("/api/hitl", json={
            "finding_id": "test-456", "title": "Prompt injection blocked",
            "description": "Content blocked by L1.03 guard requires human review and analysis",
            "priority": "HIGH",
        })
        assert r.status_code == 200

    def test_audit_timeline(self) -> None:
        r = client.get("/api/audit")
        assert r.status_code == 200
        assert r.json()["total"] > 0

    def test_admin_projects(self) -> None:
        r = client.get("/api/admin/projects")
        assert r.status_code == 200
        assert r.json()["total"] >= 4

    def test_admin_metrics(self) -> None:
        r = client.get("/api/admin/metrics")
        assert r.status_code == 200
        assert r.json()["total_agents"] >= 10

    def test_admin_blocks(self) -> None:
        r = client.get("/api/admin/blocks")
        assert r.status_code == 200
        assert r.json()["total"] >= 3

    def test_admin_compliance(self) -> None:
        r = client.get("/api/admin/compliance")
        assert r.status_code == 200
        assert "pci_dss" in r.json()

    def test_admin_throughput(self) -> None:
        r = client.get("/api/admin/throughput")
        assert r.status_code == 200
        assert r.json()["total_24h"]["findings"] > 0

    def test_admin_tenants(self) -> None:
        r = client.get("/api/admin/tenants")
        assert r.status_code == 200
        assert r.json()["total"] >= 3

    def test_admin_four_eyes(self) -> None:
        r = client.get("/api/admin/four-eyes")
        assert r.status_code == 200
        assert r.json()["total"] >= 2

    def test_admin_latency(self) -> None:
        r = client.get("/api/admin/latency")
        assert r.status_code == 200
        assert len(r.json()["layers"]) == 8

    def test_admin_alerts(self) -> None:
        r = client.get("/api/admin/alerts")
        assert r.status_code == 200
        assert r.json()["total"] >= 3
