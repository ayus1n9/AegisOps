"""API integration tests for Python service endpoints."""
import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "secureflow-python-service"
    assert "version" in data


def test_readiness_endpoint():
    response = client.get("/ready")
    assert response.status_code == 200
    assert response.json() == {"status": "ready", "ready": True}


def test_analyze_endpoint_valid():
    payload = {
        "target_name": "secureflow-api:1.0.0",
        "artifact_type": "container_image",
        "environment": "production",
        "parameters": {"user": 10001},
    }
    response = client.post("/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["target_name"] == "secureflow-api:1.0.0"
    assert data["risk_level"] == "CLEAN"
    assert data["is_releasable"] is True


def test_analyze_endpoint_invalid_target_name_injection():
    # Attempt directory traversal / injection
    payload = {
        "target_name": "../../etc/passwd",
        "artifact_type": "source_code",
    }
    response = client.post("/analyze", json=payload)
    assert response.status_code == 422
    data = response.json()
    assert "error" in data


def test_analyze_endpoint_missing_required_fields():
    response = client.post("/analyze", json={})
    assert response.status_code == 422
