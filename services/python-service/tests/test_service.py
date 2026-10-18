"""Unit tests for Python service evaluation logic."""
import pytest
from app.models import AnalyzeRequest, ArtifactType, RiskLevel
from app.service import evaluate_security_target


def test_evaluate_clean_target():
    req = AnalyzeRequest(
        target_name="aegisops-api:1.0.0",
        artifact_type=ArtifactType.CONTAINER_IMAGE,
        environment="production",
        parameters={"user": 10001, "debug": False},
    )
    res = evaluate_security_target(req)
    assert res.risk_level == RiskLevel.CLEAN
    assert res.is_releasable is True
    assert res.findings_count == 0


def test_evaluate_root_container_flag():
    req = AnalyzeRequest(
        target_name="aegisops-api:1.0.0",
        artifact_type=ArtifactType.CONTAINER_IMAGE,
        environment="production",
        parameters={"run_as_root": True},
    )
    res = evaluate_security_target(req)
    assert res.risk_level == RiskLevel.HIGH
    assert res.is_releasable is False
    assert any(f.rule_id == "AO-PY-002" for f in res.findings)


def test_evaluate_unpinned_image_tag():
    req = AnalyzeRequest(
        target_name="aegisops-api:latest",
        artifact_type=ArtifactType.CONTAINER_IMAGE,
        environment="production",
        parameters={"user": 10001},
    )
    res = evaluate_security_target(req)
    assert res.risk_level == RiskLevel.MEDIUM
    assert res.is_releasable is True  # Medium is not blocking by default
    assert any(f.rule_id == "AO-PY-003" for f in res.findings)


def test_evaluate_plaintext_secret_parameter():
    req = AnalyzeRequest(
        target_name="app-config.yaml",
        artifact_type=ArtifactType.CONFIGURATION,
        environment="production",
        parameters={"db_password": "supersecretpassword"},
    )
    res = evaluate_security_target(req)
    assert res.risk_level == RiskLevel.CRITICAL
    assert res.is_releasable is False
    assert any(f.rule_id == "AO-PY-004" for f in res.findings)
