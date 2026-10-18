"""Unit tests for suppression/exception validation and lifecycle."""
import os
import pytest
from security.policy.engine import SecurityPolicyEngine
from security.policy.models import Decision

FIXTURES_DIR = os.path.abspath("security/fixtures/mock_reports")


def test_valid_active_suppression_allows_finding():
    engine = SecurityPolicyEngine(config_path="security/policy_config.yaml")
    reports = {
        "gitleaks": os.path.join(FIXTURES_DIR, "gitleaks_clean.json"),
        "semgrep": os.path.join(FIXTURES_DIR, "semgrep_clean.json"),
        "bandit": os.path.join(FIXTURES_DIR, "bandit_clean.json"),
        "npm_audit": os.path.join(FIXTURES_DIR, "npm_audit_clean.json"),
        "pip_audit": os.path.join(FIXTURES_DIR, "pip_audit_clean.json"),
        "trivy": os.path.join(FIXTURES_DIR, "trivy_clean.json"),
        "checkov": os.path.join(FIXTURES_DIR, "checkov_clean.json"),
        "zap": os.path.join(FIXTURES_DIR, "zap_clean.json"),
    }

    # Add finding matching configured SUP-002
    engine.policy_config["suppressions"] = [
        {
            "id": "SUP-TEST",
            "scanner": "semgrep",
            "rule_id": "secureflow-no-eval",
            "component": "frontend",
            "reason": "Documented testing exception",
            "approved_by": "Security-Lead",
            "expires_at": "2030-01-01",
        }
    ]
    reports["semgrep"] = os.path.join(FIXTURES_DIR, "semgrep_finding.json")

    result = engine.evaluate(reports)
    assert result.total_findings == 1
    assert result.suppressed_findings_count == 1
    assert result.blocking_findings_count == 0
    assert result.is_releasable is True
    assert result.all_findings[0].decision == Decision.SUPPRESSED


def test_expired_suppression_is_rejected_and_blocks():
    engine = SecurityPolicyEngine(config_path="security/policy_config.yaml")
    reports = {
        "gitleaks": os.path.join(FIXTURES_DIR, "gitleaks_clean.json"),
        "semgrep": os.path.join(FIXTURES_DIR, "semgrep_finding.json"),
        "bandit": os.path.join(FIXTURES_DIR, "bandit_clean.json"),
        "npm_audit": os.path.join(FIXTURES_DIR, "npm_audit_clean.json"),
        "pip_audit": os.path.join(FIXTURES_DIR, "pip_audit_clean.json"),
        "trivy": os.path.join(FIXTURES_DIR, "trivy_clean.json"),
        "checkov": os.path.join(FIXTURES_DIR, "checkov_clean.json"),
        "zap": os.path.join(FIXTURES_DIR, "zap_clean.json"),
    }

    # Add EXPIRED suppression (date in the past)
    engine.policy_config["suppressions"] = [
        {
            "id": "SUP-EXPIRED",
            "scanner": "semgrep",
            "rule_id": "secureflow-no-eval",
            "component": "frontend",
            "reason": "Expired temporary grace period",
            "approved_by": "Security-Lead",
            "expires_at": "2020-01-01",
        }
    ]

    result = engine.evaluate(reports)
    assert result.suppressed_findings_count == 0
    assert result.blocking_findings_count == 1
    assert result.is_releasable is False
    assert result.all_findings[0].decision == Decision.BLOCK
