"""Unit tests for scanner error conditions and edge cases."""
import os
import pytest
from security.policy.engine import SecurityPolicyEngine
from security.policy.models import ScannerExecutionStatus, Severity

FIXTURES_DIR = os.path.abspath("security/fixtures/mock_reports")


def test_empty_json_report_handled_safely():
    engine = SecurityPolicyEngine(config_path="security/policy_config.yaml")
    reports = {
        "semgrep": os.path.join(FIXTURES_DIR, "empty.json"),
    }
    result = engine.evaluate(reports)
    assert result.total_findings == 0
    # Empty file does not crash the system


def test_malformed_json_report_fails_closed():
    engine = SecurityPolicyEngine(config_path="security/policy_config.yaml")
    reports = {
        "semgrep": os.path.join(FIXTURES_DIR, "malformed.json"),
    }
    result = engine.evaluate(reports)
    assert result.is_releasable is False
    assert any("malformed" in err.lower() for err in result.scanner_errors)


def test_unknown_severity_handled_as_configured():
    engine = SecurityPolicyEngine(config_path="security/policy_config.yaml")
    reports = {
        "gitleaks": os.path.join(FIXTURES_DIR, "gitleaks_clean.json"),
        "semgrep": os.path.join(FIXTURES_DIR, "unknown_severity.json"),
        "bandit": os.path.join(FIXTURES_DIR, "bandit_clean.json"),
        "npm_audit": os.path.join(FIXTURES_DIR, "npm_audit_clean.json"),
        "pip_audit": os.path.join(FIXTURES_DIR, "pip_audit_clean.json"),
        "trivy": os.path.join(FIXTURES_DIR, "trivy_clean.json"),
        "checkov": os.path.join(FIXTURES_DIR, "checkov_clean.json"),
        "zap": os.path.join(FIXTURES_DIR, "zap_clean.json"),
    }
    result = engine.evaluate(reports)
    assert result.total_findings == 1
    assert result.all_findings[0].severity == Severity.UNKNOWN
    # In default config, treat_unknown_as=HIGH, which is in fail_on_severities
    assert result.blocking_findings_count == 1
    assert result.is_releasable is False
