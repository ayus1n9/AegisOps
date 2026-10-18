"""Unit tests for Central Security Policy Engine evaluation logic."""
import os
import pytest
from security.policy.engine import SecurityPolicyEngine
from security.policy.models import Decision, Severity

FIXTURES_DIR = os.path.abspath("security/fixtures/mock_reports")


def get_clean_report_files():
    return {
        "gitleaks": os.path.join(FIXTURES_DIR, "gitleaks_clean.json"),
        "semgrep": os.path.join(FIXTURES_DIR, "semgrep_clean.json"),
        "bandit": os.path.join(FIXTURES_DIR, "bandit_clean.json"),
        "npm_audit": os.path.join(FIXTURES_DIR, "npm_audit_clean.json"),
        "pip_audit": os.path.join(FIXTURES_DIR, "pip_audit_clean.json"),
        "trivy": os.path.join(FIXTURES_DIR, "trivy_clean.json"),
        "checkov": os.path.join(FIXTURES_DIR, "checkov_clean.json"),
        "zap": os.path.join(FIXTURES_DIR, "zap_clean.json"),
    }


def test_engine_clean_reports_pass_gate():
    engine = SecurityPolicyEngine(config_path="security/policy_config.yaml")
    reports = get_clean_report_files()
    result = engine.evaluate(reports)

    assert result.is_releasable is True
    assert result.total_findings == 0
    assert result.blocking_findings_count == 0
    assert len(result.missing_required_scanners) == 0
    assert "ELIGIBLE" in result.summary_explanation


def test_engine_critical_finding_blocks_gate():
    engine = SecurityPolicyEngine(config_path="security/policy_config.yaml")
    reports = get_clean_report_files()
    # Inject Trivy critical vulnerability
    reports["trivy"] = os.path.join(FIXTURES_DIR, "trivy_finding.json")

    result = engine.evaluate(reports)
    assert result.is_releasable is False
    assert result.blocking_findings_count == 1
    assert result.blocking_findings[0].severity == Severity.CRITICAL
    assert result.blocking_findings[0].decision == Decision.BLOCK
    assert "BLOCKED" in result.summary_explanation


def test_engine_secret_finding_blocks_gate():
    engine = SecurityPolicyEngine(config_path="security/policy_config.yaml")
    reports = get_clean_report_files()
    # Inject Gitleaks secret finding
    reports["gitleaks"] = os.path.join(FIXTURES_DIR, "gitleaks_finding.json")

    result = engine.evaluate(reports)
    assert result.is_releasable is False
    assert result.blocking_findings_count == 1
    assert result.blocking_findings[0].is_secret is True
    assert result.blocking_findings[0].decision == Decision.BLOCK


def test_engine_fail_closed_on_missing_required_report():
    engine = SecurityPolicyEngine(config_path="security/policy_config.yaml")
    reports = get_clean_report_files()
    # Intentionally remove ZAP DAST scan
    del reports["zap"]

    result = engine.evaluate(reports)
    assert result.is_releasable is False
    assert "zap" in result.missing_required_scanners
    assert "missing" in result.summary_explanation.lower()


def test_engine_fail_closed_on_scanner_execution_error():
    engine = SecurityPolicyEngine(config_path="security/policy_config.yaml")
    reports = get_clean_report_files()
    # Inject report recording scanner error
    reports["trivy"] = os.path.join(FIXTURES_DIR, "scanner_error.json")

    result = engine.evaluate(reports)
    assert result.is_releasable is False
    assert len(result.scanner_errors) > 0
    assert "error" in result.summary_explanation.lower()


def test_engine_deterministic_output():
    engine = SecurityPolicyEngine(config_path="security/policy_config.yaml")
    reports = get_clean_report_files()
    reports["semgrep"] = os.path.join(FIXTURES_DIR, "semgrep_finding.json")
    reports["bandit"] = os.path.join(FIXTURES_DIR, "bandit_finding.json")

    res1 = engine.evaluate(reports)
    res2 = engine.evaluate(reports)

    assert res1.total_findings == res2.total_findings
    assert res1.is_releasable == res2.is_releasable
    assert [f.finding_id for f in res1.all_findings] == [f.finding_id for f in res2.all_findings]
