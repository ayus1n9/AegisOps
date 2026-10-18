"""Unit tests for SARIF and HTML report exporters."""
import os
import pytest
from security.policy.engine import SecurityPolicyEngine
from security.policy.exporters.html import HTMLReportGenerator
from security.policy.exporters.sarif import SARIFExporter

FIXTURES_DIR = os.path.abspath("security/fixtures/mock_reports")


def test_sarif_exporter_valid_structure():
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
    result = engine.evaluate(reports)
    sarif = SARIFExporter.export(result)

    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert len(sarif["runs"]) == 1
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["name"] == "AegisOps Central Policy Engine"
    results = sarif["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "aegisops-no-eval"
    assert results[0]["level"] == "error"


def test_html_exporter_generates_dashboard():
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
    result = engine.evaluate(reports)
    html_out = HTMLReportGenerator.generate(result)

    assert "<!DOCTYPE html>" in html_out
    assert "AegisOps DevSecOps Security Gate" in html_out
    assert "RELEASE ELIGIBLE" in html_out
    assert "TOTAL FINDINGS" in html_out
