"""Unit tests for individual scanner report parsers."""
import os
import pytest
from security.policy.models import Severity
from security.policy.parsers.bandit import BanditParser
from security.policy.parsers.checkov import CheckovParser
from security.policy.parsers.gitleaks import GitleaksParser
from security.policy.parsers.npm_audit import NpmAuditParser
from security.policy.parsers.pip_audit import PipAuditParser
from security.policy.parsers.semgrep import SemgrepParser
from security.policy.parsers.trivy import TrivyParser
from security.policy.parsers.zap import ZapParser

FIXTURES_DIR = os.path.abspath("security/fixtures/mock_reports")


def test_gitleaks_parser_clean():
    parser = GitleaksParser()
    findings, exec_stat = parser.parse(os.path.join(FIXTURES_DIR, "gitleaks_clean.json"))
    assert len(findings) == 0
    assert exec_stat.status.value == "SUCCESS"


def test_gitleaks_parser_finding_and_secret_redaction():
    parser = GitleaksParser()
    findings, exec_stat = parser.parse(os.path.join(FIXTURES_DIR, "gitleaks_finding.json"))
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "secureflow-internal-api-key"
    assert f.severity == Severity.CRITICAL
    assert f.is_secret is True
    # Secret must never be leaked in cleartext evidence
    assert "sf_secret_FAKE" not in f.evidence
    assert "redacted" in f.evidence.lower()


def test_semgrep_parser():
    parser = SemgrepParser()
    findings, exec_stat = parser.parse(os.path.join(FIXTURES_DIR, "semgrep_finding.json"))
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "secureflow-no-eval"
    assert f.severity == Severity.HIGH
    assert f.location.file_path == "frontend/src/bad.ts"
    assert f.location.start_line == 4


def test_bandit_parser():
    parser = BanditParser()
    findings, exec_stat = parser.parse(os.path.join(FIXTURES_DIR, "bandit_finding.json"))
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "B307"
    assert f.severity == Severity.HIGH
    assert "eval(user_input)" in f.evidence


def test_npm_audit_parser():
    parser = NpmAuditParser()
    findings, exec_stat = parser.parse(os.path.join(FIXTURES_DIR, "npm_audit_finding.json"))
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.CRITICAL
    assert f.location.package_name == "insecure-pkg"


def test_pip_audit_parser():
    parser = PipAuditParser()
    findings, exec_stat = parser.parse(os.path.join(FIXTURES_DIR, "pip_audit_finding.json"))
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "PYSEC-2024-999"
    assert f.location.package_name == "insecure-python-pkg"


def test_trivy_parser():
    parser = TrivyParser()
    findings, exec_stat = parser.parse(os.path.join(FIXTURES_DIR, "trivy_finding.json"))
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "CVE-2024-99999"
    assert f.severity == Severity.CRITICAL
    assert f.location.package_name == "libcrypto3"


def test_checkov_parser():
    parser = CheckovParser()
    findings, exec_stat = parser.parse(os.path.join(FIXTURES_DIR, "checkov_finding.json"))
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "CKV_DOCKER_3"
    assert f.severity == Severity.HIGH


def test_zap_parser():
    parser = ZapParser()
    findings, exec_stat = parser.parse(os.path.join(FIXTURES_DIR, "zap_finding.json"))
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "ZAP-10038"
    assert f.severity == Severity.HIGH
