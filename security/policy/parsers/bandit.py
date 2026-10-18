"""Bandit Python AST security scanner parser."""
from typing import List, Tuple
from security.policy.models import (
    Finding,
    FindingLocation,
    ScannerExecution,
    Severity,
)
from security.policy.parsers.base import BaseParser


class BanditParser(BaseParser):
    scanner_name = "bandit"

    def parse(self, file_path: str) -> Tuple[List[Finding], ScannerExecution]:
        data, execution = self.load_json_safely(file_path)
        if data is None or not isinstance(data, dict):
            return [], execution

        raw_results = data.get("results", [])
        findings: List[Finding] = []

        for item in raw_results:
            if not isinstance(item, dict):
                continue
            test_id = item.get("test_id", "bandit-check")
            issue_text = item.get("issue_text", "Bandit Python security issue")
            filename = item.get("filename", "unknown")
            line_num = item.get("line_number")
            issue_severity = item.get("issue_severity", "MEDIUM")
            code_snippet = item.get("code", "").strip()

            finding = Finding(
                scanner=self.scanner_name,
                rule_id=test_id,
                title=f"Python SAST: [{test_id}] {issue_text[:60]}",
                severity=Severity.from_str(issue_severity),
                component="python-service",
                location=FindingLocation(
                    file_path=filename,
                    start_line=line_num,
                    end_line=line_num,
                ),
                remediation=issue_text,
                evidence=f"Line {line_num}: {code_snippet[:150]}",
            )
            findings.append(finding)

        execution.findings_count = len(findings)
        return findings, execution
