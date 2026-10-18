"""Gitleaks secret scanner report parser."""
from typing import List, Tuple
from security.policy.models import (
    Finding,
    FindingLocation,
    ScannerExecution,
    Severity,
)
from security.policy.parsers.base import BaseParser


class GitleaksParser(BaseParser):
    scanner_name = "gitleaks"

    def parse(self, file_path: str) -> Tuple[List[Finding], ScannerExecution]:
        data, execution = self.load_json_safely(file_path)
        if data is None or not isinstance(data, list):
            if execution.status == execution.status.SUCCESS and not isinstance(data, list):
                execution.findings_count = 0
                return [], execution
            return [], execution

        findings: List[Finding] = []
        for item in data:
            if not isinstance(item, dict):
                continue
            rule_id = item.get("RuleID", "gitleaks-secret")
            desc = item.get("Description", "Detected plaintext secret")
            file_name = item.get("File", "unknown")
            start_line = item.get("StartLine")
            end_line = item.get("EndLine")

            # Redact actual secret content from evidence to protect logs and reports
            evidence = f"Secret match on rule '{rule_id}' in {file_name}:{start_line} (value redacted)"

            finding = Finding(
                scanner=self.scanner_name,
                rule_id=rule_id,
                title=f"Secret Detected: {desc}",
                severity=Severity.CRITICAL,  # Secrets always classified as CRITICAL
                component=file_name.split("/")[0] if "/" in file_name else "repository",
                location=FindingLocation(
                    file_path=file_name,
                    start_line=start_line,
                    end_line=end_line,
                ),
                remediation="Rotate exposed credential immediately and remove from Git history.",
                evidence=evidence,
                is_secret=True,
            )
            findings.append(finding)

        execution.findings_count = len(findings)
        return findings, execution
