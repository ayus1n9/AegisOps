"""Checkov Infrastructure-as-Code & Dockerfile scanner parser."""
from typing import List, Tuple
from security.policy.models import (
    Finding,
    FindingLocation,
    ScannerExecution,
    Severity,
)
from security.policy.parsers.base import BaseParser


class CheckovParser(BaseParser):
    scanner_name = "checkov"

    def parse(self, file_path: str) -> Tuple[List[Finding], ScannerExecution]:
        data, execution = self.load_json_safely(file_path)
        if data is None:
            return [], execution

        findings: List[Finding] = []
        # Checkov output can be a single dict or a list of dicts for multi-framework scans
        items = [data] if isinstance(data, dict) else (data if isinstance(data, list) else [])

        for report in items:
            if not isinstance(report, dict):
                continue
            results = report.get("results", {})
            failed = results.get("failed_checks", [])

            for check in failed:
                if not isinstance(check, dict):
                    continue
                check_id = check.get("check_id", "CKV_UNKNOWN")
                check_name = check.get("check_name", "IaC misconfiguration")
                file_path_str = check.get("file_path", "Dockerfile")
                line_range = check.get("file_line_range", [1, 1])
                guideline = check.get("guideline", "Review Checkov documentation.")
                severity_str = check.get("severity") or "HIGH"

                finding = Finding(
                    scanner=self.scanner_name,
                    rule_id=check_id,
                    title=f"IaC Misconfiguration: {check_name[:60]}",
                    severity=Severity.from_str(severity_str),
                    component="infrastructure",
                    location=FindingLocation(
                        file_path=file_path_str,
                        start_line=line_range[0] if line_range else 1,
                        end_line=line_range[1] if len(line_range) > 1 else line_range[0],
                    ),
                    remediation=guideline,
                    evidence=f"Checkov rule {check_id} failed on {file_path_str}",
                )
                findings.append(finding)

        execution.findings_count = len(findings)
        return findings, execution
