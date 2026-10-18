"""Semgrep SAST report parser."""
from typing import List, Tuple
from security.policy.models import (
    Finding,
    FindingLocation,
    ScannerExecution,
    Severity,
)
from security.policy.parsers.base import BaseParser


class SemgrepParser(BaseParser):
    scanner_name = "semgrep"

    def parse(self, file_path: str) -> Tuple[List[Finding], ScannerExecution]:
        data, execution = self.load_json_safely(file_path)
        if data is None or not isinstance(data, dict):
            return [], execution

        raw_results = data.get("results", [])
        findings: List[Finding] = []

        for item in raw_results:
            if not isinstance(item, dict):
                continue
            check_id = item.get("check_id", "semgrep-rule")
            path = item.get("path", "unknown")
            start = item.get("start", {})
            end = item.get("end", {})
            extra = item.get("extra", {})

            message = extra.get("message", "Semgrep security finding")
            severity_str = extra.get("severity", "WARNING")
            metadata = extra.get("metadata", {})
            cwe = metadata.get("cwe", "")
            owasp = metadata.get("owasp", "")

            remediation = f"Review code pattern according to {owasp} {cwe}".strip()

            finding = Finding(
                scanner=self.scanner_name,
                rule_id=check_id,
                title=f"SAST: {check_id}",
                severity=Severity.from_str(severity_str),
                component=path.split("/")[0] if "/" in path else "application",
                location=FindingLocation(
                    file_path=path,
                    start_line=start.get("line"),
                    end_line=end.get("line"),
                ),
                remediation=remediation,
                evidence=message[:250],
            )
            findings.append(finding)

        execution.findings_count = len(findings)
        return findings, execution
