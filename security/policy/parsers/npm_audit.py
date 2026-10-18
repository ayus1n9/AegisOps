"""npm audit dependency scanner parser."""
from typing import List, Tuple
from security.policy.models import (
    Finding,
    FindingLocation,
    ScannerExecution,
    Severity,
)
from security.policy.parsers.base import BaseParser


class NpmAuditParser(BaseParser):
    scanner_name = "npm_audit"

    def parse(self, file_path: str) -> Tuple[List[Finding], ScannerExecution]:
        data, execution = self.load_json_safely(file_path)
        if data is None or not isinstance(data, dict):
            return [], execution

        vulns = data.get("vulnerabilities", {})
        findings: List[Finding] = []

        for pkg_name, details in vulns.items():
            if not isinstance(details, dict):
                continue
            severity_str = details.get("severity", "moderate")
            via_list = details.get("via", [])

            advisory_title = "Vulnerable JavaScript dependency"
            rule_id = f"npm-{pkg_name}"
            advisory_url = ""

            for via in via_list:
                if isinstance(via, dict):
                    advisory_title = via.get("title", advisory_title)
                    rule_id = via.get("url", rule_id).split("/")[-1] or rule_id
                    advisory_url = via.get("url", "")
                    break

            fix_available = details.get("fixAvailable", False)
            remediation = f"Update '{pkg_name}' to safe version. ({'Fix available via npm audit fix' if fix_available else 'Manual dependency resolution required'})"

            finding = Finding(
                scanner=self.scanner_name,
                rule_id=rule_id,
                title=f"Dependency Vulnerability: {pkg_name} ({advisory_title[:50]})",
                severity=Severity.from_str(severity_str),
                component="node_modules",
                location=FindingLocation(
                    package_name=pkg_name,
                    package_version=details.get("range", ""),
                ),
                remediation=remediation,
                evidence=advisory_url or f"Package {pkg_name} version range {details.get('range')}",
            )
            findings.append(finding)

        execution.findings_count = len(findings)
        return findings, execution
