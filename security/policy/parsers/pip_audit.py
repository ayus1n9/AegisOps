"""pip-audit Python dependency scanner parser."""
from typing import List, Tuple
from security.policy.models import (
    Finding,
    FindingLocation,
    ScannerExecution,
    Severity,
)
from security.policy.parsers.base import BaseParser


class PipAuditParser(BaseParser):
    scanner_name = "pip_audit"

    def parse(self, file_path: str) -> Tuple[List[Finding], ScannerExecution]:
        data, execution = self.load_json_safely(file_path)
        if data is None or not isinstance(data, dict):
            return [], execution

        deps = data.get("dependencies", [])
        findings: List[Finding] = []

        for dep in deps:
            if not isinstance(dep, dict):
                continue
            pkg_name = dep.get("name", "unknown")
            installed_ver = dep.get("version", "")
            vulns = dep.get("vulns", [])

            for v in vulns:
                if not isinstance(v, dict):
                    continue
                vuln_id = v.get("id", "PYSEC-UNKNOWN")
                desc = v.get("description", "Known vulnerability in Python package")
                fix_versions = v.get("fix_versions", [])

                remediation = f"Upgrade {pkg_name} to version {', '.join(fix_versions) if fix_versions else 'latest patched release'}"

                finding = Finding(
                    scanner=self.scanner_name,
                    rule_id=vuln_id,
                    title=f"Python Dependency: {pkg_name} - {vuln_id}",
                    severity=Severity.HIGH,  # pip-audit defaults CVEs to High unless CVSS provided
                    component="python-service/dependencies",
                    location=FindingLocation(
                        package_name=pkg_name,
                        package_version=installed_ver,
                    ),
                    remediation=remediation,
                    evidence=desc[:200],
                )
                findings.append(finding)

        execution.findings_count = len(findings)
        return findings, execution
