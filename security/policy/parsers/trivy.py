"""Trivy container and vulnerability scanner parser."""
from typing import List, Tuple
from security.policy.models import (
    Finding,
    FindingLocation,
    ScannerExecution,
    Severity,
)
from security.policy.parsers.base import BaseParser


class TrivyParser(BaseParser):
    scanner_name = "trivy"

    def parse(self, file_path: str) -> Tuple[List[Finding], ScannerExecution]:
        data, execution = self.load_json_safely(file_path)
        if data is None or not isinstance(data, dict):
            return [], execution

        results = data.get("Results", [])
        findings: List[Finding] = []

        for res in results:
            if not isinstance(res, dict):
                continue
            target = res.get("Target", "container-image")
            vulns = res.get("Vulnerabilities", [])

            for v in vulns:
                if not isinstance(v, dict):
                    continue
                cve_id = v.get("VulnerabilityID", "TRIVY-VULN")
                pkg_name = v.get("PkgName", "unknown")
                installed_ver = v.get("InstalledVersion", "")
                fixed_ver = v.get("FixedVersion", "None available")
                severity_str = v.get("Severity", "UNKNOWN")
                title = v.get("Title") or v.get("Description") or cve_id

                finding = Finding(
                    scanner=self.scanner_name,
                    rule_id=cve_id,
                    title=f"Container CVE: {cve_id} in {pkg_name}",
                    severity=Severity.from_str(severity_str),
                    component=target,
                    location=FindingLocation(
                        package_name=pkg_name,
                        package_version=installed_ver,
                    ),
                    remediation=f"Upgrade {pkg_name} to {fixed_ver}",
                    evidence=title[:200],
                )
                findings.append(finding)

        execution.findings_count = len(findings)
        return findings, execution
