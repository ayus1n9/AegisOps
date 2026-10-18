"""OWASP ZAP DAST report parser."""
from typing import List, Tuple
from security.policy.models import (
    Finding,
    FindingLocation,
    ScannerExecution,
    Severity,
)
from security.policy.parsers.base import BaseParser


class ZapParser(BaseParser):
    scanner_name = "zap"

    def parse(self, file_path: str) -> Tuple[List[Finding], ScannerExecution]:
        data, execution = self.load_json_safely(file_path)
        if data is None or not isinstance(data, dict):
            return [], execution

        sites = data.get("site", [])
        findings: List[Finding] = []

        for site in sites:
            if not isinstance(site, dict):
                continue
            site_name = site.get("@name", "target-app")
            alerts = site.get("alerts", [])

            for alert in alerts:
                if not isinstance(alert, dict):
                    continue
                plugin_id = alert.get("pluginId", "ZAP-ALERT")
                alert_title = alert.get("alert", "Web Application Security Alert")
                risk_code = alert.get("riskcode", "2")
                solution = alert.get("solution", "Review OWASP security best practices.")
                desc = alert.get("desc", "")

                finding = Finding(
                    scanner=self.scanner_name,
                    rule_id=f"ZAP-{plugin_id}",
                    title=f"DAST: {alert_title}",
                    severity=Severity.from_str(risk_code),
                    component=site_name,
                    location=FindingLocation(file_path=site_name),
                    remediation=solution,
                    evidence=desc[:200],
                )
                findings.append(finding)

        execution.findings_count = len(findings)
        return findings, execution
