"""SARIF v2.1.0 exporter for GitHub Code Scanning integration."""
import json
from typing import Any, Dict
from security.policy.models import Decision, Finding, PolicyResult, Severity


def severity_to_sarif_level(sev: Severity) -> str:
    """Map AegisOps severity to standard SARIF level."""
    if sev in (Severity.CRITICAL, Severity.HIGH):
        return "error"
    elif sev == Severity.MEDIUM:
        return "warning"
    else:
        return "note"


class SARIFExporter:
    """Transforms normalized AegisOps findings into OASIS SARIF v2.1.0."""

    @staticmethod
    def export(result: PolicyResult) -> Dict[str, Any]:
        rules_map: Dict[str, Dict[str, Any]] = {}
        sarif_results = []

        for finding in result.all_findings:
            rule_id = finding.rule_id
            level = severity_to_sarif_level(finding.severity)

            if rule_id not in rules_map:
                rules_map[rule_id] = {
                    "id": rule_id,
                    "name": finding.title[:64],
                    "shortDescription": {"text": finding.title},
                    "fullDescription": {"text": f"{finding.title}. Remediation: {finding.remediation}"},
                    "defaultConfiguration": {"level": level},
                    "properties": {
                        "precision": "high",
                        "security-severity": "8.0" if finding.severity in (Severity.CRITICAL, Severity.HIGH) else "4.0",
                        "tags": ["security", finding.scanner, finding.severity.value.lower()],
                    },
                }

            loc_uri = finding.location.file_path or finding.component or "repository"
            start_line = finding.location.start_line or 1

            sarif_result: Dict[str, Any] = {
                "ruleId": rule_id,
                "level": level,
                "message": {"text": f"[{finding.scanner.upper()}] {finding.title}: {finding.evidence}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": loc_uri.lstrip("/"),
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": start_line,
                                "startColumn": 1,
                            },
                        }
                    }
                ],
                "properties": {
                    "findingId": finding.finding_id,
                    "scanner": finding.scanner,
                    "severity": finding.severity.value,
                    "remediation": finding.remediation,
                    "decision": finding.decision.value,
                },
            }

            if finding.decision == Decision.SUPPRESSED and finding.suppression:
                sarif_result["suppressions"] = [
                    {
                        "kind": "external",
                        "status": "accepted",
                        "justification": finding.suppression.reason,
                    }
                ]

            sarif_results.append(sarif_result)

        sarif_doc = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "AegisOps Central Policy Engine",
                            "semanticVersion": "1.0.0",
                            "informationUri": "https://github.com/ayus1n9/AegisOps",
                            "rules": list(rules_map.values()),
                        }
                    },
                    "results": sarif_results,
                }
            ],
        }

        return sarif_doc
