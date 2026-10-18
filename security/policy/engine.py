"""Central Security Policy Engine implementation."""
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set
import yaml

from security.policy.models import (
    Decision,
    Finding,
    PolicyResult,
    ScannerExecution,
    ScannerExecutionStatus,
    Severity,
    SuppressionRecord,
)
from security.policy.parsers import PARSER_REGISTRY, get_parser


SEVERITY_ORDER = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
    Severity.UNKNOWN: 4,  # Treat unknown as high priority for sorting
}


class SecurityPolicyEngine:
    """Evaluates multi-scanner security results against organizational policies."""

    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path
        self.policy_config = self._load_config(config_path)

    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        default_config = {
            "policy_name": "AegisOps Default DevSecOps Policy",
            "thresholds": {
                "fail_on_severities": ["CRITICAL", "HIGH"],
                "secrets_block_release": True,
                "fail_on_missing_reports": True,
                "fail_on_scanner_errors": True,
                "treat_unknown_as": "HIGH",
            },
            "required_scanners": list(PARSER_REGISTRY.keys()),
            "suppressions": [],
        }

        if not config_path or not os.path.exists(config_path):
            return default_config

        try:
            with open(config_path, "r", encoding="utf-8") as f:
                loaded = yaml.safe_load(f)
                if isinstance(loaded, dict):
                    default_config.update(loaded)
        except Exception as err:
            print(f"[Warning] Failed to parse policy config at {config_path}: {err}. Using default policy.")

        return default_config

    def _validate_suppression(self, supp: Dict[str, Any]) -> Optional[SuppressionRecord]:
        """Validate suppression entry structure and expiration date."""
        supp_id = supp.get("id")
        reason = supp.get("reason", "").strip()
        approved_by = supp.get("approved_by", "").strip()
        expires_at = supp.get("expires_at")

        if not supp_id or not reason or not approved_by:
            return None

        # Validate expiration date
        if expires_at:
            try:
                exp_date = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
                now = datetime.now(timezone.utc)
                if exp_date.tzinfo is None:
                    exp_date = exp_date.replace(tzinfo=timezone.utc)
                if now > exp_date:
                    # Expired exception
                    return None
            except Exception:
                # Invalid date format
                return None

        return SuppressionRecord(
            id=supp_id,
            scanner=supp.get("scanner", "*"),
            rule_id=supp.get("rule_id", "*"),
            component=supp.get("component", "*"),
            reason=reason,
            approved_by=approved_by,
            expires_at=expires_at,
        )

    def _is_suppressed(self, finding: Finding, valid_suppressions: List[SuppressionRecord]) -> Optional[SuppressionRecord]:
        """Determine if a finding matches an approved active suppression."""
        for supp in valid_suppressions:
            scanner_match = supp.scanner in ("*", finding.scanner)
            rule_match = supp.rule_id in ("*", finding.rule_id)
            comp_match = supp.component == "*" or supp.component in finding.component or supp.component in (finding.location.file_path or "")

            if scanner_match and rule_match and comp_match:
                return supp
        return None

    def evaluate(self, report_files: Dict[str, str]) -> PolicyResult:
        """Execute policy evaluation over declared scanner reports."""
        all_findings: List[Finding] = []
        scanner_executions: List[ScannerExecution] = []
        missing_scanners: List[str] = []
        scanner_errors: List[str] = []

        required_scanners = self.policy_config.get("required_scanners", [])
        thresholds = self.policy_config.get("thresholds", {})
        fail_on_severities: Set[str] = set(thresholds.get("fail_on_severities", ["CRITICAL", "HIGH"]))
        secrets_block = thresholds.get("secrets_block_release", True)
        fail_missing = thresholds.get("fail_on_missing_reports", True)
        fail_errors = thresholds.get("fail_on_scanner_errors", True)
        treat_unknown_as = thresholds.get("treat_unknown_as", "HIGH").upper()

        # Parse suppressions
        raw_suppressions = self.policy_config.get("suppressions", [])
        active_suppressions: List[SuppressionRecord] = []
        for raw in raw_suppressions:
            valid_supp = self._validate_suppression(raw)
            if valid_supp:
                active_suppressions.append(valid_supp)

        # Check required scanners
        for req_scanner in required_scanners:
            if req_scanner not in report_files or not os.path.exists(report_files[req_scanner]):
                missing_scanners.append(req_scanner)

        # Execute parsers
        for scanner_name, report_path in report_files.items():
            if scanner_name not in PARSER_REGISTRY:
                continue
            parser = get_parser(scanner_name)
            findings, execution = parser.parse(report_path)
            scanner_executions.append(execution)

            if execution.status == ScannerExecutionStatus.SCANNER_ERROR:
                scanner_errors.append(f"{scanner_name}: {execution.error_message}")
            elif execution.status == ScannerExecutionStatus.MALFORMED_OUTPUT:
                scanner_errors.append(f"{scanner_name} (malformed): {execution.error_message}")
            elif execution.status == ScannerExecutionStatus.MISSING_REPORT:
                if scanner_name not in missing_scanners:
                    missing_scanners.append(scanner_name)

            all_findings.extend(findings)

        # Deduplicate findings deterministically
        seen_ids: Set[str] = set()
        deduped_findings: List[Finding] = []
        for f in all_findings:
            if f.finding_id not in seen_ids:
                seen_ids.add(f.finding_id)
                deduped_findings.append(f)

        # Apply suppressions and policy decisions
        blocking_findings: List[Finding] = []
        suppressed_count = 0
        severity_counts: Dict[str, int] = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0,
            "UNKNOWN": 0,
        }

        for finding in deduped_findings:
            # Count severity
            severity_counts[finding.severity.value] = severity_counts.get(finding.severity.value, 0) + 1

            # Check suppression
            supp = self._is_suppressed(finding, active_suppressions)
            if supp:
                finding.decision = Decision.SUPPRESSED
                finding.suppression = supp
                suppressed_count += 1
                continue

            # Check secret policy
            if finding.is_secret and secrets_block:
                finding.decision = Decision.BLOCK
                blocking_findings.append(finding)
                continue

            # Check severity thresholds
            effective_sev = finding.severity.value
            if effective_sev == "UNKNOWN":
                effective_sev = treat_unknown_as

            if effective_sev in fail_on_severities:
                finding.decision = Decision.BLOCK
                blocking_findings.append(finding)
            elif finding.severity in (Severity.MEDIUM, Severity.LOW):
                finding.decision = Decision.WARN
            else:
                finding.decision = Decision.ALLOW

        # Sort findings deterministically
        deduped_findings.sort(
            key=lambda x: (
                -SEVERITY_ORDER.get(x.severity, 0),
                x.decision != Decision.BLOCK,
                x.scanner,
                x.rule_id,
                x.finding_id,
            )
        )

        # Release eligibility decision (fail closed)
        is_releasable = True
        explanation_parts = []

        if len(blocking_findings) > 0:
            is_releasable = False
            explanation_parts.append(
                f"Release BLOCKED: {len(blocking_findings)} actionable security finding(s) exceed policy threshold."
            )

        if fail_missing and len(missing_scanners) > 0:
            is_releasable = False
            explanation_parts.append(
                f"Release BLOCKED (Fail-Closed): {len(missing_scanners)} required scanner report(s) missing: {', '.join(missing_scanners)}."
            )

        if fail_errors and len(scanner_errors) > 0:
            is_releasable = False
            explanation_parts.append(
                f"Release BLOCKED (Fail-Closed): {len(scanner_errors)} scanner execution error(s) occurred."
            )

        if is_releasable:
            explanation_parts.append(
                f"Release ELIGIBLE: All {len(scanner_executions)} required scanners passed. Zero blocking vulnerabilities detected."
            )

        return PolicyResult(
            is_releasable=is_releasable,
            policy_name=self.policy_config.get("policy_name", "AegisOps Policy"),
            total_findings=len(deduped_findings),
            findings_by_severity=severity_counts,
            blocking_findings_count=len(blocking_findings),
            suppressed_findings_count=suppressed_count,
            blocking_findings=blocking_findings,
            all_findings=deduped_findings,
            scanners=scanner_executions,
            missing_required_scanners=missing_scanners,
            scanner_errors=scanner_errors,
            summary_explanation=" ".join(explanation_parts),
        )
