"""Command-line interface for the Central Security Policy Engine."""
import argparse
import json
import os
import sys

from security.policy.engine import SecurityPolicyEngine
from security.policy.exporters.sarif import SARIFExporter
from security.policy.exporters.html import HTMLReportGenerator


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="SecureFlow Central DevSecOps Security Policy Engine"
    )
    parser.add_argument(
        "--config",
        "-c",
        default="security/policy_config.yaml",
        help="Path to security policy YAML configuration",
    )
    parser.add_argument(
        "--reports-dir",
        "-d",
        default="reports",
        help="Directory containing scanner JSON report files",
    )
    parser.add_argument(
        "--json-out",
        default="reports/security_summary.json",
        help="Output path for consolidated policy JSON report",
    )
    parser.add_argument(
        "--sarif-out",
        default="reports/secureflow_results.sarif",
        help="Output path for consolidated SARIF v2.1.0 report",
    )
    parser.add_argument(
        "--html-out",
        default="reports/security_report.html",
        help="Output path for HTML summary dashboard",
    )
    parser.add_argument(
        "--fail-on-block",
        action="store_true",
        default=True,
        help="Exit with non-zero code if release gate is blocked",
    )
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    engine = SecurityPolicyEngine(config_path=args.config)
    reports_dir = args.reports_dir

    # Map expected report files in reports directory
    report_files = {
        "gitleaks": os.path.join(reports_dir, "gitleaks.json"),
        "semgrep": os.path.join(reports_dir, "semgrep.json"),
        "bandit": os.path.join(reports_dir, "bandit.json"),
        "npm_audit": os.path.join(reports_dir, "npm_audit.json"),
        "pip_audit": os.path.join(reports_dir, "pip_audit.json"),
        "trivy": os.path.join(reports_dir, "trivy.json"),
        "checkov": os.path.join(reports_dir, "checkov.json"),
        "zap": os.path.join(reports_dir, "zap.json"),
    }

    result = engine.evaluate(report_files)

    os.makedirs(os.path.dirname(os.path.abspath(args.json_out)), exist_ok=True)

    # 1. Export JSON Summary
    with open(args.json_out, "w", encoding="utf-8") as f:
        json.dump(result.model_dump(), f, indent=2)

    # 2. Export SARIF
    sarif_data = SARIFExporter.export(result)
    with open(args.sarif_out, "w", encoding="utf-8") as f:
        json.dump(sarif_data, f, indent=2)

    # 3. Export HTML Dashboard
    html_content = HTMLReportGenerator.generate(result)
    with open(args.html_out, "w", encoding="utf-8") as f:
        f.write(html_content)

    print("\n" + "=" * 70)
    print(" SecureFlow DevSecOps Central Security Gate Decision")
    print("=" * 70)
    print(f" Policy: {result.policy_name}")
    print(f" Status: {'ELIGIBLE FOR RELEASE' if result.is_releasable else 'RELEASE BLOCKED'}")
    print(f" Total Findings: {result.total_findings} | Blocking: {result.blocking_findings_count} | Suppressed: {result.suppressed_findings_count}")
    print(f" Explanation: {result.summary_explanation}")
    print("=" * 70 + "\n")

    if args.fail_on_block and not result.is_releasable:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
