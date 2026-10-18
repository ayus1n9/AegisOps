"""HTML security dashboard report generator."""
import html
from security.policy.models import Decision, PolicyResult, Severity


class HTMLReportGenerator:
    """Generates standalone responsive HTML summary dashboard."""

    @staticmethod
    def generate(result: PolicyResult) -> str:
        status_bg = "#10b981" if result.is_releasable else "#ef4444"
        status_text = "RELEASE ELIGIBLE" if result.is_releasable else "RELEASE BLOCKED"

        rows = []
        for f in result.all_findings:
            sev_color = {
                Severity.CRITICAL: "#ef4444",
                Severity.HIGH: "#f97316",
                Severity.MEDIUM: "#eab308",
                Severity.LOW: "#3b82f6",
                Severity.INFO: "#64748b",
                Severity.UNKNOWN: "#a855f7",
            }.get(f.severity, "#64748b")

            dec_badge = {
                Decision.BLOCK: '<span style="background:#7f1d1d;color:#fca5a5;padding:2px 8px;border-radius:4px;font-weight:600;">BLOCK</span>',
                Decision.WARN: '<span style="background:#713f12;color:#fde047;padding:2px 8px;border-radius:4px;font-weight:600;">WARN</span>',
                Decision.ALLOW: '<span style="background:#064e3b;color:#6ee7b7;padding:2px 8px;border-radius:4px;font-weight:600;">ALLOW</span>',
                Decision.SUPPRESSED: '<span style="background:#1e293b;color:#94a3b8;padding:2px 8px;border-radius:4px;font-weight:600;">SUPPRESSED</span>',
            }.get(f.decision, "")

            loc_str = html.escape(f"{f.location.file_path or f.location.package_name or '-'}:{f.location.start_line or ''}")
            row = f"""
            <tr style="border-bottom: 1px solid #334155;">
                <td style="padding: 10px; font-weight:600; color:{sev_color};">{f.severity.value}</td>
                <td style="padding: 10px;">{dec_badge}</td>
                <td style="padding: 10px; font-family:monospace; font-size:12px;">{html.escape(f.scanner)}</td>
                <td style="padding: 10px; font-family:monospace; font-size:12px;">{html.escape(f.rule_id)}</td>
                <td style="padding: 10px; font-weight:500;">{html.escape(f.title)}</td>
                <td style="padding: 10px; font-size:12px; color:#cbd5e1;">{loc_str}</td>
                <td style="padding: 10px; font-size:12px; color:#94a3b8;">{html.escape(f.remediation[:120])}</td>
            </tr>
            """
            rows.append(row)

        scanner_rows = []
        for s in result.scanners:
            st_color = "#10b981" if s.status.value == "SUCCESS" else "#ef4444"
            scanner_rows.append(f"""
            <tr style="border-bottom: 1px solid #334155;">
                <td style="padding: 8px; font-weight:600;">{html.escape(s.scanner_name)}</td>
                <td style="padding: 8px; color:{st_color}; font-weight:bold;">{s.status.value}</td>
                <td style="padding: 8px;">{s.findings_count}</td>
                <td style="padding: 8px; font-size:12px; color:#94a3b8;">{html.escape(s.error_message or 'OK')}</td>
            </tr>
            """)

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SecureFlow Security Gate Report</title>
    <style>
        body {{ margin: 0; padding: 2rem; background-color: #0f172a; color: #f8fafc; font-family: system-ui, -apple-system, sans-serif; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #334155; padding-bottom: 1rem; margin-bottom: 2rem; }}
        .badge {{ background-color: {status_bg}; color: #fff; padding: 0.5rem 1.25rem; border-radius: 9999px; font-weight: bold; font-size: 1rem; letter-spacing: 0.05em; }}
        .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
        .card {{ background-color: #1e293b; padding: 1.25rem; border-radius: 0.5rem; border: 1px solid #334155; }}
        .card-num {{ font-size: 1.75rem; font-weight: bold; margin-top: 0.25rem; }}
        table {{ width: 100%; border-collapse: collapse; text-align: left; background-color: #1e293b; border-radius: 0.5rem; overflow: hidden; margin-bottom: 2rem; }}
        th {{ background-color: #0f172a; padding: 12px 10px; font-size: 13px; text-transform: uppercase; color: #94a3b8; border-bottom: 2px solid #334155; }}
        .banner {{ background-color: #1e293b; border-left: 4px solid {status_bg}; padding: 1rem 1.5rem; border-radius: 0.375rem; margin-bottom: 2rem; font-size: 1.05rem; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1 style="margin:0; font-size: 1.75rem;">SecureFlow DevSecOps Security Gate</h1>
                <p style="margin:4px 0 0 0; color:#94a3b8;">Policy: {html.escape(result.policy_name)} | Evaluated: {result.evaluated_at}</p>
            </div>
            <div>
                <span class="badge">{status_text}</span>
            </div>
        </div>

        <div class="banner">
            <strong>Decision Explanation:</strong> {html.escape(result.summary_explanation)}
        </div>

        <div class="cards">
            <div class="card">
                <div style="color:#94a3b8; font-size:12px;">TOTAL FINDINGS</div>
                <div class="card-num" style="color:#38bdf8;">{result.total_findings}</div>
            </div>
            <div class="card">
                <div style="color:#94a3b8; font-size:12px;">CRITICAL</div>
                <div class="card-num" style="color:#ef4444;">{result.findings_by_severity.get('CRITICAL', 0)}</div>
            </div>
            <div class="card">
                <div style="color:#94a3b8; font-size:12px;">HIGH</div>
                <div class="card-num" style="color:#f97316;">{result.findings_by_severity.get('HIGH', 0)}</div>
            </div>
            <div class="card">
                <div style="color:#94a3b8; font-size:12px;">MEDIUM</div>
                <div class="card-num" style="color:#eab308;">{result.findings_by_severity.get('MEDIUM', 0)}</div>
            </div>
            <div class="card">
                <div style="color:#94a3b8; font-size:12px;">BLOCKING (GATE)</div>
                <div class="card-num" style="color:#ef4444;">{result.blocking_findings_count}</div>
            </div>
            <div class="card">
                <div style="color:#94a3b8; font-size:12px;">SUPPRESSED</div>
                <div class="card-num" style="color:#a855f7;">{result.suppressed_findings_count}</div>
            </div>
        </div>

        <h2 style="font-size: 1.25rem;">Scanner Execution Status</h2>
        <table>
            <thead>
                <tr>
                    <th>Scanner</th>
                    <th>Status</th>
                    <th>Findings</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
                {''.join(scanner_rows)}
            </tbody>
        </table>

        <h2 style="font-size: 1.25rem;">Normalized Findings Details ({len(result.all_findings)})</h2>
        <table>
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Gate</th>
                    <th>Scanner</th>
                    <th>Rule ID</th>
                    <th>Title</th>
                    <th>Location</th>
                    <th>Remediation</th>
                </tr>
            </thead>
            <tbody>
                {''.join(rows) if rows else '<tr><td colspan="7" style="padding:20px;text-align:center;color:#94a3b8;">Zero security findings recorded across all scanners.</td></tr>'}
            </tbody>
        </table>
    </div>
</body>
</html>
"""
        return html_content
