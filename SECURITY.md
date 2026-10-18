# Security Policy

## Supported Versions

Only the latest release on the `main` branch is actively supported with security updates.

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

The AegisOps project takes vulnerability management and responsible disclosure seriously.

If you believe you have found a security vulnerability in this project:

1. **Do not open a public issue.** Publicly disclosing vulnerabilities exposes systems before remediation can take place.
2. Email the maintainer directly at `singhayush0919@gmail.com` with the subject line `[SECURITY] AegisOps Vulnerability Report`.
3. Provide a clear description of the vulnerability, including:
   - Affected component(s)
   - Step-by-step reproduction instructions or proof-of-concept
   - Potential impact
   - Any suggested mitigations

### Response SLA
- Initial acknowledgment: within 24 hours.
- Triage and severity assessment: within 48 hours.
- Fix delivery and advisory release: within 14 days (or earlier depending on CVSS severity).

## AegisOps DevSecOps Principles

All contributions undergo automated pre-commit and CI/CD validation:
- Zero committed secrets (enforced via Gitleaks)
- Zero high/critical SAST findings (enforced via Semgrep & Bandit)
- Clean dependency audits (enforced via npm audit & pip-audit)
- Container vulnerability thresholds (enforced via Trivy)
- DAST baseline scans (enforced via OWASP ZAP)
- Policy enforcement via the Central Security Policy Engine
