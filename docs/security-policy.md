# SecureFlow Security Policy & Governance Specification

## 1. Governance Principles

The SecureFlow DevSecOps pipeline enforces automated, deterministic security gates. Development velocity must not come at the expense of security posture, nor should developers be overwhelmed with unprioritized alerts.

### Release Gate Criteria
A build is certified **ELIGIBLE FOR RELEASE** if and only if:
1. **Zero Confirmed Secrets**: Any verified secret or credential detected by Gitleaks immediately blocks release.
2. **Zero Unsuppressed Critical Vulnerabilities**: Findings classified as `CRITICAL` (e.g. CVSS 9.0+, critical CVEs, unauthenticated RCE) fail the build.
3. **Zero Unsuppressed High Vulnerabilities**: Findings classified as `HIGH` (e.g. injection flaws, root containers, missing security headers) fail the build under standard policy.
4. **All Required Scanners Succeeded**: The pipeline operates under a **Fail-Closed** mandate. If a required scanner fails to execute or its report is missing, the build is blocked.
5. **No Invalid or Expired Suppressions**: Any suppression referencing an expired date or invalid component is rejected and the finding remains blocking.

---

## 2. Severity Classification Matrix

| Severity | Definition | Examples | Gate Action |
| :--- | :--- | :--- | :--- |
| **CRITICAL** | Flaws permitting arbitrary code execution, total authentication bypass, or committed secrets. | Gitleaks secret match, Trivy RCE CVE in base image, npm critical advisory. | **BLOCKS RELEASE** |
| **HIGH** | Significant vulnerabilities permitting privilege escalation, command injection, or root container execution. | Bandit B602 (shell=True), Semgrep eval(), Checkov root container user. | **BLOCKS RELEASE** |
| **MEDIUM** | Misconfigurations, unpinned tags, or cryptographic weaknesses requiring specific preconditions. | Semgrep MD5/SHA1 usage, floating container tags, missing anti-CSRF tokens. | **WARN** (Blocks in Strict Mode) |
| **LOW** | Minor hygiene issues, outdated non-security dependencies, or verbose informational logs. | Minor version drift, missing non-security headers. | **ALLOW** |
| **INFO** | Informational telemetry, scanner metrics, or architectural notes. | License notices, tool performance data. | **ALLOW** |
| **UNKNOWN** | Non-standard or unmapped severity values emitted by custom tools. | Unrecognized scanner string. | **Treated as HIGH (Fail-Closed)** |

---

## 3. Vulnerability Exception (Suppression) Governance

Suppressions allow temporary, reviewed operational exceptions without disabling scanner coverage.

### Requirements for Valid Suppressions:
1. **Scoped Identifier**: Must target explicit `rule_id` and `scanner`. Broad wildcard (`*`) suppressions across all rules are rejected.
2. **Documented Rationale**: A substantive explanation of why the finding cannot be remediated immediately and why the residual risk is acceptable.
3. **Approved By**: Must record the security reviewer or team author (e.g., `AppSec-Team`).
4. **Enforced Expiration (`expires_at`)**: Every exception must define an ISO 8601 expiration date. When the date passes, the Central Security Policy Engine automatically revokes the suppression and blocks the build until renewed or remediated.
