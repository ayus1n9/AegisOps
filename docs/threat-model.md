# AegisOps Threat Model & STRIDE Risk Assessment

## 1. Overview & Methodology

This document details the threat model for the AegisOps application stack and DevSecOps security pipeline. The evaluation follows the **STRIDE** methodology (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) and analyzes threats across both runtime application components and build-time CI/CD workflows.

---

## 2. In-Depth Threat Matrix (16 Vectors)

### Threat 1: Accidental Secret Exposure
- **Asset**: API keys, signing keys, cloud tokens, database credentials.
- **Threat Scenario**: Developer inadvertently commits a configuration file, `.env`, or test fixture containing production or personal access tokens into Git history.
- **Impact**: Full compromise of downstream cloud infrastructure or backend services.
- **Mitigation Implemented**: Versioned `.gitleaks.toml` configuration integrated into pre-commit and CI; strictly scoped allowlists for test fixtures; Gitignore excludes `.env` and `*.key`.
- **Verification Method**: Automated scanner tests verify detection of synthetic secrets (`tests/test_parsers.py::test_gitleaks_parser_finding_and_secret_redaction`).
- **Remaining Limitations**: Gitleaks cannot detect custom, low-entropy proprietary tokens without bespoke regex rules.

### Threat 2: Vulnerable Third-Party Dependencies (SCA)
- **Asset**: Node.js and Python runtime dependencies in `frontend/`, `services/api/`, `services/python-service/`.
- **Threat Scenario**: A vulnerable direct or transitive dependency containing a published CVE (e.g. Prototype Pollution, RCE) is imported.
- **Impact**: Application exploitation, remote code execution, or data theft.
- **Mitigation Implemented**: Multi-tier SCA auditing with `npm audit` and `pip-audit` validating against GitHub Advisory Database and PyPI vulnerability database.
- **Verification Method**: Central Policy Engine blocks release on critical SCA advisories (`test_parsers.py::test_npm_audit_parser`, `test_npm_audit_finding`).
- **Remaining Limitations**: Zero-day vulnerabilities not yet cataloged in CVE/GHSA databases cannot be detected by SCA tools.

### Threat 3: Malicious Pull Requests
- **Asset**: GitHub Actions CI runner, secrets, and repository integrity.
- **Threat Scenario**: An untrusted external contributor submits a pull request containing malicious build scripts or payload injection.
- **Impact**: Exfiltration of repository secrets or unauthorized execution in the GitHub Actions context.
- **Mitigation Implemented**: Workflow triggers restricted to `pull_request` (not `pull_request_target`); `permissions: { contents: read }` default; zero secret exposure to forked pull requests.
- **Verification Method**: GitHub Actions workflow syntax and permission boundary validation.
- **Remaining Limitations**: Reviewer vigilance is required before approving workflows on first-time external contributors.

### Threat 4: Dependency Confusion & Supply Chain Tampering
- **Asset**: Internal package names and package registry resolution.
- **Threat Scenario**: Attacker publishes a malicious package with the same name as an internal library to a public registry (npm/PyPI).
- **Impact**: Automatic installation of attacker-controlled code during `npm install` or `pip install`.
- **Mitigation Implemented**: Scoped packages; strict lockfiles (`package-lock.json`, exact version pins); pinned Python requirements with hashes where applicable.
- **Verification Method**: `npm ci` and pinned pip dependency installations.
- **Remaining Limitations**: Public registry typosquatting requires continuous developer awareness.

### Threat 5: Compromised GitHub Actions Dependencies
- **Asset**: CI/CD execution pipeline.
- **Threat Scenario**: A third-party action tag (e.g. `@v4`) is updated upstream to point to a compromised commit by an attacker who hijacked the action author's account.
- **Impact**: Full pipeline compromise, malicious artifact modification, credential harvesting.
- **Mitigation Implemented**: All third-party actions in `.github/workflows/security-pipeline.yml` are pinned to immutable 40-character commit SHAs with version comments.
- **Verification Method**: Automated regex audit verifying commit SHA pinning across all workflow `uses:` statements.
- **Remaining Limitations**: Action pinning requires manual or automated maintenance (e.g., Dependabot) to incorporate upstream security patches.

### Threat 6: Insecure Container Configurations
- **Asset**: Host operating system, container runtime kernel.
- **Threat Scenario**: Container runs as `root` (UID 0), mounts host sockets, or runs with full Linux capabilities, enabling container escape.
- **Impact**: Host takeover from within a compromised container.
- **Mitigation Implemented**: Multi-stage builds running as dedicated non-root users (`nginx` 101, `node` 1000, `appuser` 10001); `compose.yaml` enforces `read_only: true`, `cap_drop: [ALL]`, and `security_opt: [no-new-privileges:true]`.
- **Verification Method**: Non-root UID verification commands; Checkov IaC scans (`test_parsers.py::test_checkov_parser`).
- **Remaining Limitations**: Ephemeral `tmpfs` mounts remain writable to satisfy application logging/temp requirements.

### Threat 7: API Input Validation Failures & Path Traversal
- **Asset**: API Gateway and Python analytics microservice.
- **Threat Scenario**: Attacker injects path traversal sequences (`../../etc/passwd`) or arbitrary parameters into API request payloads.
- **Impact**: Arbitrary file access or unhandled server crashes.
- **Mitigation Implemented**: Strict Zod schema validation in Node API; Pydantic regex validators in FastAPI rejecting traversal sequences (`..`, `/`, `\`); safe error handling.
- **Verification Method**: Unit tests `test_analyze_endpoint_invalid_target_name_injection` and `api.test.ts::reject path traversal`.
- **Remaining Limitations**: Business logic flaws can still occur if parameters pass schema syntax checks.

### Threat 8: Cross-Origin Request Risks (CORS & CSP)
- **Asset**: Client browser session, API endpoints.
- **Threat Scenario**: Malicious website makes unauthorized cross-origin requests to the API or executes injected scripts in the user's browser.
- **Impact**: Cross-Site Scripting (XSS), cross-origin data theft, session hijacking.
- **Mitigation Implemented**: Helmet middleware with restrictive CSP directives; explicit `cors` origin whitelist (`http://localhost:3000`); React avoidance of `dangerouslySetInnerHTML`.
- **Verification Method**: Supertest verification of Helmet headers; OWASP ZAP baseline scan.
- **Remaining Limitations**: If CORS origin is misconfigured to `*` in development, cross-origin protection is degraded.

### Threat 9: Unauthorized Access to CI Artifacts
- **Asset**: Scanner reports, SARIF files, build artifacts.
- **Threat Scenario**: Sensitive source code fragments or credentials leak into build artifacts downloaded by unauthenticated users.
- **Impact**: Information disclosure to unauthorized repository viewers.
- **Mitigation Implemented**: Gitleaks parser redacts matched secret text from all evidence strings; ephemeral reports expire according to GitHub retention policies.
- **Verification Method**: Verification test `test_gitleaks_parser_finding_and_secret_redaction` asserts redaction.
- **Remaining Limitations**: Developers must ensure stack traces are suppressed in test output.

### Threat 10: Untrusted Scanner Output Injection
- **Asset**: Central Security Policy Engine.
- **Threat Scenario**: Scanner emits crafted control characters or HTML markup in vulnerability titles, leading to HTML injection or parser confusion in the dashboard.
- **Impact**: Stored XSS in the generated security report or policy engine crash.
- **Mitigation Implemented**: The HTML report exporter enforces strict `html.escape()` sanitization across all titles, rules, locations, and evidence fields.
- **Verification Method**: HTML exporter unit test verifies escaped output (`test_exporters.py`).
- **Remaining Limitations**: Exporters must be updated whenever new output formats are introduced.

### Threat 11: Report-Parser Failures & Crashes
- **Asset**: Security gate availability and reliability.
- **Threat Scenario**: Scanner crashes, outputs malformed JSON, or produces unexpected schema structures, causing the policy engine to throw an unhandled exception.
- **Impact**: Denial of service in the CI pipeline or false-green bypass if errors are swallowed.
- **Mitigation Implemented**: Safe JSON loader with dedicated exception handling for `JSONDecodeError`, empty files, and scanner error status records.
- **Verification Method**: Unit tests `test_empty_json_report_handled_safely` and `test_malformed_json_report_fails_closed`.
- **Remaining Limitations**: Upstream scanner major schema changes require updating parser models.

### Threat 12: Security-Gate Bypasses
- **Asset**: Release certification gate.
- **Threat Scenario**: Developer deletes a scanner report file or disables a scanner CLI to force a green pipeline status.
- **Impact**: Vulnerable code shipped to production undetected.
- **Mitigation Implemented**: **Fail-Closed Architecture**: Missing required reports or scanner execution errors are explicitly classified as blocking conditions (`is_releasable = False`).
- **Verification Method**: Unit tests `test_engine_fail_closed_on_missing_required_report` and `test_engine_fail_closed_on_scanner_execution_error`.
- **Remaining Limitations**: Repository administrators with branch protection bypass permissions could force-merge.

### Threat 13: False Positives & Developer Fatigue
- **Asset**: Developer productivity and team adoption.
- **Threat Scenario**: Excessive noise from uncalibrated scanners leads developers to ignore or disable security tools.
- **Impact**: Real vulnerabilities overlooked due to alert fatigue.
- **Mitigation Implemented**: Scoped, audited suppression system with mandatory expiration dates and approved rationale; severity-aware thresholding (informational checks do not block builds).
- **Verification Method**: Suppression validation tests (`test_valid_active_suppression_allows_finding`, `test_expired_suppression_is_rejected_and_blocks`).
- **Remaining Limitations**: Suppressions require periodic security review to avoid stale exceptions.

### Threat 14: Insecure Exception Handling & Information Disclosure
- **Asset**: Server internals, directory structure, runtime versions.
- **Threat Scenario**: Unhandled exception emits full Python traceback or Node.js memory state to HTTP response body.
- **Impact**: Attackers gain structural reconnaissance to plan targeted exploits.
- **Mitigation Implemented**: Central error handling middleware in Express and FastAPI catches all unhandled exceptions, logs internally, and returns sanitized generic error payloads.
- **Verification Method**: API tests verify 422 and 500 responses return clean JSON without stack traces (`test_api.py`, `api.test.ts`).
- **Remaining Limitations**: Detailed internal logs must be monitored via centralized secure logging.

### Threat 15: Compromised Build Artifacts & Image Tampering
- **Asset**: Published Docker images.
- **Threat Scenario**: Man-in-the-middle or compromised registry alters container image layers after build.
- **Impact**: Deployment of trojanized containers to production environments.
- **Mitigation Implemented**: Software Bill of Materials (SBOM) generation via Syft (CycloneDX); cryptographic artifact signing and verification via Cosign (`scripts/sign_artifacts.sh`).
- **Verification Method**: Automated verification script checks Cosign public key signature match against image manifest digest.
- **Remaining Limitations**: Keyless signing in GitHub Actions requires configuring OIDC identity federation with Sigstore.

### Threat 16: Inadequate CI/CD Token Permissions
- **Asset**: GitHub repository settings, releases, code scanning alerts.
- **Threat Scenario**: Workflow token has default `write-all` permissions; compromised dependency uses token to overwrite releases or push malicious commits.
- **Impact**: Total repository compromise.
- **Mitigation Implemented**: Top-level `permissions: { contents: read }`; elevated permission (`security-events: write`) restricted exclusively to the `upload-sarif` job.
- **Verification Method**: Workflow syntax validation and GitHub security settings inspection.
- **Remaining Limitations**: Organization admins must maintain branch protection rules requiring status checks.
