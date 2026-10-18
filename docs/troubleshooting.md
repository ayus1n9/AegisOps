# SecureFlow Troubleshooting & Operational Playbook

## 1. Common Pipeline Failures & Resolutions

### Scenario A: Gitleaks Reports Secret Finding
- **Symptom**: Pipeline fails at `scan-secrets` or `policy-gate` with `Release BLOCKED: Confirmed secret finding detected`.
- **Diagnosis**: Gitleaks identified a pattern resembling an API token, private key, or credential.
- **Resolution**:
  1. Inspect the finding location in `reports/gitleaks.json`.
  2. If the secret is real: **Immediately revoke and rotate the credential**. Remove from Git history using `git-filter-repo` or BFG Repo-Cleaner. Never simply commit a deletion.
  3. If the secret is a false positive in a test fixture: Verify that the path is listed in the narrow allowlist in `.gitleaks.toml`.

### Scenario B: Trivy Detects Vulnerable Base Image CVE
- **Symptom**: Pipeline blocks at `container-build-scan` with a CRITICAL or HIGH operating system vulnerability.
- **Resolution**:
  1. Inspect the affected package in `reports/trivy.json`.
  2. Update the base image version in the corresponding Dockerfile (e.g. `node:22-alpine` or `python:3.12-slim`).
  3. Rebuild with `make build` and rescan with `make scan-container`.

### Scenario C: Ephemeral DAST Times Out Waiting for Service Readiness
- **Symptom**: `scan-dast` fails because `curl -sf http://localhost:8000/health` times out.
- **Diagnosis**: One of the containers in Docker Compose failed health checks or crashed on startup.
- **Resolution**:
  1. Run `docker compose ps` locally to identify the unready container.
  2. Inspect container logs with `docker compose logs <service>`.
  3. Verify port allocations (ensure ports 3000 and 8000 are not occupied by host processes).

### Scenario D: Expired Suppression Blocks Release
- **Symptom**: Policy engine reports `Release BLOCKED` on an expected exception.
- **Diagnosis**: The `expires_at` date in `security/policy_config.yaml` has passed.
- **Resolution**:
  1. Re-evaluate whether the underlying issue can be permanently remediated.
  2. If an extension is justified, submit a reviewed PR updating the expiration date and rationale.
