"""Core security analysis logic for Python microservice."""
import hashlib
import uuid
from typing import List
from app.models import (
    AnalyzeRequest,
    AnalyzeResponse,
    ArtifactType,
    RiskLevel,
    SecurityFinding,
)


def evaluate_security_target(request: AnalyzeRequest) -> AnalyzeResponse:
    """Evaluate target against built-in baseline security hygiene rules."""
    findings: List[SecurityFinding] = []
    params = request.parameters or {}

    # Rule 1: Check for debug flags in production
    if request.environment.lower() == "production" and params.get("debug") is True:
        findings.append(
            SecurityFinding(
                rule_id="AO-PY-001",
                title="Debug Mode Active in Production Environment",
                severity=RiskLevel.HIGH,
                description="Debug configuration flag detected in production environment request.",
                remediation="Disable debug mode in production configurations.",
            )
        )

    # Rule 2: Container image running as root or untagged
    if request.artifact_type == ArtifactType.CONTAINER_IMAGE:
        if params.get("run_as_root") is True or params.get("user") in ("0", "root", 0):
            findings.append(
                SecurityFinding(
                    rule_id="AO-PY-002",
                    title="Container Configured to Run as Root",
                    severity=RiskLevel.HIGH,
                    description="Container image specified UID 0 or root execution context.",
                    remediation="Add USER directive with non-root UID (e.g., 10001) in Dockerfile.",
                )
            )
        if ":latest" in request.target_name or ":" not in request.target_name:
            findings.append(
                SecurityFinding(
                    rule_id="AO-PY-003",
                    title="Floating or Implicit 'latest' Image Tag",
                    severity=RiskLevel.MEDIUM,
                    description="Container image uses an unpinned tag, risking non-reproducible builds.",
                    remediation="Pin container image reference to explicit immutable digest or version tag.",
                )
            )

    # Rule 3: Configuration plaintext secret indicators
    if request.artifact_type == ArtifactType.CONFIGURATION:
        for key in params.keys():
            lower_k = key.lower()
            if any(secret_term in lower_k for secret_term in ("secret", "password", "token", "apikey")):
                findings.append(
                    SecurityFinding(
                        rule_id="AO-PY-004",
                        title="Potential Sensitive Key in Plaintext Configuration",
                        severity=RiskLevel.CRITICAL,
                        description=f"Configuration parameter '{key}' suggests plaintext credential storage.",
                        remediation="Store secrets in a dedicated vault and inject via secret manager.",
                    )
                )

    # Determine aggregated risk level
    if any(f.severity == RiskLevel.CRITICAL for f in findings):
        aggregate_risk = RiskLevel.CRITICAL
        is_releasable = False
    elif any(f.severity == RiskLevel.HIGH for f in findings):
        aggregate_risk = RiskLevel.HIGH
        is_releasable = False
    elif any(f.severity == RiskLevel.MEDIUM for f in findings):
        aggregate_risk = RiskLevel.MEDIUM
        is_releasable = True
    elif any(f.severity == RiskLevel.LOW for f in findings):
        aggregate_risk = RiskLevel.LOW
        is_releasable = True
    else:
        aggregate_risk = RiskLevel.CLEAN
        is_releasable = True

    # Deterministic or unique analysis ID
    analysis_id = str(uuid.uuid4())

    return AnalyzeResponse(
        analysis_id=analysis_id,
        target_name=request.target_name,
        artifact_type=request.artifact_type,
        environment=request.environment,
        risk_level=aggregate_risk,
        is_releasable=is_releasable,
        findings_count=len(findings),
        findings=findings,
    )
