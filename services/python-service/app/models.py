"""Data models for SecureFlow Python Security Service."""
import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator


class ArtifactType(str, Enum):
    CONTAINER_IMAGE = "container_image"
    SOURCE_CODE = "source_code"
    CONFIGURATION = "configuration"


class RiskLevel(str, Enum):
    CLEAN = "CLEAN"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AnalyzeRequest(BaseModel):
    target_name: str = Field(
        ...,
        min_length=1,
        max_length=120,
        description="Target identifier (e.g. repo name or image name)",
    )
    artifact_type: ArtifactType = Field(
        ..., description="Type of artifact being evaluated"
    )
    environment: str = Field(
        default="production",
        pattern=r"^[a-zA-Z0-9_\-\.]{1,32}$",
        description="Deployment environment name",
    )
    parameters: Optional[Dict[str, Any]] = Field(
        default_factory=dict,
        description="Additional evaluation parameters",
    )

    @field_validator("target_name")
    @classmethod
    def validate_target_name(cls, value: str) -> str:
        # Prevent path traversal characters and command injection sequences
        if ".." in value or "/" in value or "\\" in value or ";" in value or "|" in value or "&" in value:
            raise ValueError("target_name contains disallowed characters")
        if not re.match(r"^[a-zA-Z0-9_\-\.:]+$", value):
            raise ValueError("target_name must contain only alphanumeric, dash, dot, or underscore")
        return value.strip()


class SecurityFinding(BaseModel):
    rule_id: str
    title: str
    severity: RiskLevel
    description: str
    remediation: str


class AnalyzeResponse(BaseModel):
    analysis_id: str
    target_name: str
    artifact_type: ArtifactType
    environment: str
    risk_level: RiskLevel
    is_releasable: bool
    findings_count: int
    findings: List[SecurityFinding]
    evaluated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
