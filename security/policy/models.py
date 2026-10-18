"""Normalized data models for SecureFlow Central Security Policy Engine."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def from_str(cls, val: Any) -> Severity:
        if not val or not isinstance(val, (str, int)):
            return cls.UNKNOWN
        s = str(val).strip().upper()
        mapping = {
            "CRITICAL": cls.CRITICAL,
            "CRIT": cls.CRITICAL,
            "HIGH": cls.HIGH,
            "ERROR": cls.HIGH,
            "3": cls.HIGH,          # ZAP riskcode 3 = High
            "MEDIUM": cls.MEDIUM,
            "MODERATE": cls.MEDIUM,
            "WARNING": cls.MEDIUM,
            "WARN": cls.MEDIUM,
            "2": cls.MEDIUM,        # ZAP riskcode 2 = Medium
            "LOW": cls.LOW,
            "1": cls.LOW,           # ZAP riskcode 1 = Low
            "INFO": cls.INFO,
            "INFORMATIONAL": cls.INFO,
            "0": cls.INFO,          # ZAP riskcode 0 = Informational
        }
        return mapping.get(s, cls.UNKNOWN)


class Decision(str, Enum):
    BLOCK = "BLOCK"
    WARN = "WARN"
    ALLOW = "ALLOW"
    SUPPRESSED = "SUPPRESSED"


class ScannerExecutionStatus(str, Enum):
    SUCCESS = "SUCCESS"
    SCANNER_ERROR = "SCANNER_ERROR"
    MISSING_REPORT = "MISSING_REPORT"
    MALFORMED_OUTPUT = "MALFORMED_OUTPUT"


class SuppressionRecord(BaseModel):
    id: str
    scanner: str
    rule_id: str
    component: str
    reason: str
    approved_by: str
    expires_at: Optional[str] = None


class FindingLocation(BaseModel):
    file_path: Optional[str] = None
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    package_name: Optional[str] = None
    package_version: Optional[str] = None


class Finding(BaseModel):
    finding_id: str = Field(default="")
    scanner: str
    rule_id: str
    title: str
    severity: Severity
    component: str
    location: FindingLocation = Field(default_factory=FindingLocation)
    remediation: str = ""
    evidence: str = ""
    is_secret: bool = False
    decision: Decision = Decision.ALLOW
    suppression: Optional[SuppressionRecord] = None

    def compute_deterministic_id(self) -> str:
        """Compute stable SHA-256 hash identifying the unique finding instance."""
        loc_str = f"{self.location.file_path}:{self.location.start_line}:{self.location.package_name}"
        raw = f"{self.scanner}|{self.rule_id}|{self.component}|{loc_str}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def model_post_init(self, __context: Any) -> None:
        if not self.finding_id:
            self.finding_id = self.compute_deterministic_id()


class ScannerExecution(BaseModel):
    scanner_name: str
    status: ScannerExecutionStatus
    report_path: Optional[str] = None
    error_message: Optional[str] = None
    findings_count: int = 0


class PolicyResult(BaseModel):
    is_releasable: bool
    policy_name: str
    evaluated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    total_findings: int = 0
    findings_by_severity: Dict[str, int] = Field(default_factory=dict)
    blocking_findings_count: int = 0
    suppressed_findings_count: int = 0
    blocking_findings: List[Finding] = Field(default_factory=list)
    all_findings: List[Finding] = Field(default_factory=list)
    scanners: List[ScannerExecution] = Field(default_factory=list)
    missing_required_scanners: List[str] = Field(default_factory=list)
    scanner_errors: List[str] = Field(default_factory=list)
    summary_explanation: str = ""
