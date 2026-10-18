"""Base scanner parser interface and utilities."""
import abc
import json
import os
from typing import Any, List, Tuple
from security.policy.models import Finding, ScannerExecution, ScannerExecutionStatus


class BaseParser(abc.ABC):
    """Abstract base parser for security scanner report formats."""

    scanner_name: str = "generic"

    def load_json_safely(self, file_path: str) -> Tuple[Any, ScannerExecution]:
        """Load and parse JSON file with comprehensive safety and error detection."""
        if not file_path or not os.path.exists(file_path):
            return None, ScannerExecution(
                scanner_name=self.scanner_name,
                status=ScannerExecutionStatus.MISSING_REPORT,
                report_path=file_path,
                error_message=f"Required report file not found at: {file_path}",
            )

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if not content:
                    # Empty file
                    return {}, ScannerExecution(
                        scanner_name=self.scanner_name,
                        status=ScannerExecutionStatus.SUCCESS,
                        report_path=file_path,
                        findings_count=0,
                    )
                data = json.loads(content)
        except json.JSONDecodeError as err:
            return None, ScannerExecution(
                scanner_name=self.scanner_name,
                status=ScannerExecutionStatus.MALFORMED_OUTPUT,
                report_path=file_path,
                error_message=f"JSON decoding error: {str(err)}",
            )
        except Exception as err:
            return None, ScannerExecution(
                scanner_name=self.scanner_name,
                status=ScannerExecutionStatus.SCANNER_ERROR,
                report_path=file_path,
                error_message=f"Failed to read report: {str(err)}",
            )

        # Detect scanner runtime failure records
        if isinstance(data, dict):
            if data.get("status") == "error" or "error_message" in data:
                return None, ScannerExecution(
                    scanner_name=self.scanner_name,
                    status=ScannerExecutionStatus.SCANNER_ERROR,
                    report_path=file_path,
                    error_message=data.get("error_message", "Scanner reported error state"),
                )

        return data, ScannerExecution(
            scanner_name=self.scanner_name,
            status=ScannerExecutionStatus.SUCCESS,
            report_path=file_path,
        )

    @abc.abstractmethod
    def parse(self, file_path: str) -> Tuple[List[Finding], ScannerExecution]:
        """Parse raw report file into normalized Findings and execution record."""
        raise NotImplementedError
