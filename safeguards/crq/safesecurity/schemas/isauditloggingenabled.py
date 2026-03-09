"""Schema for isauditloggingenabled transformation input."""
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class AuditReportData(BaseModel):
    """Nested data object from the audit log trigger response."""

    uuid: Optional[str] = Field(None, description="UUID of the queued report generation job")

    class Config:
        extra = "allow"


class IsauditloggingenabledInput(BaseModel):
    """Expected input schema for the isauditloggingenabled transformation. Criteria key: isAuditLoggingEnabled"""

    success: Optional[bool] = Field(None, description="Whether the audit log export was successfully queued")
    message: Optional[str] = Field(None, description="Status message from the report generation request")
    data: Optional[AuditReportData] = Field(None, description="Report generation job details containing the job UUID")

    class Config:
        extra = "allow"
