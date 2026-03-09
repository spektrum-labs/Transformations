"""Schema for isauditloggingenabled transformation input."""
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class AuditLogRecord(BaseModel):
    """Individual audit log record from Britive /api/v1/audit-logs."""
    eventId: Optional[str] = Field(None, description="Unique event identifier")
    timestamp: Optional[str] = Field(None, description="ISO timestamp of the event")
    eventTime: Optional[str] = Field(None, description="Alternate timestamp field")
    actor: Optional[Dict[str, Any]] = Field(None, description="Actor who performed the action")
    target: Optional[Dict[str, Any]] = Field(None, description="Target of the action")
    action: Optional[str] = Field(None, description="Action that was performed")
    result: Optional[str] = Field(None, description="Result of the action (success/failure)")

    class Config:
        extra = "allow"


class IsauditloggingenabledInput(BaseModel):
    """Expected input schema for the isauditloggingenabled transformation. Criteria key: isAuditLoggingEnabled"""
    totalCount: Optional[int] = Field(None, description="Total number of audit log records")
    count: Optional[int] = Field(None, description="Alternate count field")
    data: Optional[List[AuditLogRecord]] = Field(None, description="List of audit log records")
    records: Optional[List[AuditLogRecord]] = Field(None, description="Alternate list of audit log records")
    auditLogs: Optional[List[AuditLogRecord]] = Field(None, description="Alternate list of audit log records")

    class Config:
        extra = "allow"
