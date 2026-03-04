"""Schema for isauditloggingenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AuditLogEntry(BaseModel):
    """Single audit log entry from Zscaler ZIA."""

    class Config:
        extra = "allow"


class LoggingConfig(BaseModel):
    """Logging configuration settings."""

    enabled: Optional[bool] = None

    class Config:
        extra = "allow"


class IsauditloggingenabledInput(BaseModel):
    """
    Expected input schema for the isauditloggingenabled transformation.
    Criteria key: isAuditLoggingEnabled

    Checks for audit log presence, explicit logging flags, and
    logging configuration in Zscaler ZIA.
    """

    auditLogs: Optional[List[AuditLogEntry]] = None
    responseData: Optional[List[Any]] = None
    auditLoggingEnabled: Optional[bool] = None
    loggingEnabled: Optional[bool] = None
    loggingConfig: Optional[LoggingConfig] = None
    auditConfig: Optional[LoggingConfig] = None
    apiResponse: Optional[Dict[str, Any]] = None

    class Config:
        extra = "allow"
