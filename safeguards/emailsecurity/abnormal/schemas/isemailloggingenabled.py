"""Schema for isemailloggingenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AuditLoggingSettings(BaseModel):
    """Audit logging configuration."""

    enabled: Optional[bool] = None

    class Config:
        extra = "allow"


class IsemailloggingenabledInput(BaseModel):
    """
    Expected input schema for the isemailloggingenabled transformation.
    Criteria key: isEmailLoggingEnabled

    Checks for audit logs presence, paginated log responses, or
    logging configuration settings from Abnormal Security.
    """

    auditLogs: Optional[List[Dict[str, Any]]] = None
    results: Optional[List[Dict[str, Any]]] = None
    logs: Optional[List[Dict[str, Any]]] = None
    total_count: Optional[int] = None
    pageNumber: Optional[int] = None
    settings: Optional[Dict[str, Any]] = None

    class Config:
        extra = "allow"
