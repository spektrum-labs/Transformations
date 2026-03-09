"""Schema for isbackuploggingenabled transformation input."""

from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


class AuditEvent(BaseModel):
    """Single audit trail event entry."""

    class Config:
        extra = "allow"


class IsbackuploggingenabledInput(BaseModel):
    """
    Expected input schema for the isbackuploggingenabled transformation.
    Criteria key: isBackupLoggingEnabled
    """
    auditEnabled: Optional[Union[bool, str]] = None
    isAuditEnabled: Optional[Union[bool, str]] = None
    loggingEnabled: Optional[Union[bool, str]] = None
    auditTrailList: Optional[List[AuditEvent]] = None
    events: Optional[List[AuditEvent]] = None
    auditEvents: Optional[List[AuditEvent]] = None
    items: Optional[List[AuditEvent]] = None
    totalRecords: Optional[Union[int, str]] = None
    count: Optional[Union[int, str]] = None

    class Config:
        extra = "allow"
