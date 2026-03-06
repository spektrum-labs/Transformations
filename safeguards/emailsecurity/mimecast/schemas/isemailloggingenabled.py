"""Schema for isemailloggingenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsemailloggingenabledInput(BaseModel):
    """
    Expected input schema for the isemailloggingenabled transformation.
    Criteria key: isEmailLoggingEnabled

    Checks logging status, audit log presence, and SIEM integration
    settings from Mimecast.
    """

    loggingEnabled: Optional[bool] = None
    auditEnabled: Optional[bool] = None
    enabled: Optional[bool] = None
    state: Optional[str] = None
    status: Optional[str] = None
    logs: Optional[List[Dict[str, Any]]] = None
    auditLog: Optional[Any] = None

    class Config:
        extra = "allow"
