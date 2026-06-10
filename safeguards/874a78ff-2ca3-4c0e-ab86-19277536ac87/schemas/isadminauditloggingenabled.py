"""Schema for isadminauditloggingenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsadminauditloggingenabledInput(BaseModel):
    """
    Expected input schema for the isadminauditloggingenabled transformation.

    Mirrors the Microsoft Graph /auditLogs/directoryAudits response shape:
    a top-level `value` list of audit log records. Admin audit logging is
    considered enabled when at least one record is present.
    """

    value: Optional[List[Dict[str, Any]]] = Field(
        default=None, description="Directory audit log records returned by Microsoft Graph"
    )

    class Config:
        extra = "allow"
