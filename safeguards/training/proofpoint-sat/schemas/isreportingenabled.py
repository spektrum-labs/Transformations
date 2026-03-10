"""Schema for isreportingenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsreportingenabledInput(BaseModel):
    """
    Expected input schema for the isreportingenabled transformation.
    Criteria key: isReportingEnabled

    Validates that PhishAlarm reporting button data exists, indicating
    the button is deployed and active in Proofpoint SAT.
    """

    phishalarm: Optional[Dict[str, Any]] = Field(None, description="PhishAlarm reporting button configuration and status")
    reporting_enabled: Optional[bool] = Field(None, description="Whether reporting is enabled")
    data: Optional[List[Dict[str, Any]]] = Field(None, description="Generic data wrapper for reporting records")

    class Config:
        extra = "allow"
