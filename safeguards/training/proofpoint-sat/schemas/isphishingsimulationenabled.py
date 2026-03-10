"""Schema for isphishingsimulationenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsphishingsimulationenabledInput(BaseModel):
    """
    Expected input schema for the isphishingsimulationenabled transformation.
    Criteria key: isPhishingSimulationEnabled

    Validates that phishing simulation campaigns exist and at least one
    has been launched in Proofpoint SAT.
    """

    campaigns: Optional[List[Dict[str, Any]]] = Field(None, description="List of phishing simulation campaign objects")
    total_records: Optional[int] = Field(None, description="Total number of phishing simulation records")
    data: Optional[List[Dict[str, Any]]] = Field(None, description="Generic data wrapper for campaign records")

    class Config:
        extra = "allow"
