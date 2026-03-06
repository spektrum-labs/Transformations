"""Schema for isphishingsimulationenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsphishingsimulationenabledInput(BaseModel):
    """
    Expected input schema for the isphishingsimulationenabled transformation.
    Criteria key: isPhishingSimulationEnabled

    Validates that phishing simulation campaigns are configured
    by checking the phishing_campaigns endpoint.
    """

    phishing_campaigns: Optional[List[Dict[str, Any]]] = None
    campaigns: Optional[List[Dict[str, Any]]] = None
    data: Optional[List[Dict[str, Any]]] = None

    class Config:
        extra = "allow"
