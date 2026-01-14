"""Schema for requiredcoveragepercentage transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class RequiredcoveragepercentageInput(BaseModel):
    """
    Expected input schema for the requiredcoveragepercentage transformation.
    Criteria key: requiredcoveragepercentage
    """

    apiResponse: Optional[Dict[str, Any]] = None

    class Config:
        extra = "allow"
