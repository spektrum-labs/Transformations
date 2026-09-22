from pydantic import BaseModel
from typing import Any, Dict, List, Optional


class RequiredCoveragePercentageInput(BaseModel):
    """
    Input schema for the requiredCoveragePercentage transformation.
    Represents the aggregated getEndpoints response from Red Canary (all pages via follow=true).
    """
    data: Optional[List[Any]] = None
    meta: Optional[Dict[str, Any]] = None

    class Config:
        extra = "allow"
