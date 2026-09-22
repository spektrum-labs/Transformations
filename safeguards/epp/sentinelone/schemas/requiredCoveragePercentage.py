from pydantic import BaseModel
from typing import Any, Dict, List, Optional


class RequiredCoveragePercentageInput(BaseModel):
    """Input schema for the requiredCoveragePercentage transformation.

    Expects the fully-paginated SentinelOne getAgents response with all
    agent records aggregated into data[].
    """

    data: Optional[List[Dict[str, Any]]] = None
    pagination: Optional[Dict[str, Any]] = None

    class Config:
        extra = "allow"
