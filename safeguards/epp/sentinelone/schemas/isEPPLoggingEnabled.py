from pydantic import BaseModel
from typing import Any, Dict, List, Optional


class IsEPPLoggingEnabledInput(BaseModel):
    """Input schema for the isEPPLoggingEnabled transformation.

    Expects the SentinelOne getAgents response shape:
      - data: list of agent records, each with an activeProtection array
      - pagination: object with totalItems integer
    """

    data: Optional[List[Dict[str, Any]]] = None
    pagination: Optional[Dict[str, Any]] = None

    class Config:
        extra = "allow"
