from pydantic import BaseModel
from typing import Any, Dict, List, Optional


class IsEPPEnabledInput(BaseModel):
    """Input schema for the isEPPEnabled transformation (SentinelOne getAgents response)."""

    data: Optional[List[Dict[str, Any]]] = None
    pagination: Optional[Dict[str, Any]] = None

    class Config:
        extra = "allow"
