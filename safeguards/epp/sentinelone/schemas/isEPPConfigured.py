from pydantic import BaseModel
from typing import Any, Dict, List, Optional


class IsEPPConfiguredInput(BaseModel):
    """Input schema for the isEPPConfigured transformation (SentinelOne getAgents response)."""

    class Config:
        extra = "allow"

    data: Optional[List[Dict[str, Any]]] = None
    pagination: Optional[Dict[str, Any]] = None
