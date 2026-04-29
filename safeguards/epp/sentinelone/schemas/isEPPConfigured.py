from pydantic import BaseModel
from typing import Any, Dict, List, Optional


class IsEPPConfiguredInput(BaseModel):
    """Input schema for the isEPPConfigured transformation.

    Expects the raw getAgents response shape:
      data: list of agent records (each with mitigationMode, activeProtection, etc.)
      pagination: object with totalItems
    """

    data: Optional[List[Dict[str, Any]]] = None
    pagination: Optional[Dict[str, Any]] = None

    class Config:
        extra = "allow"
