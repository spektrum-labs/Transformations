from pydantic import BaseModel
from typing import Any, Dict, List, Optional


class IsEPPConfiguredInput(BaseModel):
    """Input schema for the isEPPConfigured transformation.

    Expects a SentinelOne getAgents response envelope with:
      - data: list of agent records (each may contain mitigationMode, scanStatus, userActionsNeeded)
      - pagination: object with totalItems integer
    """

    class Config:
        extra = "allow"
