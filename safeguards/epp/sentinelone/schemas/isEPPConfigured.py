from pydantic import BaseModel
from typing import Any, Dict, List, Optional


class IsEPPConfiguredInput(BaseModel):
    """Input schema for the isEPPConfigured transformation.

    Expects a SentinelOne getAgents response envelope with a data list
    of agent records and a pagination object.
    """

    class Config:
        extra = "allow"
