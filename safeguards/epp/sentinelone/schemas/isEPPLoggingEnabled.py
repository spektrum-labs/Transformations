from pydantic import BaseModel
from typing import Any, Dict, List, Optional


class IsEPPLoggingEnabledInput(BaseModel):
    """Input schema for the isEPPLoggingEnabled transformation.

    Expects the getAgents API response shape with a 'data' list of agent
    records (each containing an 'activeProtection' array) and a 'pagination'
    object with 'totalItems'.
    """

    class Config:
        extra = "allow"
