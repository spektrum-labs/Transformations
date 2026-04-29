from pydantic import BaseModel
from typing import Any, Dict, List, Optional


class IsEPPLoggingEnabledInput(BaseModel):
    """Input schema for the isEPPLoggingEnabled transformation.

    Accepts the raw getAgents API response envelope containing a paginated
    list of agent records and a pagination object with totalItems.
    """

    class Config:
        extra = "allow"
