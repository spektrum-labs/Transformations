from pydantic import BaseModel
from typing import Any, Dict, List, Optional


class IsEPPEnabledInput(BaseModel):
    """Input schema for the isEPPEnabled transformation.

    Expects the SentinelOne GET /web/api/v2.1/agents response envelope,
    containing a 'data' list of agent records and a 'pagination' object
    with 'totalItems' reflecting the full fleet count.
    """

    class Config:
        extra = "allow"
