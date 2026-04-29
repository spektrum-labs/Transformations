from pydantic import BaseModel
from typing import Any, Dict, List, Optional


class IsEPPEnabledInput(BaseModel):
    """Input schema for the isEPPEnabled transformation.

    Expects the raw SentinelOne GET /web/api/v2.1/agents response shape,
    with a top-level 'data' list of agent records and a 'pagination' object
    containing 'totalItems' (fleet-wide enrolled agent count).
    """

    data: Optional[List[Dict[str, Any]]] = None
    pagination: Optional[Dict[str, Any]] = None

    class Config:
        extra = "allow"
