from pydantic import BaseModel
from typing import Any, Dict, List, Optional


class IsAntiPhishingEnabledInput(BaseModel):
    """Input schema for the isAntiPhishingEnabled transformation.

    Expects the raw getAccount response envelope with a top-level 'data'
    array containing account objects that include a 'packages' list of
    licensed product strings.
    """

    fail: Optional[List[Any]] = None
    meta: Optional[Dict[str, Any]] = None
    data: Optional[List[Dict[str, Any]]] = None

    class Config:
        extra = "allow"
