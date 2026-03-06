"""Schema for isdnsfilteringenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsdnsfilteringenabledInput(BaseModel):
    """
    Expected input schema for the isdnsfilteringenabled transformation.
    Criteria key: isDNSFilteringEnabled

    Validates that DNS filtering networks are configured and active
    by checking the networks endpoint.
    """

    networks: Optional[List[Dict[str, Any]]] = None
    data: Optional[List[Dict[str, Any]]] = None

    class Config:
        extra = "allow"
