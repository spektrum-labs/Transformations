"""Schema for isdnsfilteringenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsdnsfilteringenabledInput(BaseModel):
    """
    Expected input schema for the isdnsfilteringenabled transformation.
    Criteria key: isDNSFilteringEnabled

    Validates DNS filtering by checking DNS records and proxy status
    from the Cloudflare API.
    """

    result: Optional[List[Dict[str, Any]]] = None
    success: Optional[bool] = None

    class Config:
        extra = "allow"
