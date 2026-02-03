"""Schema for ismfaenforcedforusers transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsmfaenforcedforusersInput(BaseModel):
    """
    Expected input schema for the ismfaenforcedforusers transformation.
    Criteria key: ismfaenforcedforusers
    """

    apiResponse: Optional[Dict[str, Any]] = None

    class Config:
        extra = "allow"
