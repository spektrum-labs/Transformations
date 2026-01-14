"""Schema for ismfaenforcedforusers transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsmfaenforcedforusersInput(BaseModel):
    """
    Expected input schema for the ismfaenforcedforusers transformation.
    Criteria key: ismfaenforcedforusers
    """

    status: Optional[str] = None
    message: Optional[str] = None
    authResponse: Optional[Any] = None

    class Config:
        extra = "allow"
