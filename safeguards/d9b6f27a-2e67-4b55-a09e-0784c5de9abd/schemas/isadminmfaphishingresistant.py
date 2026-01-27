"""Schema for isadminmfaphishingresistant transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsadminmfaphishingresistantInput(BaseModel):
    """
    Expected input schema for the isadminmfaphishingresistant transformation.
    Criteria key: isadminmfaphishingresistant
    """

    status: Optional[str] = None
    message: Optional[str] = None
    authResponse: Optional[Any] = None

    class Config:
        extra = "allow"
