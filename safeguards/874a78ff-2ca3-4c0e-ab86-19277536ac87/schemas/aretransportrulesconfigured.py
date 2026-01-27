"""Schema for aretransportrulesconfigured transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AretransportrulesconfiguredInput(BaseModel):
    """
    Expected input schema for the aretransportrulesconfigured transformation.
    Criteria key: aretransportrulesconfigured
    """

    status: Optional[str] = None
    message: Optional[str] = None
    authResponse: Optional[Any] = None

    class Config:
        extra = "allow"
