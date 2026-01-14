"""Schema for isautoforwarddisabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsautoforwarddisabledInput(BaseModel):
    """
    Expected input schema for the isautoforwarddisabled transformation.
    Criteria key: isautoforwarddisabled
    """

    status: Optional[str] = None
    message: Optional[str] = None
    authResponse: Optional[Any] = None

    class Config:
        extra = "allow"
