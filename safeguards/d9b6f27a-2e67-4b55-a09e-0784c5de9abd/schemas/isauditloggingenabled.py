"""Schema for isauditloggingenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsauditloggingenabledInput(BaseModel):
    """
    Expected input schema for the isauditloggingenabled transformation.
    Criteria key: isauditloggingenabled
    """

    status: Optional[str] = None
    message: Optional[str] = None
    authResponse: Optional[Any] = None

    class Config:
        extra = "allow"
