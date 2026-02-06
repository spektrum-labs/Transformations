"""Schema for areconditionalaccesspoliciesconfigured transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AreconditionalaccesspoliciesconfiguredInput(BaseModel):
    """
    Expected input schema for the areconditionalaccesspoliciesconfigured transformation.
    Criteria key: areconditionalaccesspoliciesconfigured
    """

    status: Optional[str] = None
    message: Optional[str] = None
    authResponse: Optional[Any] = None

    class Config:
        extra = "allow"
