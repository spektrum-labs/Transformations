"""Schema for isipsenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsipsenabledInput(BaseModel):
    """
    Expected input schema for the isipsenabled transformation.
    Criteria key: isIPSEnabled
    """

    mode: Optional[str] = None

    class Config:
        extra = "allow"
