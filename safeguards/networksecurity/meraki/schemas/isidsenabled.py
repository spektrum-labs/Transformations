"""Schema for isidsenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsidsenabledInput(BaseModel):
    """
    Expected input schema for the isidsenabled transformation.
    Criteria key: isIDSEnabled
    """

    mode: Optional[str] = None

    class Config:
        extra = "allow"
