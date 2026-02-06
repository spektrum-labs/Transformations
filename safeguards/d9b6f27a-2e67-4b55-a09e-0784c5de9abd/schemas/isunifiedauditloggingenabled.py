"""Schema for isunifiedauditloggingenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsunifiedauditloggingenabledInput(BaseModel):
    """
    Expected input schema for the isunifiedauditloggingenabled transformation.

    Note: No API response sample available. Schema structure should be
    updated based on actual API response format.
    """

    class Config:
        extra = "allow"
