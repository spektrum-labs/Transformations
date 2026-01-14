"""Schema for ismailboxauditloggingenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsmailboxauditloggingenabledInput(BaseModel):
    """
    Expected input schema for the ismailboxauditloggingenabled transformation.

    Note: No API response sample available. Schema structure should be
    updated based on actual API response format.
    """

    class Config:
        extra = "allow"
