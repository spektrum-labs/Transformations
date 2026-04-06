"""Schema for iscompliancemonitored transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IscompliancemonitoredInput(BaseModel):
    """
    Expected input schema for the iscompliancemonitored transformation.
    Vendor: Onetrust
    Category: grc

    Note: No API response sample available. Schema structure should be
    updated based on actual API response format.
    """

    class Config:
        extra = "allow"
