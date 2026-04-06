"""Schema for islogingestionactive transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IslogingestionactiveInput(BaseModel):
    """
    Expected input schema for the islogingestionactive transformation.
    Vendor: Exabeam
    Category: siem

    Note: No API response sample available. Schema structure should be
    updated based on actual API response format.
    """

    class Config:
        extra = "allow"
