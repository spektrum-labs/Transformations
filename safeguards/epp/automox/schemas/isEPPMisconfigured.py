"""Schema for iseppmisconfigured transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IseppmisconfiguredInput(BaseModel):
    """
    Expected input schema for the iseppmisconfigured transformation.
    Vendor: Automox
    Category: epp

    Note: No API response sample available. Schema structure should be
    updated based on actual API response format.
    """

    class Config:
        extra = "allow"
