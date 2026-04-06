"""Schema for issecurityscanningenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IssecurityscanningenabledInput(BaseModel):
    """
    Expected input schema for the issecurityscanningenabled transformation.
    Vendor: Teamcity
    Category: devsecops

    Note: No API response sample available. Schema structure should be
    updated based on actual API response format.
    """

    class Config:
        extra = "allow"
