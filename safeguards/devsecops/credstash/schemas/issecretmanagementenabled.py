"""Schema for issecretmanagementenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IssecretmanagementenabledInput(BaseModel):
    """
    Expected input schema for the issecretmanagementenabled transformation.
    Vendor: Credstash
    Category: devsecops

    Note: No API response sample available. Schema structure should be
    updated based on actual API response format.
    """

    class Config:
        extra = "allow"
