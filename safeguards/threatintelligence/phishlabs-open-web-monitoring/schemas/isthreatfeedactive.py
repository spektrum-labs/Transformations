"""Schema for isthreatfeedactive transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsthreatfeedactiveInput(BaseModel):
    """
    Expected input schema for the isthreatfeedactive transformation.
    Vendor: Phishlabs Open Web Monitoring
    Category: threatintelligence

    Note: No API response sample available. Schema structure should be
    updated based on actual API response format.
    """

    class Config:
        extra = "allow"
