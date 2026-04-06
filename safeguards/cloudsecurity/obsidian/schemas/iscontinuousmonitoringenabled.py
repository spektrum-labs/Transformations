"""Schema for iscontinuousmonitoringenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IscontinuousmonitoringenabledInput(BaseModel):
    """
    Expected input schema for the iscontinuousmonitoringenabled transformation.
    Vendor: Obsidian
    Category: cloudsecurity

    Note: No API response sample available. Schema structure should be
    updated based on actual API response format.
    """

    class Config:
        extra = "allow"
