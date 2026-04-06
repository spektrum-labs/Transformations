"""Schema for isnotificationconfigured transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsnotificationconfiguredInput(BaseModel):
    """
    Expected input schema for the isnotificationconfigured transformation.
    Vendor: Infobip
    Category: communication

    Note: No API response sample available. Schema structure should be
    updated based on actual API response format.
    """

    class Config:
        extra = "allow"
