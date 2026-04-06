"""Schema for isdashboardconfigured transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsdashboardconfiguredInput(BaseModel):
    """
    Expected input schema for the isdashboardconfigured transformation.
    Vendor: Dynatrace
    Category: logging

    Note: No API response sample available. Schema structure should be
    updated based on actual API response format.
    """

    class Config:
        extra = "allow"
