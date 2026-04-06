"""Schema for isintegrationhealthy transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsintegrationhealthyInput(BaseModel):
    """
    Expected input schema for the isintegrationhealthy transformation.
    Vendor: Confluence
    Category: taskmgmt

    Note: No API response sample available. Schema structure should be
    updated based on actual API response format.
    """

    class Config:
        extra = "allow"
