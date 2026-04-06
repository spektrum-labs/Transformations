"""Schema for isedrdeployed transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsedrdeployedInput(BaseModel):
    """
    Expected input schema for the isedrdeployed transformation.
    Vendor: Kandji
    Category: epp

    Note: No API response sample available. Schema structure should be
    updated based on actual API response format.
    """

    class Config:
        extra = "allow"
