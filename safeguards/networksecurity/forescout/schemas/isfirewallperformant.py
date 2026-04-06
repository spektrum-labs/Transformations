"""Schema for isfirewallperformant transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsfirewallperformantInput(BaseModel):
    """
    Expected input schema for the isfirewallperformant transformation.
    Vendor: Forescout
    Category: networksecurity

    Note: No API response sample available. Schema structure should be
    updated based on actual API response format.
    """

    class Config:
        extra = "allow"
