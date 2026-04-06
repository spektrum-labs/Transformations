"""Schema for isdmarcconfigured transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsdmarcconfiguredInput(BaseModel):
    """
    Expected input schema for the isdmarcconfigured transformation.
    Vendor: Trellix Email Security
    Category: emailsecurity

    Note: No API response sample available. Schema structure should be
    updated based on actual API response format.
    """

    class Config:
        extra = "allow"
