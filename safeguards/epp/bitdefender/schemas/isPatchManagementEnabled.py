"""Schema for isPatchManagementEnabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IspatchmanagementenabledInput(BaseModel):
    """
    Expected input schema for the isPatchManagementEnabled transformation.
    Vendor: Bitdefender
    Category: epp

    Note: No API response sample available. Schema structure should be
    updated based on actual API response format.
    """

    class Config:
        extra = "allow"
