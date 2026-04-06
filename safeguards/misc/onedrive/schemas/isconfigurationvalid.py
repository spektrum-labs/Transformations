"""Schema for isconfigurationvalid transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsconfigurationvalidInput(BaseModel):
    """
    Expected input schema for the isconfigurationvalid transformation.
    Vendor: Onedrive
    Category: misc

    Note: No API response sample available. Schema structure should be
    updated based on actual API response format.
    """

    class Config:
        extra = "allow"
