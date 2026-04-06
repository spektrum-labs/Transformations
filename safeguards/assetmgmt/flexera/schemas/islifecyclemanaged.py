"""Schema for islifecyclemanaged transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IslifecyclemanagedInput(BaseModel):
    """
    Expected input schema for the islifecyclemanaged transformation.
    Vendor: Flexera
    Category: assetmgmt

    Note: No API response sample available. Schema structure should be
    updated based on actual API response format.
    """

    class Config:
        extra = "allow"
