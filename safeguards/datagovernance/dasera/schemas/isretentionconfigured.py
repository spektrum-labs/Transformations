"""Schema for isretentionconfigured transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsretentionconfiguredInput(BaseModel):
    """
    Expected input schema for the isretentionconfigured transformation.
    Vendor: Dasera
    Category: datagovernance

    Note: No API response sample available. Schema structure should be
    updated based on actual API response format.
    """

    class Config:
        extra = "allow"
