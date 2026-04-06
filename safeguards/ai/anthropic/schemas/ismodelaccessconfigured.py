"""Schema for ismodelaccessconfigured transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsmodelaccessconfiguredInput(BaseModel):
    """
    Expected input schema for the ismodelaccessconfigured transformation.
    Vendor: Anthropic
    Category: ai

    Note: No API response sample available. Schema structure should be
    updated based on actual API response format.
    """

    class Config:
        extra = "allow"
