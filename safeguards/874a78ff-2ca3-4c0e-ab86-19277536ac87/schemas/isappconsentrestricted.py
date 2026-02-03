"""Schema for isappconsentrestricted transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsappconsentrestrictedInput(BaseModel):
    """
    Expected input schema for the isappconsentrestricted transformation.

    Note: No API response sample available. Schema structure should be
    updated based on actual API response format.
    """

    class Config:
        extra = "allow"
