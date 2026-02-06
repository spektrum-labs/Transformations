"""Schema for isbackupimmutable transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsbackupimmutableInput(BaseModel):
    """
    Expected input schema for the isbackupimmutable transformation.

    Note: No API response sample available. Schema structure should be
    updated based on actual API response format.
    """

    class Config:
        extra = "allow"
