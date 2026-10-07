"""Schema for issafelinksenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IssafelinksenabledInput(BaseModel):
    """
    Expected input schema for the issafelinksenabled transformation.

    Note: No API response sample available. Schema structure should be
    updated based on actual API response format.
    """

    class Config:
        extra = "allow"
