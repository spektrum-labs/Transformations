"""Schema for isforensicsenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsforensicsenabledInput(BaseModel):
    """
    Expected input schema for the isforensicsenabled transformation.
    Vendor: Thehive
    Category: incidentmgmt

    Note: No API response sample available. Schema structure should be
    updated based on actual API response format.
    """

    class Config:
        extra = "allow"
