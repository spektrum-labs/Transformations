"""Schema for isincidentresponseenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsincidentresponseenabledInput(BaseModel):
    """
    Expected input schema for the isincidentresponseenabled transformation.
    Vendor: Firehydrant
    Category: incidentmgmt

    Note: No API response sample available. Schema structure should be
    updated based on actual API response format.
    """

    class Config:
        extra = "allow"
