"""Schema for ismessagingenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsmessagingenabledInput(BaseModel):
    """
    Expected input schema for the ismessagingenabled transformation.
    Vendor: Lark
    Category: communication

    Note: No API response sample available. Schema structure should be
    updated based on actual API response format.
    """

    class Config:
        extra = "allow"
