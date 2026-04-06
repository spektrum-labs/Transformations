"""Schema for isserviceenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsserviceenabledInput(BaseModel):
    """
    Expected input schema for the isserviceenabled transformation.
    Vendor: Docusign
    Category: misc

    Note: No API response sample available. Schema structure should be
    updated based on actual API response format.
    """

    class Config:
        extra = "allow"
