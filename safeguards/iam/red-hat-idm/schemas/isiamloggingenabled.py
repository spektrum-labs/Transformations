"""Schema for isiamloggingenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsiamloggingenabledInput(BaseModel):
    """
    Expected input schema for the isiamloggingenabled transformation.
    Vendor: Red Hat Idm
    Category: iam

    Note: No API response sample available. Schema structure should be
    updated based on actual API response format.
    """

    class Config:
        extra = "allow"
