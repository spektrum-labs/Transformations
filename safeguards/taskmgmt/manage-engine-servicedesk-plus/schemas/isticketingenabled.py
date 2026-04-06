"""Schema for isticketingenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsticketingenabledInput(BaseModel):
    """
    Expected input schema for the isticketingenabled transformation.
    Vendor: Manage Engine Servicedesk Plus
    Category: taskmgmt

    Note: No API response sample available. Schema structure should be
    updated based on actual API response format.
    """

    class Config:
        extra = "allow"
