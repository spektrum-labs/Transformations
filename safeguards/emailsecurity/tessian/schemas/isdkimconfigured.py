"""Schema for isdkimconfigured transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsdkimconfiguredInput(BaseModel):
    """
    Expected input schema for the isdkimconfigured transformation.
    Vendor: Tessian
    Category: emailsecurity

    Note: No API response sample available. Schema structure should be
    updated based on actual API response format.
    """

    class Config:
        extra = "allow"
