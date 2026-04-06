"""Schema for isalertingconfigured transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsalertingconfiguredInput(BaseModel):
    """
    Expected input schema for the isalertingconfigured transformation.
    Vendor: Wazuh Server
    Category: mdr

    Note: No API response sample available. Schema structure should be
    updated based on actual API response format.
    """

    class Config:
        extra = "allow"
