"""Schema for isBehavioralMonitoringValid transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsbehavioralmonitoringvalidInput(BaseModel):
    """
    Expected input schema for the isBehavioralMonitoringValid transformation.
    Vendor: Workspace One Uem
    Category: epp

    Note: No API response sample available. Schema structure should be
    updated based on actual API response format.
    """

    class Config:
        extra = "allow"
