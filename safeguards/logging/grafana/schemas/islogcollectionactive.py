"""Schema for islogcollectionactive transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IslogcollectionactiveInput(BaseModel):
    """
    Expected input schema for the islogcollectionactive transformation.
    Vendor: Grafana
    Category: logging

    Note: No API response sample available. Schema structure should be
    updated based on actual API response format.
    """

    class Config:
        extra = "allow"
