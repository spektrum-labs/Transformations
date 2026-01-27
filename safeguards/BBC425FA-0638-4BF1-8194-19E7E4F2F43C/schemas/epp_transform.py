"""Schema for epp_transform transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class EppTransformInput(BaseModel):
    """
    Expected input schema for the epp_transform transformation.

    Note: No API response sample available. Schema structure should be
    updated based on actual API response format.
    """

    class Config:
        extra = "allow"
