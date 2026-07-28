"""Schema for isdataretentionconfigured transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsdataretentionconfiguredInput(BaseModel):
    """
    Expected input schema for the isdataretentionconfigured transformation.
    Criteria key: isDataRetentionConfigured
    """

    class Config:
        extra = "allow"
