"""Schema for isspfconfigured transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsspfconfiguredInput(BaseModel):
    """
    Expected input schema for the isspfconfigured transformation.
    Criteria key: isSPFConfigured
    """

    spf_record: Optional[str] = None

    class Config:
        extra = "allow"
