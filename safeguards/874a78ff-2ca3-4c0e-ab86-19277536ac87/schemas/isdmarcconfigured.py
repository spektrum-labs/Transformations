"""Schema for isdmarcconfigured transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsdmarcconfiguredInput(BaseModel):
    """
    Expected input schema for the isdmarcconfigured transformation.
    Criteria key: isDMARCConfigured
    """

    dmarc_record: Optional[str] = None

    class Config:
        extra = "allow"
