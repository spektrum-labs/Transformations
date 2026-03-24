"""Schema for isdkimconfigured transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsdkimconfiguredInput(BaseModel):
    """
    Expected input schema for the isdkimconfigured transformation.
    Criteria key: isDKIMConfigured
    """

    Enabled: Optional[bool] = None
    Status: Optional[str] = None

    class Config:
        extra = "allow"
