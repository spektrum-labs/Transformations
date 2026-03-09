"""Schema for isassetdiscoveryenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IsassetdiscoveryenabledInput(BaseModel):
    """
    Expected input schema for the isassetdiscoveryenabled transformation.

    Axonius devices and adapters API response containing discovery status.
    """

    devices: Optional[Dict[str, Any]] = Field(None, description="Axonius devices data from getDevices endpoint")
    adapters: Optional[Dict[str, Any]] = Field(None, description="Axonius adapters data from getAdapters endpoint")
    data: Optional[List[Dict[str, Any]]] = Field(None, description="Fallback data array")

    class Config:
        extra = "allow"
