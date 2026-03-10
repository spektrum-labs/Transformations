"""Schema for ismfaenabled transformation input."""
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class IdpAdapterPluginRef(BaseModel):
    """Reference to the plugin descriptor for an IdP adapter."""

    id: Optional[str] = Field(None, description="Plugin descriptor identifier")

    class Config:
        extra = "allow"


class IdpAdapterItem(BaseModel):
    """An individual IdP adapter entry."""

    id: Optional[str] = Field(None, description="Adapter identifier")
    pluginDescriptorRef: Optional[IdpAdapterPluginRef] = Field(None, description="Reference to the plugin descriptor")

    class Config:
        extra = "allow"


class IsmfaenabledInput(BaseModel):
    """Expected input schema for the ismfaenabled transformation. Criteria key: isMFAEnabled"""

    items: Optional[List[IdpAdapterItem]] = Field(None, description="List of IdP adapter instances")

    class Config:
        extra = "allow"
