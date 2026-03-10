"""Schema for authtypesallowed transformation input."""
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class AdapterPluginRef(BaseModel):
    """Reference to the plugin descriptor for an adapter."""

    id: Optional[str] = Field(None, description="Plugin descriptor identifier")

    class Config:
        extra = "allow"


class AdapterItem(BaseModel):
    """An individual adapter entry."""

    id: Optional[str] = Field(None, description="Adapter identifier")
    pluginDescriptorRef: Optional[AdapterPluginRef] = Field(None, description="Reference to the plugin descriptor")

    class Config:
        extra = "allow"


class AuthtypesallowedInput(BaseModel):
    """Expected input schema for the authtypesallowed transformation. Criteria key: authTypesAllowed"""

    items: Optional[List[AdapterItem]] = Field(None, description="List of IdP adapter instances")

    class Config:
        extra = "allow"
