"""Schema for confirmedlicensepurchased transformation input."""
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field


class BundleItem(BaseModel):
    """A single bundle/subscription item from the NINJIO API."""
    name: Optional[str] = Field(None, description="Bundle name (e.g. AWARE, ENGAGE, PRODIGY)")
    bundleName: Optional[str] = Field(None, description="Alternate bundle name field")
    type: Optional[str] = Field(None, description="Bundle type")
    status: Optional[str] = Field(None, description="Bundle status (e.g. active, enabled)")
    state: Optional[str] = Field(None, description="Alternate status field")
    active: Optional[Union[bool, str]] = Field(None, description="Whether the bundle is active")

    class Config:
        extra = "allow"


class ConfirmedlicensepurchasedInput(BaseModel):
    """Expected input schema for the confirmedlicensepurchased transformation. Criteria key: confirmedLicensePurchased"""
    bundles: Optional[List[BundleItem]] = Field(None, description="List of subscription bundles")
    data: Optional[Any] = Field(None, description="Alternate key for bundles list or nested data")
    results: Optional[List[BundleItem]] = Field(None, description="Alternate key for bundles list")
    items: Optional[List[BundleItem]] = Field(None, description="Alternate key for bundles list")

    class Config:
        extra = "allow"
