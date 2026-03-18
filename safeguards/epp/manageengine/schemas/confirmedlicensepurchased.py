"""Schema for confirmedlicensepurchased transformation input."""
from typing import Optional, Union

from pydantic import BaseModel, Field


class ConfirmedlicensepurchasedInput(BaseModel):
    """Expected input schema for the confirmedlicensepurchased transformation.
    Criteria key: confirmedLicensePurchased
    Source: ManageEngine Endpoint Central GET /api/1.4/desktop/serverproperties"""
    server_name: Optional[str] = Field(None, description="Endpoint Central server name")
    serverName: Optional[str] = Field(None, description="Alternate server name field")
    product_name: Optional[str] = Field(None, description="Product name (e.g. Endpoint Central)")
    productName: Optional[str] = Field(None, description="Alternate product name field")
    product_version: Optional[str] = Field(None, description="Product version")
    productVersion: Optional[str] = Field(None, description="Alternate product version field")
    build_number: Optional[str] = Field(None, description="Build number")
    buildNumber: Optional[str] = Field(None, description="Alternate build number field")
    license_type: Optional[str] = Field(None, description="License type (e.g. Professional, Enterprise, UEM)")
    licenseType: Optional[str] = Field(None, description="Alternate license type field")
    license_expiry: Optional[str] = Field(None, description="License expiry date")
    licenseExpiry: Optional[str] = Field(None, description="Alternate license expiry field")

    class Config:
        extra = "allow"
