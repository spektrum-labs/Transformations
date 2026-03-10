"""Schema for confirmedlicensepurchased transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class LicenseUsageSummaryEntry(BaseModel):
    """Single entry in the licenseUsageSummary array (v4 API)."""
    totalLicense: Optional[int] = None
    purchasedQuantity: Optional[int] = None

    class Config:
        extra = "allow"


class License(BaseModel):
    """Single license entry from the licenses list."""
    licenseStatus: Optional[str] = None
    isActive: Optional[bool] = None

    class Config:
        extra = "allow"


class LicenseInfo(BaseModel):
    """License info block."""
    isLicensed: Optional[bool] = None

    class Config:
        extra = "allow"


class ConfirmedlicensepurchasedInput(BaseModel):
    """
    Expected input schema for the confirmedlicensepurchased transformation.
    Criteria key: confirmedLicensePurchased
    """
    licenseUsageSummary: Optional[List[LicenseUsageSummaryEntry]] = None
    licenses: Optional[List[License]] = None
    licenseInfo: Optional[LicenseInfo] = None
    oemName: Optional[str] = None
    commCellName: Optional[str] = None

    class Config:
        extra = "allow"
