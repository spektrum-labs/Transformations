from __future__ import annotations

from typing import List, Optional
from pydantic import BaseModel, Field


class SiteDetail(BaseModel):
    siteId: str = Field(description="Unique site identifier")
    siteName: str = Field(description="Human-readable site name")
    activeLicenses: int = Field(description="Number of active licenses on the site")
    totalLicenses: int = Field(description="Total licenses allocated to the site")
    sku: str = Field(description="License SKU / product tier for the site")
    state: str = Field(description="Site state (e.g. active, expired)")
    expiration: Optional[str] = Field(None, description="License expiration date-time, if set")
    hasActiveLicense: bool = Field(description="True when activeLicenses > 0 and sku is non-empty")


class ConfirmedLicensePurchasedOutput(BaseModel):
    confirmedLicensePurchased: bool = Field(
        description="True when at least one site has activeLicenses > 0 and a non-empty sku"
    )
    totalSites: int = Field(description="Total number of sites returned by the API")
    licensedSiteCount: int = Field(description="Number of sites with an active license")
    licensedSiteNames: List[str] = Field(description="Names of sites that have active licenses")
    siteDetails: List[SiteDetail] = Field(description="Per-site license detail records")
