from pydantic import BaseModel
from typing import Any, Dict, List, Optional


class SkuItem(BaseModel):
    agentsInSku: Optional[int] = None
    totalLicenses: Optional[int] = None
    type: Optional[str] = None
    unlimited: Optional[bool] = None

    class Config:
        extra = "allow"


class LicenseSurface(BaseModel):
    count: Optional[int] = None
    name: Optional[str] = None

    class Config:
        extra = "allow"


class LicenseBundle(BaseModel):
    displayName: Optional[str] = None
    majorVersion: Optional[int] = None
    minorVersion: Optional[int] = None
    name: Optional[str] = None
    surfaces: Optional[List[LicenseSurface]] = None
    totalSurfaces: Optional[int] = None

    class Config:
        extra = "allow"


class LicenseModule(BaseModel):
    displayName: Optional[str] = None
    majorVersion: Optional[int] = None
    name: Optional[str] = None

    class Config:
        extra = "allow"


class LicenseSetting(BaseModel):
    displayName: Optional[str] = None
    groupName: Optional[str] = None
    setting: Optional[str] = None
    settingGroup: Optional[str] = None
    settingGroupDisplayName: Optional[str] = None

    class Config:
        extra = "allow"


class Licenses(BaseModel):
    bundles: Optional[List[LicenseBundle]] = None
    modules: Optional[List[LicenseModule]] = None
    settings: Optional[List[LicenseSetting]] = None

    class Config:
        extra = "allow"


class AccountItem(BaseModel):
    id: Optional[str] = None
    name: Optional[str] = None
    accountType: Optional[str] = None
    activeAgents: Optional[int] = None
    billingMode: Optional[str] = None
    createdAt: Optional[str] = None
    expiration: Optional[str] = None
    isDefault: Optional[bool] = None
    licenses: Optional[Licenses] = None
    skus: Optional[List[SkuItem]] = None
    state: Optional[str] = None
    totalLicenses: Optional[int] = None
    unlimitedComplete: Optional[bool] = None
    unlimitedControl: Optional[bool] = None
    unlimitedCore: Optional[bool] = None
    unlimitedExpiration: Optional[bool] = None
    usageType: Optional[str] = None

    class Config:
        extra = "allow"


class Pagination(BaseModel):
    nextCursor: Optional[str] = None
    totalItems: Optional[int] = None

    class Config:
        extra = "allow"


class ConfirmedLicensePurchasedInput(BaseModel):
    """Input schema for the confirmedLicensePurchased transformation.
    Matches the GET /web/api/v2.1/accounts response shape from SentinelOne."""
    data: Optional[List[AccountItem]] = None
    pagination: Optional[Pagination] = None

    class Config:
        extra = "allow"
