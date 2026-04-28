from typing import List, Optional, Any
from pydantic import BaseModel


class SkuInfo(BaseModel):
    type: Optional[str]
    totalLicenses: Optional[int]
    unlimited: bool


class ConfirmedLicensePurchasedOutput(BaseModel):
    confirmedLicensePurchased: bool
    accountName: Optional[str]
    accountType: Optional[str]
    accountState: Optional[str]
    billingMode: Optional[str]
    expiration: Optional[str]
    unlimitedExpiration: bool
    licenseBundles: List[str]
    skus: List[SkuInfo]
