from pydantic import BaseModel
from typing import List, Optional


class LicenseDetail(BaseModel):
    accountId: str
    accountName: str
    accountType: str
    state: str
    totalLicenses: Optional[int]
    hasActiveLicense: bool


class ConfirmedLicensePurchasedOutput(BaseModel):
    confirmedLicensePurchased: bool
    licenseDetails: List[LicenseDetail]
