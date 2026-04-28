from typing import Optional
from pydantic import BaseModel


class ConfirmedLicensePurchasedOutput(BaseModel):
    confirmedLicensePurchased: bool
    sku: Optional[str] = None
    activeLicenses: int
    totalLicenses: int
    unlimitedLicenses: bool
