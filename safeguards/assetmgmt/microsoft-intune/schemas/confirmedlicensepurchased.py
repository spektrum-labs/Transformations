"""Schema for confirmedlicensepurchased transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class PrepaidUnits(BaseModel):
    """Prepaid license unit counts."""

    enabled: Optional[int] = None
    suspended: Optional[int] = None
    warning: Optional[int] = None

    class Config:
        extra = "allow"


class SubscribedSku(BaseModel):
    """Microsoft Graph subscribedSku entry."""

    skuPartNumber: Optional[str] = None
    skuId: Optional[str] = None
    prepaidUnits: Optional[PrepaidUnits] = None
    consumedUnits: Optional[int] = None
    capabilityStatus: Optional[str] = None

    class Config:
        extra = "allow"


class ConfirmedlicensepurchasedInput(BaseModel):
    """
    Expected input schema for the confirmedlicensepurchased transformation.
    Criteria key: confirmedLicensePurchased

    Checks subscribedSkus for Intune-capable SKU part numbers
    (INTUNE_A, EMS, SPE_E3, SPE_E5, M365_E3, M365_E5, etc.)
    with enabled units > 0.
    """

    value: Optional[List[SubscribedSku]] = None
    skus: Optional[List[SubscribedSku]] = None

    class Config:
        extra = "allow"
