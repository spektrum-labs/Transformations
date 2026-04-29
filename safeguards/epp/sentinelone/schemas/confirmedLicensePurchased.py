from pydantic import BaseModel
from typing import Any, Dict, List, Optional


class ConfirmedLicensePurchasedInput(BaseModel):
    """Input schema for the confirmedLicensePurchased transformation.

    Validates the getAccounts response from SentinelOne v2.1.
    Each account record carries accountType, state, licenses (bundles/modules/settings),
    skus, and unlimited-seat flags that together confirm whether a paid, active
    license is in place.
    """

    class Config:
        extra = "allow"
