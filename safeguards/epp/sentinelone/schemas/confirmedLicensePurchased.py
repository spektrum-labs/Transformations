from pydantic import BaseModel
from typing import Any, Dict, List, Optional


class ConfirmedLicensePurchasedInput(BaseModel):
    """Input schema for the confirmedLicensePurchased transformation.

    Accepts the raw getAccounts API response from SentinelOne v2.1.
    The data array contains account records with accountType, state,
    skus, licenses.bundles, and totalLicenses fields used to confirm
    a purchased and active license.
    """

    class Config:
        extra = "allow"
