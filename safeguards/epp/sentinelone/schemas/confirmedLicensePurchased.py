from pydantic import BaseModel
from typing import Any, Dict, List, Optional


class ConfirmedLicensePurchasedInput(BaseModel):
    """Input schema for the confirmedLicensePurchased transformation.

    Accepts the raw getAccounts API response from SentinelOne.
    The top-level 'data' list contains account records with fields including
    accountType, state, skus, licenses, totalLicenses, and unlimitedExpiration.
    """

    class Config:
        extra = "allow"
