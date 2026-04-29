
from pydantic import BaseModel
from typing import Any, Dict, List, Optional


class ConfirmedLicensePurchasedInput(BaseModel):
    """Input schema for the confirmedLicensePurchased transformation.

    Expects the raw getAccounts API response with a top-level 'data' list
    of account objects, each containing accountType, state, totalLicenses,
    unlimitedComplete/Control/Core, skus, and licenses.bundles fields.
    """

    data: Optional[List[Dict[str, Any]]] = None
    pagination: Optional[Dict[str, Any]] = None

    class Config:
        extra = "allow"
