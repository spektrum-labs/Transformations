from pydantic import BaseModel
from typing import Any, Dict, List, Optional


class ConfirmedLicensePurchasedInput(BaseModel):
    """Input schema for the confirmedLicensePurchased transformation.

    Expects the response shape from Mimecast get-account:
      data[]  — list of account objects (accountCode, accountName, packages, etc.)
      meta    — envelope metadata including status code
      fail[]  — list of error objects (empty on success)
    """

    data: Optional[List[Dict[str, Any]]] = None
    meta: Optional[Dict[str, Any]] = None
    fail: Optional[List[Any]] = None

    class Config:
        extra = "allow"
