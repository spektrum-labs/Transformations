from pydantic import BaseModel
from typing import Any, Dict, List, Optional


class ConfirmedLicensePurchasedInput(BaseModel):
    """Input schema for the confirmedLicensePurchased transformation.

    Expects the raw Mimecast getAccount API response envelope:
      {
        "fail": [],
        "meta": {"status": 200},
        "data": [{"accountCode": "...", "accountName": "...", "packages": [...], ...}]
      }
    """

    fail: Optional[List[Any]] = None
    meta: Optional[Dict[str, Any]] = None
    data: Optional[List[Dict[str, Any]]] = None

    class Config:
        extra = "allow"
