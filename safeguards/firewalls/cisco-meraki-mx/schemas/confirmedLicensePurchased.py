from pydantic import BaseModel
from typing import Optional, Dict, Any


class ConfirmedLicensePurchasedInput(BaseModel):
    """Input schema for the confirmedLicensePurchased transformation."""
    status: Optional[str] = None
    expirationDate: Optional[str] = None
    licensedDeviceCounts: Optional[Dict[str, Any]] = None

    class Config:
        extra = "allow"
