"""Schema for confirmedLicensePurchased transformation input."""
from typing import Optional
from pydantic import BaseModel


class ConfirmedLicensePurchasedInput(BaseModel):
    """
    Expected input shape for the confirmedLicensePurchased transformation.
    Accepts the raw ManagedAccounts response (list) or an error dict.
    """
    Message: Optional[str] = None
    error: Optional[str] = None
    status: Optional[str] = None
    message: Optional[str] = None

    class Config:
        extra = "allow"
