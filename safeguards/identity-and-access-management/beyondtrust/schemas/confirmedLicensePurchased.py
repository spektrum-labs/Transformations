"""Schema for confirmedLicensePurchased transformation input."""
from typing import List, Optional, Union
from pydantic import BaseModel


class ManagedAccount(BaseModel):
    """A single managed account entry (minimal fields needed for license check)."""
    ManagedAccountID: Optional[int] = None

    class Config:
        extra = "allow"


class ConfirmedLicensePurchasedInput(BaseModel):
    """Expected input shape for the confirmedLicensePurchased transformation."""
    Message: Optional[str] = None
    error: Optional[str] = None
    status: Optional[str] = None
    message: Optional[str] = None

    class Config:
        extra = "allow"
