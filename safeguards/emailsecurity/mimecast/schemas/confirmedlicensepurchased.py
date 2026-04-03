"""Schema for confirmedlicensepurchased transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class MimecastAccount(BaseModel):
    """Mimecast account information from the account API."""
    accountName: Optional[str] = None
    accountCode: Optional[str] = None
    mimecastId: Optional[str] = None
    packages: Optional[List[str]] = None
    userCount: Optional[str] = None
    region: Optional[str] = None
    type: Optional[str] = None
    gateway: Optional[str] = None
    archive: Optional[str] = None
    contactEmail: Optional[str] = None
    contactName: Optional[str] = None

    class Config:
        extra = "allow"


class ConfirmedlicensepurchasedInput(BaseModel):
    """
    Expected input schema for the confirmedlicensepurchased transformation.
    Criteria key: confirmedLicensePurchased

    Note: After API response parsing, the Mimecast account response is
    unwrapped from the 'data' key, yielding a list of MimecastAccount
    entries. Schema validation may report an error for list inputs.
    The transformation handles both list and dict formats.
    """

    data: Optional[List[MimecastAccount]] = None

    class Config:
        extra = "allow"
