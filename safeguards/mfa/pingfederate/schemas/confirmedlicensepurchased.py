"""Schema for confirmedlicensepurchased transformation input."""
from typing import Optional

from pydantic import BaseModel, Field


class ConfirmedlicensepurchasedInput(BaseModel):
    """Expected input schema for the confirmedlicensepurchased transformation. Criteria key: confirmedLicensePurchased"""

    id: Optional[str] = Field(None, description="License record identifier")
    expirationDate: Optional[str] = Field(None, description="License expiration date string (YYYY-MM-DD)")

    class Config:
        extra = "allow"
