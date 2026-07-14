"""Schema for confirmedlicensepurchased transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ConfirmedlicensepurchasedInput(BaseModel):
    """
    Expected input schema for the confirmedlicensepurchased transformation.
    Criteria key: confirmedLicensePurchased
    """

    class Config:
        extra = "allow"
