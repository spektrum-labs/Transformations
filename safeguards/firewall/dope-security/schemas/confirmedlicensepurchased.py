"""Schema for confirmedlicensepurchased transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class Endpoint(BaseModel):
    """An endpoint enrolled in Dope Security."""

    class Config:
        extra = "allow"


class DataPayload(BaseModel):
    """Inner data payload containing endpoints."""

    endpoints: Optional[List[Endpoint]] = None

    class Config:
        extra = "allow"


class ConfirmedlicensepurchasedInput(BaseModel):
    """Expected input schema for the confirmedlicensepurchased transformation. Criteria key: confirmedLicensePurchased"""

    data: Optional[DataPayload] = None

    class Config:
        extra = "allow"
