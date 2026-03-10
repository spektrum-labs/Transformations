"""Schema for confirmedlicensepurchased transformation input."""
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ConfirmedlicensepurchasedInput(BaseModel):
    """Expected input schema for the confirmedlicensepurchased transformation. Criteria key: confirmedLicensePurchased"""

    size: Optional[int] = Field(None, description="Number of licensed users in the SAFE tenant")
    values: Optional[List[Dict[str, Any]]] = Field(None, description="List of user records confirming an active subscription")

    class Config:
        extra = "allow"
