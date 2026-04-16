"""Schema for confirmedlicensepurchased transformation input (BeyondTrust PRA)."""
from typing import Any, List, Optional
from pydantic import BaseModel, Field


class ConfirmedlicensepurchasedInput(BaseModel):
    """Expected input: response from GET /api/config/v1/vault/account.
    A list (even empty) indicates a licensed, reachable appliance.
    """
    accounts: Optional[List[Any]] = Field(None, description="List of vault accounts (when response is wrapped)")

    class Config:
        extra = "allow"
