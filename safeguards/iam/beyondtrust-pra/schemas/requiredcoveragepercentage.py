"""Schema for requiredcoveragepercentage transformation input (BeyondTrust PRA)."""
from typing import Any, List, Optional, Union
from pydantic import BaseModel, Field


class VaultAccountCoverage(BaseModel):
    id: Optional[int] = None
    name: Optional[str] = None
    account_state: Optional[str] = Field(None, description="Account state: valid, invalid, needs_rotate")
    policy_id: Optional[Union[int, str]] = Field(None, description="Assigned vault policy ID")
    group_policy_id: Optional[Union[int, str]] = Field(None, description="Assigned group policy ID")

    class Config:
        extra = "allow"


class RequiredcoveragepercentageInput(BaseModel):
    """Expected input: response from GET /api/config/v1/vault/account.
    Coverage = (accounts with account_state=valid AND group_policy_id set) / total accounts.
    """
    accounts: Optional[List[VaultAccountCoverage]] = Field(None, description="List of vault accounts")

    class Config:
        extra = "allow"
