"""Schema for ispamenabled transformation input (BeyondTrust PRA)."""
from typing import Any, List, Optional
from pydantic import BaseModel, Field


class VaultAccount(BaseModel):
    id: Optional[int] = Field(None, description="Vault account ID")
    name: Optional[str] = Field(None, description="Vault account name")
    username: Optional[str] = Field(None, description="Account username")
    type: Optional[str] = Field(None, description="Account type (generic, generic_managed, linux, windows, ssh, etc.)")
    account_state: Optional[str] = Field(None, description="Account state: valid, invalid, needs_rotate")

    class Config:
        extra = "allow"


class IspamenabledInput(BaseModel):
    """Expected input: response from GET /api/config/v1/vault/account."""
    accounts: Optional[List[VaultAccount]] = Field(None, description="List of vault accounts")

    class Config:
        extra = "allow"
