"""Schema for ispasswordpolicyconfigured transformation input (BeyondTrust PRA)."""
from typing import Any, List, Optional, Union
from pydantic import BaseModel, Field


class GroupPolicy(BaseModel):
    id: Optional[int] = None
    name: Optional[str] = None
    perm_vault_add_accounts: Optional[Union[bool, str]] = Field(None, description="Permission to add vault accounts")
    perm_vault_manage_accounts: Optional[Union[bool, str]] = Field(None, description="Permission to manage vault accounts")
    perm_vault_manage_account_groups: Optional[Union[bool, str]] = Field(None, description="Permission to manage account groups")
    perm_vault_administrator: Optional[Union[bool, str]] = Field(None, description="Vault administrator permission")

    class Config:
        extra = "allow"


class IspasswordpolicyconfiguredInput(BaseModel):
    """Expected input: response from GET /api/config/v1/group_policy."""
    group_policies: Optional[List[GroupPolicy]] = Field(None, description="List of group policies")

    class Config:
        extra = "allow"
