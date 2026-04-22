"""Schema for isPasswordAutoManagementEnabled transformation input."""
from typing import List, Optional, Union
from pydantic import BaseModel


class ManagedAccountAutoManagement(BaseModel):
    """A BeyondTrust managed account with auto-management flag."""
    AutoManagementFlag: Optional[Union[bool, str]] = None

    class Config:
        extra = "allow"


class IsPasswordAutoManagementEnabledInput(BaseModel):
    """
    Expected input shape for the isPasswordAutoManagementEnabled transformation.
    Accepts either a bare list or a dict with ManagedAccounts key.
    """
    ManagedAccounts: Optional[List[ManagedAccountAutoManagement]] = None
    items: Optional[List[ManagedAccountAutoManagement]] = None
    results: Optional[List[ManagedAccountAutoManagement]] = None

    class Config:
        extra = "allow"
