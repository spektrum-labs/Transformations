"""Schema for isPasswordRotationOnReleaseEnabled transformation input."""
from typing import List, Optional, Union
from pydantic import BaseModel


class ManagedAccount(BaseModel):
    """A single managed account entry from the BeyondTrust ManagedAccounts endpoint."""
    ManagedAccountID: Optional[int] = None
    ManagedSystemID: Optional[int] = None
    AccountName: Optional[str] = None
    ChangePasswordAfterAnyReleaseFlag: Optional[Union[bool, str]] = None
    AutoManagementFlag: Optional[Union[bool, str]] = None

    class Config:
        extra = "allow"


class IsPasswordRotationOnReleaseEnabledInput(BaseModel):
    """Expected input shape for the isPasswordRotationOnReleaseEnabled transformation."""
    ManagedAccounts: Optional[List[ManagedAccount]] = None
    items: Optional[List[ManagedAccount]] = None
    results: Optional[List[ManagedAccount]] = None

    class Config:
        extra = "allow"
