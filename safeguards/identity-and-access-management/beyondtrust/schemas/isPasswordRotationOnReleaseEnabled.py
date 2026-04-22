"""Schema for isPasswordRotationOnReleaseEnabled transformation input."""
from typing import List, Optional, Union
from pydantic import BaseModel


class ManagedAccountRotation(BaseModel):
    """A BeyondTrust managed account with password rotation on release flag."""
    ChangePasswordAfterAnyReleaseFlag: Optional[Union[bool, str]] = None

    class Config:
        extra = "allow"


class IsPasswordRotationOnReleaseEnabledInput(BaseModel):
    """
    Expected input shape for the isPasswordRotationOnReleaseEnabled transformation.
    Accepts either a bare list or a dict with ManagedAccounts key.
    """
    ManagedAccounts: Optional[List[ManagedAccountRotation]] = None
    items: Optional[List[ManagedAccountRotation]] = None
    results: Optional[List[ManagedAccountRotation]] = None

    class Config:
        extra = "allow"
