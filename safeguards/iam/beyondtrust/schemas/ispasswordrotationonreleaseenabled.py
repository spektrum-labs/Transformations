"""Schema for ispasswordrotationonreleaseenabled transformation input."""

from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


class ManagedAccountRotation(BaseModel):
    """A single managed account with password rotation on release flag."""
    ChangePasswordAfterAnyReleaseFlag: Optional[Union[bool, str]] = None

    class Config:
        extra = "allow"


class IspasswordrotationonreleaseenabledInput(BaseModel):
    """
    Expected input schema for the ispasswordrotationonreleaseenabled transformation.
    Criteria key: isPasswordRotationOnReleaseEnabled
    """
    ManagedAccounts: Optional[List[ManagedAccountRotation]] = None
    items: Optional[List[ManagedAccountRotation]] = None
    results: Optional[List[ManagedAccountRotation]] = None

    class Config:
        extra = "allow"
