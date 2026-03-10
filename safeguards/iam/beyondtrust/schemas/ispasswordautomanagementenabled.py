"""Schema for ispasswordautomanagementenabled transformation input."""

from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


class ManagedAccountAutoManagement(BaseModel):
    """A single managed account with auto-management flag."""
    AutoManagementFlag: Optional[Union[bool, str]] = None

    class Config:
        extra = "allow"


class IspasswordautomanagementenabledInput(BaseModel):
    """
    Expected input schema for the ispasswordautomanagementenabled transformation.
    Criteria key: isPasswordAutoManagementEnabled
    """
    ManagedAccounts: Optional[List[ManagedAccountAutoManagement]] = None
    items: Optional[List[ManagedAccountAutoManagement]] = None
    results: Optional[List[ManagedAccountAutoManagement]] = None

    class Config:
        extra = "allow"
