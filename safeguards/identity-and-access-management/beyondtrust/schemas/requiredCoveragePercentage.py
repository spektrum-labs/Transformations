"""Schema for requiredCoveragePercentage transformation input."""
from typing import Any, List, Optional
from pydantic import BaseModel


class ManagedSystem(BaseModel):
    """A BeyondTrust managed system entry."""
    ManagedSystemID: Optional[Any] = None

    class Config:
        extra = "allow"


class ManagedAccount(BaseModel):
    """A BeyondTrust managed account entry."""
    ManagedSystemID: Optional[Any] = None

    class Config:
        extra = "allow"


class RequiredCoveragePercentageInput(BaseModel):
    """
    Expected input shape for the requiredCoveragePercentage transformation.
    Requires a merged payload with both managed systems and accounts.
    """
    managedSystems: Optional[List[ManagedSystem]] = None
    ManagedSystems: Optional[List[ManagedSystem]] = None
    managedAccounts: Optional[List[ManagedAccount]] = None
    ManagedAccounts: Optional[List[ManagedAccount]] = None

    class Config:
        extra = "allow"
