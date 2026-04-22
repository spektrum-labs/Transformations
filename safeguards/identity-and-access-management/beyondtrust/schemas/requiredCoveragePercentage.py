"""Schema for requiredCoveragePercentage transformation input."""
from typing import List, Optional, Union
from pydantic import BaseModel


class ManagedSystem(BaseModel):
    """A single managed system entry from the BeyondTrust ManagedSystems endpoint."""
    ManagedSystemID: Optional[int] = None
    SystemName: Optional[str] = None
    NetBiosName: Optional[str] = None
    IsActive: Optional[Union[bool, str]] = None

    class Config:
        extra = "allow"


class ManagedAccount(BaseModel):
    """A single managed account entry from the BeyondTrust ManagedAccounts endpoint."""
    ManagedAccountID: Optional[int] = None
    ManagedSystemID: Optional[int] = None
    AccountName: Optional[str] = None

    class Config:
        extra = "allow"


class RequiredCoveragePercentageInput(BaseModel):
    """Expected input shape for the requiredCoveragePercentage transformation.
    The workflow merges getManagedAccounts and getManagedSystems responses into a single dict.
    """
    ManagedSystems: Optional[List[ManagedSystem]] = None
    managedSystems: Optional[List[ManagedSystem]] = None
    ManagedAccounts: Optional[List[ManagedAccount]] = None
    managedAccounts: Optional[List[ManagedAccount]] = None

    class Config:
        extra = "allow"
