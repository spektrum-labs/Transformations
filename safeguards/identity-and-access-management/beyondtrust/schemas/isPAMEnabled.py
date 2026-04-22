"""Schema for isPAMEnabled transformation input."""
from typing import List, Optional, Union
from pydantic import BaseModel


class ManagedSystem(BaseModel):
    """A single managed system entry from the BeyondTrust ManagedSystems endpoint."""
    ManagedSystemID: Optional[int] = None
    SystemName: Optional[str] = None
    NetBiosName: Optional[str] = None
    EntityTypeID: Optional[int] = None
    IsActive: Optional[Union[bool, str]] = None

    class Config:
        extra = "allow"


class IsPAMEnabledInput(BaseModel):
    """Expected input shape for the isPAMEnabled transformation."""
    ManagedSystems: Optional[List[ManagedSystem]] = None
    items: Optional[List[ManagedSystem]] = None
    results: Optional[List[ManagedSystem]] = None

    class Config:
        extra = "allow"
