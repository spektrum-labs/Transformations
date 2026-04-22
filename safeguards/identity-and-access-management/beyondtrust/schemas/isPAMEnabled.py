"""Schema for isPAMEnabled transformation input."""
from typing import Any, List, Optional
from pydantic import BaseModel


class ManagedSystem(BaseModel):
    """A single BeyondTrust managed system entry."""
    ManagedSystemID: Optional[Any] = None

    class Config:
        extra = "allow"


class IsPAMEnabledInput(BaseModel):
    """
    Expected input shape for the isPAMEnabled transformation.
    Accepts a direct list of managed systems or a dict wrapper.
    """
    ManagedSystems: Optional[List[ManagedSystem]] = None
    managedSystems: Optional[List[ManagedSystem]] = None
    items: Optional[List[ManagedSystem]] = None
    results: Optional[List[ManagedSystem]] = None

    class Config:
        extra = "allow"
