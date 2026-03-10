"""Schema for requiredcoveragepercentage transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ManagedSystem(BaseModel):
    """A single managed system entry."""
    ManagedSystemID: Optional[Any] = None

    class Config:
        extra = "allow"


class ManagedAccountCoverage(BaseModel):
    """A single managed account entry with system linkage."""
    ManagedSystemID: Optional[Any] = None

    class Config:
        extra = "allow"


class RequiredcoveragepercentageInput(BaseModel):
    """
    Expected input schema for the requiredcoveragepercentage transformation.
    Criteria key: requiredCoveragePercentage
    """
    managedSystems: Optional[List[ManagedSystem]] = None
    ManagedSystems: Optional[List[ManagedSystem]] = None
    managedAccounts: Optional[List[ManagedAccountCoverage]] = None
    ManagedAccounts: Optional[List[ManagedAccountCoverage]] = None

    class Config:
        extra = "allow"
