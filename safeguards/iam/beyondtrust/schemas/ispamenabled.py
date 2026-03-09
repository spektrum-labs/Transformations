"""Schema for ispamenabled transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ManagedAccount(BaseModel):
    """A single managed account entry."""

    class Config:
        extra = "allow"


class IspamenabledInput(BaseModel):
    """
    Expected input schema for the ispamenabled transformation.
    Criteria key: isPAMEnabled
    """
    ManagedAccounts: Optional[List[ManagedAccount]] = None
    items: Optional[List[ManagedAccount]] = None
    results: Optional[List[ManagedAccount]] = None

    class Config:
        extra = "allow"
