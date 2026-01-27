"""Schema for confirmedlicensepurchased transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ConfirmedlicensepurchasedInput(BaseModel):
    """
    Expected input schema for the confirmedlicensepurchased transformation.
    Criteria key: confirmedlicensepurchased
    """

    isEPPConfigured: Optional[str] = None
    isMDRConfigured: Optional[str] = None

    class Config:
        extra = "allow"
