"""Schema for confirmedlicensepurchased transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ConfirmedlicensepurchasedInput(BaseModel):
    """
    Expected input schema for the confirmedlicensepurchased transformation.
    Criteria key: confirmedlicensepurchased
    """

    message: Optional[str] = None
    status: Optional[str] = None

    class Config:
        extra = "allow"
