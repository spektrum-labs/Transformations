"""Schema for confirmedlicensepurchased transformation input."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ConfirmedlicensepurchasedInput(BaseModel):
    """
    Expected input schema for the confirmedlicensepurchased transformation.
    Criteria key: confirmedlicensepurchased
    """

    odata_context: Optional[str] = Field(default=None, alias="@odata.context")
    value: Optional[List[Optional[Dict[str, Any]]]] = None

    class Config:
        extra = "allow"
