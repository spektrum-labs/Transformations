"""Schema for isidpenabled transformation input."""

from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class IsidpenabledInput(BaseModel):
    """
    Expected input schema for the isidpenabled transformation.
    Criteria key: isSSOEnabled

    Validates that SSO/IDP is enabled for the endpoint protection
    platform, including MDR SSO status.
    """

    isSSOEnabled: Optional[bool] = None
    isSSOEnabledMDR: Optional[bool] = None

    class Config:
        extra = "allow"
