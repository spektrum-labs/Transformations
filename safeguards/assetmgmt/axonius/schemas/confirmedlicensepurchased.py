"""Schema for confirmedlicensepurchased transformation input."""

from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class ConfirmedlicensepurchasedInput(BaseModel):
    """
    Expected input schema for the confirmedlicensepurchased transformation.

    Axonius health check API response containing instance and license info.
    """

    build_date: Optional[str] = Field(None, alias="Build Date", description="Axonius instance build date")
    version: Optional[str] = Field(None, alias="Version", description="Axonius instance version")
    subscription: Optional[Dict[str, Any]] = Field(None, description="Subscription information")
    license: Optional[Dict[str, Any]] = Field(None, description="License information")
    active: Optional[bool] = Field(None, description="Whether the instance is active")
    enabled: Optional[bool] = Field(None, description="Whether the instance is enabled")

    class Config:
        extra = "allow"
