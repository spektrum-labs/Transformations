"""Schema for confirmedlicensepurchased transformation input."""
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class UserRecord(BaseModel):
    """Individual user record from Britive /api/users."""
    status: Optional[str] = None

    class Config:
        extra = "allow"


class ConfirmedlicensepurchasedInput(BaseModel):
    """Expected input schema for the confirmedlicensepurchased transformation. Criteria key: confirmedLicensePurchased"""
    count: Optional[int] = Field(None, description="Total number of users")
    totalCount: Optional[int] = Field(None, description="Alternate total count field")
    data: Optional[List[UserRecord]] = Field(None, description="List of user records")
    users: Optional[List[UserRecord]] = Field(None, description="Alternate list of user records")

    class Config:
        extra = "allow"
