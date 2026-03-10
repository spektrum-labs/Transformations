"""Schema for isssoenforced transformation input."""
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class UserRecord(BaseModel):
    """A single user entry from the SAFE users endpoint."""

    authenticationType: Optional[str] = Field(None, description="Authentication method for the user (e.g. SSO, Native)")

    class Config:
        extra = "allow"


class IsssoenforcedInput(BaseModel):
    """Expected input schema for the isssoenforced transformation. Criteria key: isSSOEnforced"""

    values: Optional[List[UserRecord]] = Field(None, description="List of user records from the SAFE platform")
    users: Optional[List[UserRecord]] = Field(None, description="Alternate key for user records")

    class Config:
        extra = "allow"
