"""Schema for ismfaenforced_admins transformation input."""
from typing import List, Optional, Union

from pydantic import BaseModel, Field


class AdminAccount(BaseModel):
    """An individual admin account entry."""

    active: Optional[Union[bool, str]] = Field(None, description="Whether the account is active (bool or string)")
    roles: Optional[Union[List[str], str]] = Field(None, description="Roles assigned to the account (e.g. ADMINISTRATOR, AUDITOR, USER_ADMIN)")

    class Config:
        extra = "allow"


class IsmfaenforcedAdminsInput(BaseModel):
    """Expected input schema for the ismfaenforced_admins transformation. Criteria key: isMFAEnforcedAdmins"""

    items: Optional[List[AdminAccount]] = Field(None, description="List of admin account entries")

    class Config:
        extra = "allow"
