"""Schema for areadminaccountsseparate transformation input."""
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class AdminRoleRecord(BaseModel):
    """Admin role assigned to a user."""
    name: Optional[str] = Field(None, description="Role name (e.g. TenantAdmin)")
    displayName: Optional[str] = Field(None, description="Human-readable role name")

    class Config:
        extra = "allow"


class UserRecord(BaseModel):
    """Individual user record from Britive /api/users."""
    userId: Optional[str] = Field(None, description="User identifier")
    username: Optional[str] = Field(None, description="Username")
    status: Optional[str] = Field(None, description="User status (active/inactive)")
    type: Optional[str] = Field(None, description="Account type (User/ServiceIdentity)")
    adminRoles: Optional[List[AdminRoleRecord]] = Field(None, description="List of admin roles assigned to the user")

    class Config:
        extra = "allow"


class AreadminaccountsseparateInput(BaseModel):
    """Expected input schema for the areadminaccountsseparate transformation. Criteria key: areAdminAccountsSeparate"""
    count: Optional[int] = Field(None, description="Total number of users")
    data: Optional[List[UserRecord]] = Field(None, description="List of user records")
    users: Optional[List[UserRecord]] = Field(None, description="Alternate list of user records")

    class Config:
        extra = "allow"
