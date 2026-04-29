from pydantic import BaseModel
from typing import Any, Dict, List, Optional


class UserRecord(BaseModel):
    id: Optional[str] = None
    email: Optional[str] = None
    fullName: Optional[str] = None
    source: Optional[str] = None
    isActive: Optional[bool] = None
    role: Optional[str] = None
    lowestRole: Optional[str] = None
    scope: Optional[str] = None
    primaryTwoFaMethod: Optional[str] = None
    dateJoined: Optional[str] = None
    lastLogin: Optional[str] = None
    firstLogin: Optional[str] = None
    isSystem: Optional[bool] = None

    class Config:
        extra = "allow"


class Pagination(BaseModel):
    nextCursor: Optional[str] = None
    totalItems: Optional[int] = None

    class Config:
        extra = "allow"


class IsSSOEnabledInput(BaseModel):
    """Input schema for the isSSOEnabled transformation.

    Expects a SentinelOne GET /web/api/v2.1/users response.
    The 'source' field on each user record ('local', 'sso', 'scim') is used
    to determine whether SSO is actively in use on the tenant.
    """

    data: Optional[List[UserRecord]] = None
    pagination: Optional[Pagination] = None

    class Config:
        extra = "allow"
