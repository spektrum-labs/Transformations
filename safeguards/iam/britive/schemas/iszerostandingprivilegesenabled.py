"""Schema for iszerostandingprivilegesenabled transformation input."""
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field


class ProfileRecord(BaseModel):
    """Individual privileged access profile (PAP) from Britive /api/apps/{appId}/paps."""
    papId: Optional[str] = Field(None, description="Profile identifier")
    name: Optional[str] = Field(None, description="Profile name")
    status: Optional[str] = Field(None, description="Profile status (active/inactive)")
    expirationInMinutes: Optional[Union[int, str]] = Field(None, description="Profile expiration time in minutes (0 = no expiry)")
    sessionDuration: Optional[Union[int, str, None]] = Field(None, description="Session duration limit")

    class Config:
        extra = "allow"


class IszerostandingprivilegesenabledInput(BaseModel):
    """Expected input schema for the iszerostandingprivilegesenabled transformation. Criteria key: isZeroStandingPrivilegesEnabled"""
    profiles: Optional[List[ProfileRecord]] = Field(None, description="List of privileged access profile objects")
    data: Optional[List[ProfileRecord]] = Field(None, description="Alternate list of profile objects")
    paps: Optional[List[ProfileRecord]] = Field(None, description="Alternate list of PAP objects")

    class Config:
        extra = "allow"
