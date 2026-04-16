"""Schema for ispasswordrotationonreleaseenabled transformation input (BeyondTrust PRA)."""
from typing import Any, List, Optional, Union
from pydantic import BaseModel, Field


class VaultAccountRotationOnRelease(BaseModel):
    id: Optional[int] = None
    name: Optional[str] = None
    password_rotation_on_release: Optional[Union[bool, str]] = Field(None, description="Whether to rotate the password after session release")

    class Config:
        extra = "allow"


class IspasswordrotationonreleaseenabledInput(BaseModel):
    """Expected input: response from GET /api/config/v1/vault/account."""
    accounts: Optional[List[VaultAccountRotationOnRelease]] = Field(None, description="List of vault accounts")

    class Config:
        extra = "allow"
