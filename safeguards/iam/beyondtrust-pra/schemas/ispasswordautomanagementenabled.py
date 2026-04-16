"""Schema for ispasswordautomanagementenabled transformation input (BeyondTrust PRA)."""
from typing import Any, List, Optional, Union
from pydantic import BaseModel, Field


class VaultAccountRotation(BaseModel):
    id: Optional[int] = None
    name: Optional[str] = None
    type: Optional[str] = Field(None, description="Account type")
    automatic_password_rotation: Optional[Union[bool, str]] = Field(None, description="Whether automatic password rotation is enabled")
    rotation_interval_in_days: Optional[Union[int, float]] = Field(None, description="Rotation interval in days (>0 indicates rotation configured)")

    class Config:
        extra = "allow"


class IspasswordautomanagementenabledInput(BaseModel):
    """Expected input: response from GET /api/config/v1/vault/account."""
    accounts: Optional[List[VaultAccountRotation]] = Field(None, description="List of vault accounts with rotation settings")

    class Config:
        extra = "allow"
