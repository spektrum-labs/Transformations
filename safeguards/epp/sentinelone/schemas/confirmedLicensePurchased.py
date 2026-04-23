"""Schema for confirmedLicensePurchased transformation input."""
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


class AccountLicenseInfo(BaseModel):
    """Represents a single SentinelOne account from /accounts endpoint."""
    id: Optional[str] = Field(None, description="Account identifier")
    name: Optional[str] = Field(None, description="Account name")
    state: Optional[str] = Field(None, description="Account state, e.g. active, inactive")
    accountType: Optional[str] = Field(None, description="Account type, e.g. Trial, Paid, Enterprise")
    activeLicenses: Optional[int] = Field(None, description="Number of active licenses")
    totalLicenses: Optional[int] = Field(None, description="Total licenses purchased")
    expiration: Optional[str] = Field(None, description="License expiration date")
    createdAt: Optional[str] = Field(None, description="Account creation timestamp")
    updatedAt: Optional[str] = Field(None, description="Account last update timestamp")

    class Config:
        extra = "allow"


class ConfirmedLicensePurchasedInput(BaseModel):
    """Expected input shape for the confirmedLicensePurchased transformation."""
    data: Optional[Union[List[AccountLicenseInfo], Dict[str, Any]]] = Field(None, description="List of account objects or wrapper dict")
    pagination: Optional[Dict[str, Any]] = Field(None, description="Pagination metadata")
    checkLicenseStatus: Optional[Dict[str, Any]] = Field(None, description="Merged method result from checkLicenseStatus")

    class Config:
        extra = "allow"
