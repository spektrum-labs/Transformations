"""Schema for ismdrenabled transformation input."""
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class CompanyFeaturesMDR(BaseModel):
    """Features block within company object."""
    mdr_service: Optional[Any] = Field(None, description="MDR service feature flag (bool or string)")

    class Config:
        extra = "allow"


class CompanyMDR(BaseModel):
    """Company object containing subscription and feature details."""
    subscription_status: Optional[str] = Field(None, description="Subscription status (e.g. active, trial, enterprise)")
    features: Optional[CompanyFeaturesMDR] = Field(None, description="Feature flags for the company subscription")

    class Config:
        extra = "allow"


class IsmdrennabledInput(BaseModel):
    """Expected input schema for the ismdrenabled transformation. Criteria key: isMDREnabled"""
    is_active: Optional[bool] = Field(None, description="Whether the user account is active")
    company: Optional[CompanyMDR] = Field(None, description="Company object containing subscription and feature details")

    class Config:
        extra = "allow"
