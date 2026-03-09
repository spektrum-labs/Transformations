"""Schema for istakedownserviceenabled transformation input."""
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class CompanyFeaturesTakedown(BaseModel):
    """Features block within company object."""
    takedown_services: Optional[Any] = Field(None, description="Takedown services feature flag (bool or string)")

    class Config:
        extra = "allow"


class CompanyTakedown(BaseModel):
    """Company object containing subscription plan and feature details."""
    features: Optional[CompanyFeaturesTakedown] = Field(None, description="Feature flags for the company subscription")
    subscription_plan: Optional[str] = Field(None, description="Subscription plan name (e.g. enterprise, enterprise_plus, premium)")

    class Config:
        extra = "allow"


class IstakedownserviceenabledInput(BaseModel):
    """Expected input schema for the istakedownserviceenabled transformation. Criteria key: isTakedownServiceEnabled"""
    company: Optional[CompanyTakedown] = Field(None, description="Company object containing subscription plan and feature details")

    class Config:
        extra = "allow"
