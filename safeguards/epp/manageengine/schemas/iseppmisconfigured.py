"""Schema for iseppmisconfigured transformation input."""
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field


class HealthPolicyItem(BaseModel):
    """A patch health policy from the Endpoint Central API."""
    policy_name: Optional[str] = Field(None, description="Policy name")
    policyName: Optional[str] = Field(None, description="Alternate policy name field")
    name: Optional[str] = Field(None, description="Alternate name field")
    enabled: Optional[Union[bool, str]] = Field(None, description="Whether policy is enabled")
    is_enabled: Optional[Union[bool, str]] = Field(None, description="Alternate enabled field")
    status: Optional[str] = Field(None, description="Policy status")
    scan_enabled: Optional[Union[bool, str]] = Field(None, description="Automatic scanning enabled")
    scanEnabled: Optional[Union[bool, str]] = Field(None, description="Alternate scan enabled field")
    auto_scan: Optional[Union[bool, str]] = Field(None, description="Alternate auto scan field")
    notify_enabled: Optional[Union[bool, str]] = Field(None, description="Notifications enabled")
    auto_approve_critical: Optional[Union[bool, str]] = Field(None, description="Auto-approve critical patches")
    health_status: Optional[str] = Field(None, description="Current health status")
    healthStatus: Optional[str] = Field(None, description="Alternate health status field")

    class Config:
        extra = "allow"


class IseppmisconfiguredInput(BaseModel):
    """Expected input schema for the iseppmisconfigured transformation.
    Criteria key: isEPPMisconfigured
    Source: ManageEngine Endpoint Central GET /api/1.4/patch/healthpolicy"""
    health_policies: Optional[List[HealthPolicyItem]] = Field(None, description="List of health policies")
    healthPolicies: Optional[List[HealthPolicyItem]] = Field(None, description="Alternate policies field")
    policies: Optional[List[HealthPolicyItem]] = Field(None, description="Alternate policies field")
    data: Optional[Any] = Field(None, description="Alternate data key")

    class Config:
        extra = "allow"
