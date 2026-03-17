"""Schema for ispatchmanagementenabled transformation input."""
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field


class VulnScanConfig(BaseModel):
    """Vulnerability scan configuration within a policy."""
    enabled: Optional[Union[bool, str]] = Field(None, description="Whether vulnerability scanning is enabled")
    active: Optional[Union[bool, str]] = Field(None, description="Alternate enabled field")
    schedule: Optional[str] = Field(None, description="Scan schedule/frequency")
    frequency: Optional[str] = Field(None, description="Alternate schedule field")

    class Config:
        extra = "allow"


class PolicyItem(BaseModel):
    """A single policy from the ThreatDown Nebula API."""
    name: Optional[str] = Field(None, description="Policy name")
    policyName: Optional[str] = Field(None, description="Alternate policy name field")
    vulnerability_scan: Optional[Union[bool, VulnScanConfig]] = Field(None, description="Vulnerability scan settings")
    vulnerabilityScan: Optional[Union[bool, VulnScanConfig]] = Field(None, description="Alternate vuln scan field")
    patch_management: Optional[Union[bool, Dict]] = Field(None, description="Patch management settings")
    patchManagement: Optional[Union[bool, Dict]] = Field(None, description="Alternate patch mgmt field")
    software_updates: Optional[Union[bool, Dict]] = Field(None, description="Software update settings")
    softwareUpdates: Optional[Union[bool, Dict]] = Field(None, description="Alternate software updates field")

    class Config:
        extra = "allow"


class IspatchmanagementenabledInput(BaseModel):
    """Expected input schema for the ispatchmanagementenabled transformation.
    Criteria key: isPatchManagementEnabled
    Source: ThreatDown Nebula /nebula/v1/policies endpoint."""
    policies: Optional[List[PolicyItem]] = Field(None, description="List of policies")
    data: Optional[Any] = Field(None, description="Alternate key for nested data")
    results: Optional[List[PolicyItem]] = Field(None, description="Alternate key for policies list")

    class Config:
        extra = "allow"
