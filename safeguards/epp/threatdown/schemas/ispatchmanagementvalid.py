"""Schema for ispatchmanagementvalid transformation input."""
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field


class VulnScanConfig(BaseModel):
    """Vulnerability scan configuration within a policy."""
    enabled: Optional[Union[bool, str]] = Field(None, description="Whether vulnerability scanning is enabled")
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
    auto_remediate: Optional[Union[bool, str]] = Field(None, description="Auto-remediation enabled")
    autoRemediate: Optional[Union[bool, str]] = Field(None, description="Alternate auto-remediate field")
    auto_patch: Optional[Union[bool, str]] = Field(None, description="Alternate auto-patch field")

    class Config:
        extra = "allow"


class IspatchmanagementvalidInput(BaseModel):
    """Expected input schema for the ispatchmanagementvalid transformation.
    Criteria key: isPatchManagementValid
    Source: ThreatDown Nebula /nebula/v1/policies endpoint."""
    policies: Optional[List[PolicyItem]] = Field(None, description="List of policies")
    data: Optional[Any] = Field(None, description="Alternate key for nested data")
    results: Optional[List[PolicyItem]] = Field(None, description="Alternate key for policies list")

    class Config:
        extra = "allow"
