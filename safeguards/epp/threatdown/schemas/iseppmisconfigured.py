"""Schema for iseppmisconfigured transformation input."""
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field


class PolicyItem(BaseModel):
    """A single policy from the ThreatDown Nebula API."""
    name: Optional[str] = Field(None, description="Policy name")
    policyName: Optional[str] = Field(None, description="Alternate policy name field")
    real_time_protection: Optional[Union[bool, str]] = Field(None, description="Real-time protection enabled")
    realTimeProtection: Optional[Union[bool, str]] = Field(None, description="Alternate RTP field")
    rtp: Optional[Union[bool, str]] = Field(None, description="Alternate RTP field")
    scan_schedule: Optional[Union[bool, str, Dict]] = Field(None, description="Scheduled scanning config")
    scheduledScan: Optional[Union[bool, str]] = Field(None, description="Alternate scan schedule field")
    tamper_protection: Optional[Union[bool, str]] = Field(None, description="Tamper protection enabled")
    tamperProtection: Optional[Union[bool, str]] = Field(None, description="Alternate tamper protection field")
    quarantine: Optional[Union[bool, str]] = Field(None, description="Auto-quarantine enabled")
    autoQuarantine: Optional[Union[bool, str]] = Field(None, description="Alternate quarantine field")

    class Config:
        extra = "allow"


class IseppmisconfiguredInput(BaseModel):
    """Expected input schema for the iseppmisconfigured transformation.
    Criteria key: isEPPMisconfigured
    Source: ThreatDown Nebula /nebula/v1/policies endpoint."""
    policies: Optional[List[PolicyItem]] = Field(None, description="List of policies")
    data: Optional[Any] = Field(None, description="Alternate key for nested data")
    results: Optional[List[PolicyItem]] = Field(None, description="Alternate key for policies list")

    class Config:
        extra = "allow"
