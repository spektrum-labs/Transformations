"""Schema for isbehavioralmonitoringvalid transformation input."""
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field


class PolicyItem(BaseModel):
    """A single policy from the ThreatDown Nebula API."""
    name: Optional[str] = Field(None, description="Policy name")
    policyName: Optional[str] = Field(None, description="Alternate policy name field")
    behavioral_monitoring: Optional[Union[bool, str, Dict]] = Field(None, description="Behavioral monitoring settings")
    behavioralMonitoring: Optional[Union[bool, str, Dict]] = Field(None, description="Alternate behavioral monitoring field")
    anomaly_detection: Optional[Union[bool, str, Dict]] = Field(None, description="Anomaly detection settings")
    anomalyDetection: Optional[Union[bool, str, Dict]] = Field(None, description="Alternate anomaly detection field")
    edr: Optional[Union[bool, str, Dict]] = Field(None, description="EDR settings")
    endpoint_detection: Optional[Union[bool, str, Dict]] = Field(None, description="Endpoint detection settings")
    endpointDetection: Optional[Union[bool, str, Dict]] = Field(None, description="Alternate endpoint detection field")
    suspicious_activity: Optional[Union[bool, str, Dict]] = Field(None, description="Suspicious activity monitoring")
    suspiciousActivity: Optional[Union[bool, str, Dict]] = Field(None, description="Alternate suspicious activity field")
    real_time_protection: Optional[Union[bool, str]] = Field(None, description="Real-time protection enabled")
    realTimeProtection: Optional[Union[bool, str]] = Field(None, description="Alternate RTP field")
    rtp: Optional[Union[bool, str]] = Field(None, description="Alternate RTP field")

    class Config:
        extra = "allow"


class IsbehavioralmonitoringvalidInput(BaseModel):
    """Expected input schema for the isbehavioralmonitoringvalid transformation.
    Criteria key: isBehavioralMonitoringValid
    Source: ThreatDown Nebula /nebula/v1/policies endpoint."""
    policies: Optional[List[PolicyItem]] = Field(None, description="List of policies")
    data: Optional[Any] = Field(None, description="Alternate key for nested data")
    results: Optional[List[PolicyItem]] = Field(None, description="Alternate key for policies list")

    class Config:
        extra = "allow"
