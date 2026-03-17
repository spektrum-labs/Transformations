"""Schema for iseppdeployed transformation input."""
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field


class EndpointItem(BaseModel):
    """A single endpoint from the ThreatDown Nebula API."""
    status: Optional[str] = Field(None, description="Endpoint status (e.g. online, offline, stale)")
    agent_status: Optional[str] = Field(None, description="Alternate status field")
    agent_version: Optional[str] = Field(None, description="ThreatDown agent version installed")
    agentVersion: Optional[str] = Field(None, description="Alternate agent version field")
    hostname: Optional[str] = Field(None, description="Endpoint hostname")
    os_type: Optional[str] = Field(None, description="Operating system type")

    class Config:
        extra = "allow"


class IseppdeployedInput(BaseModel):
    """Expected input schema for the iseppdeployed transformation.
    Criteria key: isEPPDeployed
    Source: ThreatDown Nebula /nebula/v1/endpoints endpoint."""
    endpoints: Optional[List[EndpointItem]] = Field(None, description="List of endpoints")
    machines: Optional[List[EndpointItem]] = Field(None, description="Alternate key for endpoints list")
    devices: Optional[List[EndpointItem]] = Field(None, description="Alternate key for endpoints list")
    data: Optional[Any] = Field(None, description="Alternate key for nested data")
    results: Optional[List[EndpointItem]] = Field(None, description="Alternate key for endpoints list")
    total_count: Optional[int] = Field(None, description="Total number of endpoints (paginated)")

    class Config:
        extra = "allow"
