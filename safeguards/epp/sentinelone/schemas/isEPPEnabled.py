"""Schema for isEPPEnabled transformation input."""
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


class AgentRecord(BaseModel):
    """A single endpoint agent record from /agents endpoint."""
    id: Optional[str] = Field(None, description="Agent identifier")
    uuid: Optional[str] = Field(None, description="Agent UUID")
    computerName: Optional[str] = Field(None, description="Endpoint computer name")
    hostname: Optional[str] = Field(None, description="Endpoint hostname")
    agentVersion: Optional[str] = Field(None, description="Installed agent version")
    isActive: Optional[bool] = Field(None, description="Whether the agent is active")
    isUninstalled: Optional[bool] = Field(None, description="Whether the agent has been uninstalled")
    networkStatus: Optional[str] = Field(None, description="Agent network connection status")
    threatCount: Optional[int] = Field(None, description="Number of active threats detected")
    infected: Optional[bool] = Field(None, description="Whether the endpoint is infected")
    lastActiveDate: Optional[str] = Field(None, description="Last activity timestamp")
    scanStatus: Optional[str] = Field(None, description="Current scan status")

    class Config:
        extra = "allow"


class IsEPPEnabledInput(BaseModel):
    """Expected input shape for the isEPPEnabled transformation."""
    data: Optional[Union[List[AgentRecord], Dict[str, Any]]] = Field(None, description="List of agent records or wrapper dict")
    pagination: Optional[Dict[str, Any]] = Field(None, description="Pagination metadata")
    getEndpoints: Optional[Dict[str, Any]] = Field(None, description="Merged method result from getEndpoints")

    class Config:
        extra = "allow"
