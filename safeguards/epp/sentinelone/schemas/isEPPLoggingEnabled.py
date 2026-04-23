"""Schema for isEPPLoggingEnabled transformation input."""
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


class AgentLoggingRecord(BaseModel):
    """A single endpoint agent record used for logging status evaluation."""
    id: Optional[str] = Field(None, description="Agent identifier")
    uuid: Optional[str] = Field(None, description="Agent UUID")
    computerName: Optional[str] = Field(None, description="Endpoint computer name")
    hostname: Optional[str] = Field(None, description="Endpoint hostname")
    agentVersion: Optional[str] = Field(None, description="Installed agent version string")
    isActive: Optional[bool] = Field(None, description="Whether the agent is actively reporting")
    isUninstalled: Optional[bool] = Field(None, description="Whether the agent has been uninstalled")
    lastActiveDate: Optional[str] = Field(None, description="Timestamp of last agent activity - key logging indicator")
    scanStatus: Optional[str] = Field(None, description="Current scan status, e.g. finished, none, full")
    lastLoggedInUserName: Optional[str] = Field(None, description="Last user logged into the endpoint")
    threatCount: Optional[int] = Field(None, description="Number of active threats detected")

    class Config:
        extra = "allow"


class IsEPPLoggingEnabledInput(BaseModel):
    """Expected input shape for the isEPPLoggingEnabled transformation."""
    data: Optional[Union[List[AgentLoggingRecord], Dict[str, Any]]] = Field(None, description="List of agent records or wrapper dict")
    pagination: Optional[Dict[str, Any]] = Field(None, description="Pagination metadata")
    getEndpoints: Optional[Dict[str, Any]] = Field(None, description="Merged method result from getEndpoints")

    class Config:
        extra = "allow"
