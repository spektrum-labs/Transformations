"""Schema for requiredCoveragePercentage transformation input."""
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


class AgentCoverageRecord(BaseModel):
    """A single endpoint agent record used for coverage calculation."""
    id: Optional[str] = Field(None, description="Agent identifier")
    uuid: Optional[str] = Field(None, description="Agent UUID")
    computerName: Optional[str] = Field(None, description="Endpoint computer name")
    hostname: Optional[str] = Field(None, description="Endpoint hostname")
    agentVersion: Optional[str] = Field(None, description="Installed agent version string - key coverage indicator")
    isActive: Optional[bool] = Field(None, description="Whether the agent is actively reporting")
    isUninstalled: Optional[bool] = Field(None, description="Whether the agent has been uninstalled")
    networkStatus: Optional[str] = Field(None, description="Agent network connection status")
    lastActiveDate: Optional[str] = Field(None, description="Timestamp of last agent activity")

    class Config:
        extra = "allow"


class RequiredCoveragePercentageInput(BaseModel):
    """Expected input shape for the requiredCoveragePercentage transformation."""
    data: Optional[Union[List[AgentCoverageRecord], Dict[str, Any]]] = Field(None, description="List of agent records or wrapper dict")
    pagination: Optional[Dict[str, Any]] = Field(None, description="Pagination metadata")
    getEndpoints: Optional[Dict[str, Any]] = Field(None, description="Merged method result from getEndpoints")

    class Config:
        extra = "allow"
