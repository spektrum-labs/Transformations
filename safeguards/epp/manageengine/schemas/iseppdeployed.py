"""Schema for iseppdeployed transformation input."""
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ComputerItem(BaseModel):
    """A managed computer from the SOM API."""
    agent_status: Optional[str] = Field(None, description="Agent status")
    agentStatus: Optional[str] = Field(None, description="Alternate agent status field")
    hostname: Optional[str] = Field(None, description="Computer hostname")

    class Config:
        extra = "allow"


class IseppdeployedInput(BaseModel):
    """Expected input schema for the iseppdeployed transformation.
    Criteria key: isEPPDeployed
    Source: ManageEngine Endpoint Central GET /api/1.4/som/summary"""
    total_computers: Optional[int] = Field(None, description="Total computers in scope")
    totalComputers: Optional[int] = Field(None, description="Alternate total field")
    managed_computers: Optional[int] = Field(None, description="Computers with agent installed")
    managedComputers: Optional[int] = Field(None, description="Alternate managed field")
    agent_installed_count: Optional[int] = Field(None, description="Agent installed count")
    agentInstalledCount: Optional[int] = Field(None, description="Alternate agent count field")
    yet_to_install: Optional[int] = Field(None, description="Endpoints pending agent installation")
    yetToInstall: Optional[int] = Field(None, description="Alternate yet to install field")
    computers: Optional[List[ComputerItem]] = Field(None, description="List of computers")
    data: Optional[Any] = Field(None, description="Alternate data key")

    class Config:
        extra = "allow"
