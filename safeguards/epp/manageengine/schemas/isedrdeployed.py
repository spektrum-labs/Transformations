"""Schema for isedrdeployed transformation input."""
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ComputerItem(BaseModel):
    """A managed computer from the SOM API."""
    agent_status: Optional[str] = Field(None, description="Agent status (installed, active, online)")
    agentStatus: Optional[str] = Field(None, description="Alternate agent status field")
    hostname: Optional[str] = Field(None, description="Computer hostname")
    os_type: Optional[str] = Field(None, description="Operating system type")

    class Config:
        extra = "allow"


class SOMSummary(BaseModel):
    """Nested SOM summary object."""
    total_computers: Optional[int] = Field(None, description="Total computers in SOM")
    total: Optional[int] = Field(None, description="Alternate total field")
    managed_computers: Optional[int] = Field(None, description="Managed (agent installed) computers")
    managed: Optional[int] = Field(None, description="Alternate managed field")

    class Config:
        extra = "allow"


class IsedrdeployedInput(BaseModel):
    """Expected input schema for the isedrdeployed transformation.
    Criteria key: isEDRDeployed
    Source: ManageEngine Endpoint Central GET /api/1.4/som/summary"""
    total_computers: Optional[int] = Field(None, description="Total computers in scope")
    totalComputers: Optional[int] = Field(None, description="Alternate total field")
    managed_computers: Optional[int] = Field(None, description="Computers with agent installed")
    managedComputers: Optional[int] = Field(None, description="Alternate managed field")
    agent_installed_count: Optional[int] = Field(None, description="Agent installed count")
    agentInstalledCount: Optional[int] = Field(None, description="Alternate agent count field")
    computer_summary: Optional[SOMSummary] = Field(None, description="Nested computer summary")
    computerSummary: Optional[SOMSummary] = Field(None, description="Alternate summary field")
    computers: Optional[List[ComputerItem]] = Field(None, description="List of computers")
    data: Optional[Any] = Field(None, description="Alternate data key")

    class Config:
        extra = "allow"
