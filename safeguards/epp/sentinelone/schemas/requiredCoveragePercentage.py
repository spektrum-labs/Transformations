from pydantic import BaseModel
from typing import Any, Dict, List, Optional


class PaginationModel(BaseModel):
    nextCursor: Optional[str] = None
    totalItems: Optional[int] = None

    class Config:
        extra = "allow"


class AgentItem(BaseModel):
    id: Optional[str] = None
    computerName: Optional[str] = None
    isActive: Optional[bool] = None
    isDecommissioned: Optional[bool] = None
    isPendingUninstall: Optional[bool] = None
    isUninstalled: Optional[bool] = None
    isUpToDate: Optional[bool] = None
    activeThreats: Optional[int] = None
    mitigationMode: Optional[str] = None
    networkStatus: Optional[str] = None
    agentVersion: Optional[str] = None
    osType: Optional[str] = None
    siteName: Optional[str] = None

    class Config:
        extra = "allow"


class RequiredCoveragePercentageInput(BaseModel):
    """Input schema for the requiredCoveragePercentage transformation.

    Expects the SentinelOne getAgents response shape with a data array of
    agent records and a pagination object containing totalItems.
    """
    data: Optional[List[AgentItem]] = None
    pagination: Optional[PaginationModel] = None

    class Config:
        extra = "allow"
