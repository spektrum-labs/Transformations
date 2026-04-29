from pydantic import BaseModel
from typing import Any, Dict, List, Optional


class SkuItem(BaseModel):
    agentsInSku: Optional[int] = None
    totalLicenses: Optional[int] = None
    type: Optional[str] = None
    unlimited: Optional[bool] = None

    class Config:
        extra = "allow"


class AccountItem(BaseModel):
    id: Optional[str] = None
    name: Optional[str] = None
    accountType: Optional[str] = None
    activeAgents: Optional[int] = None
    billingMode: Optional[str] = None
    totalLicenses: Optional[int] = None
    unlimitedComplete: Optional[bool] = None
    unlimitedControl: Optional[bool] = None
    unlimitedCore: Optional[bool] = None
    skus: Optional[List[SkuItem]] = None
    state: Optional[str] = None

    class Config:
        extra = "allow"


class PaginationInfo(BaseModel):
    nextCursor: Optional[str] = None
    totalItems: Optional[int] = None

    class Config:
        extra = "allow"


class RequiredCoveragePercentageInput(BaseModel):
    """Input schema for the requiredCoveragePercentage transformation."""
    data: Optional[List[AccountItem]] = None
    pagination: Optional[PaginationInfo] = None

    class Config:
        extra = "allow"
