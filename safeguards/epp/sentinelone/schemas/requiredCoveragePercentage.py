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
    totalLicenses: Optional[int] = None
    unlimitedComplete: Optional[bool] = None
    unlimitedControl: Optional[bool] = None
    unlimitedCore: Optional[bool] = None
    billingMode: Optional[str] = None
    state: Optional[str] = None
    skus: Optional[List[SkuItem]] = None
    licenses: Optional[Dict[str, Any]] = None

    class Config:
        extra = "allow"


class PaginationInfo(BaseModel):
    nextCursor: Optional[str] = None
    totalItems: Optional[int] = None

    class Config:
        extra = "allow"


class RequiredCoveragePercentageInput(BaseModel):
    """Input schema for the requiredCoveragePercentage transformation.

    Expects the getAccounts API response containing account records with
    activeAgents counts and license information (totalLicenses, unlimited flags, skus).
    """
    data: Optional[List[AccountItem]] = None
    pagination: Optional[PaginationInfo] = None

    class Config:
        extra = "allow"
