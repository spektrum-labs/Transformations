"""Schema for requiredcoveragepercentage transformation input."""

from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


class AdminSetState(BaseModel):
    """Admin-set state for an endpoint."""

    enabled: Optional[Union[bool, str]] = None

    class Config:
        extra = "allow"


class Endpoint(BaseModel):
    """An endpoint enrolled in Dope Security."""

    status: Optional[str] = None
    adminSetState: Optional[Union[AdminSetState, bool]] = None
    deviceName: Optional[str] = None
    emailId: Optional[str] = None

    class Config:
        extra = "allow"


class PageInfo(BaseModel):
    """Pagination info for the API response."""

    hasNextPage: Optional[bool] = None

    class Config:
        extra = "allow"


class DataPayload(BaseModel):
    """Inner data payload containing endpoints and pagination info."""

    endpoints: Optional[List[Endpoint]] = None
    pageInfo: Optional[PageInfo] = None

    class Config:
        extra = "allow"


class RequiredcoveragepercentageInput(BaseModel):
    """Expected input schema for the requiredcoveragepercentage transformation. Criteria key: requiredCoveragePercentage"""

    data: Optional[DataPayload] = None

    class Config:
        extra = "allow"
