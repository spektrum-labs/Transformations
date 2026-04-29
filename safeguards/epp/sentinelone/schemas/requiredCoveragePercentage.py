from pydantic import BaseModel
from typing import Optional


class RequiredCoveragePercentageInput(BaseModel):
    """Input schema for the requiredCoveragePercentage transformation.

    Represents the response shape from SentinelOne GET /web/api/v2.1/agents/count.
    The 'data' object contains aggregate agent count scalars.
    """

    class CountData(BaseModel):
        total: Optional[int] = None
        upToDate: Optional[int] = None
        outOfDate: Optional[int] = None
        online: Optional[int] = None
        infected: Optional[int] = None
        decommissioned: Optional[int] = None

        class Config:
            extra = "allow"

    data: Optional[CountData] = None

    class Config:
        extra = "allow"
