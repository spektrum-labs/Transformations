from pydantic import BaseModel
from typing import Optional, List, Any


class IsThreatCampaignCorrelationEnabledInput(BaseModel):
    """Input schema for the isThreatCampaignCorrelationEnabled transformation.

    Expects the payload returned by GET /v1/threats (getThreats), a page of
    threatId-keyed threat records with a total count, optionally wrapped in
    the runtime's enriched {data, validation} envelope or a legacy
    apiResponse wrapper.
    """
    total: Optional[int] = None
    threats: Optional[List[Any]] = None
    pageNumber: Optional[int] = None
    nextPageNumber: Optional[int] = None

    class Config:
        extra = "allow"
