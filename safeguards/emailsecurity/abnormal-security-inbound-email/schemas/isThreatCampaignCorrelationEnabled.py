from pydantic import BaseModel


class IsThreatCampaignCorrelationEnabledInput(BaseModel):
    """Input schema for the isThreatCampaignCorrelationEnabled transformation."""

    class Config:
        extra = "allow"
