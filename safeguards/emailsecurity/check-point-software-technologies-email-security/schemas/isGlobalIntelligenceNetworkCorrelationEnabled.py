from pydantic import BaseModel


class IsGlobalIntelligenceNetworkCorrelationEnabledInput(BaseModel):
    """Input schema for the isGlobalIntelligenceNetworkCorrelationEnabled transformation."""

    class Config:
        extra = "allow"
