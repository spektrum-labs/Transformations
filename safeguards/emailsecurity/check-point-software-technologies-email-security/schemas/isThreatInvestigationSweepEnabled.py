from pydantic import BaseModel


class IsThreatInvestigationSweepEnabledInput(BaseModel):
    """Input schema for the isThreatInvestigationSweepEnabled transformation."""

    class Config:
        extra = "allow"
