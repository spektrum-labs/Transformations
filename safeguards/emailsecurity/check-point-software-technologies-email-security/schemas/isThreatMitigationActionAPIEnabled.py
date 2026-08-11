from pydantic import BaseModel


class IsThreatMitigationActionAPIEnabledInput(BaseModel):
    """Input schema for the isThreatMitigationActionAPIEnabled transformation."""

    class Config:
        extra = "allow"
