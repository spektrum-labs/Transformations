from pydantic import BaseModel


class IsThreatIntelIOCLookupEnabledInput(BaseModel):
    """Input schema for the isThreatIntelIOCLookupEnabled transformation."""

    class Config:
        extra = "allow"
