from pydantic import BaseModel


class IsThreatIntelIntegratedInput(BaseModel):
    """Input schema for the isThreatIntelIntegrated transformation."""

    class Config:
        extra = "allow"
