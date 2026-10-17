from pydantic import BaseModel


class HasThreatIntelligenceFeedIntegrationInput(BaseModel):
    """Input schema for the hasThreatIntelligenceFeedIntegration transformation."""

    class Config:
        extra = "allow"
