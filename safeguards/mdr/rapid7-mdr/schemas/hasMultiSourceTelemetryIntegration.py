from pydantic import BaseModel


class HasMultiSourceTelemetryIntegrationInput(BaseModel):
    """Input schema for the hasMultiSourceTelemetryIntegration transformation."""

    class Config:
        extra = "allow"
