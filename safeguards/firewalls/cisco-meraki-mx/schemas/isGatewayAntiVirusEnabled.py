from pydantic import BaseModel


class IsGatewayAntiVirusEnabledInput(BaseModel):
    """Input schema for the isGatewayAntiVirusEnabled transformation."""

    class Config:
        extra = "allow"
