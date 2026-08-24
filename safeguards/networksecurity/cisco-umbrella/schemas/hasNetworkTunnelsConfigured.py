from pydantic import BaseModel


class HasNetworkTunnelsConfiguredInput(BaseModel):
    """Input schema for the hasNetworkTunnelsConfigured transformation."""

    class Config:
        extra = "allow"
