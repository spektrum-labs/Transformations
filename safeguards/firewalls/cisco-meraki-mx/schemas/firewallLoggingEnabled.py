from pydantic import BaseModel


class FirewallLoggingEnabledInput(BaseModel):
    """Input schema for the firewallLoggingEnabled transformation."""

    class Config:
        extra = "allow"
