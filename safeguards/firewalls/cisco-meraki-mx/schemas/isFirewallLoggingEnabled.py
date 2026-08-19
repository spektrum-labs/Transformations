from pydantic import BaseModel


class IsFirewallLoggingEnabledInput(BaseModel):
    """Input schema for the isFirewallLoggingEnabled transformation."""

    class Config:
        extra = "allow"
