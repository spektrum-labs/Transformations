from pydantic import BaseModel


class IsFirewallEnabledInput(BaseModel):
    """Input schema for the isFirewallEnabled transformation."""

    class Config:
        extra = "allow"
