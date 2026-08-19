from pydantic import BaseModel


class IsFirewallPerformantInput(BaseModel):
    """Input schema for the isFirewallPerformant transformation."""

    class Config:
        extra = "allow"
