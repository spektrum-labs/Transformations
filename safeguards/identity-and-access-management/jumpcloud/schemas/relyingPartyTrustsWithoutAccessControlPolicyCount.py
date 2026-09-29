from pydantic import BaseModel


class RelyingPartyTrustsWithoutAccessControlPolicyCountInput(BaseModel):
    """Input schema for the relyingPartyTrustsWithoutAccessControlPolicyCount transformation."""

    class Config:
        extra = "allow"
