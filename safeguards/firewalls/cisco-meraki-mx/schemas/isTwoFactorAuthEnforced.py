from pydantic import BaseModel


class IsTwoFactorAuthEnforcedInput(BaseModel):
    """Input schema for the isTwoFactorAuthEnforced transformation."""

    class Config:
        extra = "allow"
