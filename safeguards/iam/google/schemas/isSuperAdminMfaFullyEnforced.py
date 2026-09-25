from pydantic import BaseModel


class IsSuperAdminMfaFullyEnforcedInput(BaseModel):
    """Input schema for the isSuperAdminMfaFullyEnforced transformation."""

    class Config:
        extra = "allow"
