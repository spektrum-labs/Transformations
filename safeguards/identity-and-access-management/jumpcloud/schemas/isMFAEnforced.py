from pydantic import BaseModel


class IsMFAEnforcedInput(BaseModel):
    """Input schema for the isMFAEnforced transformation."""

    class Config:
        extra = "allow"
