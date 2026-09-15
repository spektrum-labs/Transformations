from pydantic import BaseModel


class IsSPFEnforcedInput(BaseModel):
    """Input schema for the isSPFEnforced transformation."""

    class Config:
        extra = "allow"
