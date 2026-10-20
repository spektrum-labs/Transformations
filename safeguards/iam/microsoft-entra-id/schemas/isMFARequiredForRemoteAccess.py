from pydantic import BaseModel


class IsMFARequiredForRemoteAccessInput(BaseModel):
    """Input schema for the isMFARequiredForRemoteAccess transformation."""

    class Config:
        extra = "allow"
