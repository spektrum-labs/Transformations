from pydantic import BaseModel

class IsMFAEnforcedForUsersInput(BaseModel):
    """Input schema for the isMFAEnforcedForUsers transformation."""
    class Config:
        extra = "allow"
