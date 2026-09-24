from pydantic import BaseModel


class HasEmergencyAccessCodeAPIAccessInput(BaseModel):
    """Input schema for the hasEmergencyAccessCodeAPIAccess transformation."""

    class Config:
        extra = "allow"
