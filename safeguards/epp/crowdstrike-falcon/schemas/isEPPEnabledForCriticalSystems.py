from pydantic import BaseModel


class IsEPPEnabledForCriticalSystemsInput(BaseModel):
    """Input schema for the isEPPEnabledForCriticalSystems transformation."""

    class Config:
        extra = "allow"
