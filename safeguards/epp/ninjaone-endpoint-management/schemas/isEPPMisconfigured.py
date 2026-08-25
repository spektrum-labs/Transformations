from pydantic import BaseModel


class IsEPPMisconfiguredInput(BaseModel):
    """Input schema for the isEPPMisconfigured transformation."""

    class Config:
        extra = "allow"
