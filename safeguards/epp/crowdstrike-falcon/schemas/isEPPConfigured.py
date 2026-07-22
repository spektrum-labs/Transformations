from pydantic import BaseModel


class IsEPPConfiguredInput(BaseModel):
    """Input schema for the isEPPConfigured transformation."""

    class Config:
        extra = "allow"
