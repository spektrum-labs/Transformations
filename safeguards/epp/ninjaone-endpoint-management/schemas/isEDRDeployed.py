from pydantic import BaseModel


class IsEDRDeployedInput(BaseModel):
    """Input schema for the isEDRDeployed transformation (getAntivirusStatusReport response)."""

    class Config:
        extra = "allow"
