from pydantic import BaseModel


class IsEPPDeployedInput(BaseModel):
    """Input schema for the isEPPDeployed transformation (getAntivirusStatus response)."""

    class Config:
        extra = "allow"
