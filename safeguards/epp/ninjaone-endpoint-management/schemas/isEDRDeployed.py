from pydantic import BaseModel


class IsEDRDeployedInput(BaseModel):
    """Input schema for the isEDRDeployed transformation."""

    class Config:
        extra = "allow"
