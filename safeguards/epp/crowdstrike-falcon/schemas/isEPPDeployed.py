from pydantic import BaseModel


class IsEPPDeployedInput(BaseModel):
    """Input schema for the isEPPDeployed transformation."""

    class Config:
        extra = "allow"
