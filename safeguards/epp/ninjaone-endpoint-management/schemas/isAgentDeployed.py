from pydantic import BaseModel


class IsAgentDeployedInput(BaseModel):
    """Input schema for the isAgentDeployed transformation."""

    class Config:
        extra = "allow"
