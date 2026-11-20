from pydantic import BaseModel


class RiskScoreInput(BaseModel):
    """Input schema for the riskScore transformation."""

    class Config:
        extra = "allow"
