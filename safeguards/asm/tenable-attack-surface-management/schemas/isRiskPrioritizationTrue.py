from pydantic import BaseModel

class IsRiskPrioritizationTrueInput(BaseModel):
    """Input schema for the isRiskPrioritizationTrue transformation."""
    class Config:
        extra = "allow"
