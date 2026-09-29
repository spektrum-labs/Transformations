from pydantic import BaseModel


class RequiredCoveragePercentageInput(BaseModel):
    """Input schema for the requiredCoveragePercentage transformation."""

    class Config:
        extra = "allow"
