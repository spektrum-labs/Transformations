from pydantic import BaseModel


class IsNVDIndependentCoverageEnabledInput(BaseModel):
    """Input schema for the isNVDIndependentCoverageEnabled transformation."""

    class Config:
        extra = "allow"
