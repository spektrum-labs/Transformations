from pydantic import BaseModel


class MfaEnforcementCoveragePercentageInput(BaseModel):
    """Input schema for the mfaEnforcementCoveragePercentage transformation."""

    class Config:
        extra = "allow"
