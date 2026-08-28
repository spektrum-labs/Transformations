from pydantic import BaseModel


class RemediationGuidanceProvidedPercentageInput(BaseModel):
    """Input schema for the remediationGuidanceProvidedPercentage transformation."""

    class Config:
        extra = "allow"
