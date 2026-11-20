from pydantic import BaseModel


class VendorRiskAssessmentCoveragePercentageInput(BaseModel):
    """Input schema for the vendorRiskAssessmentCoveragePercentage transformation."""

    class Config:
        extra = "allow"
