from pydantic import BaseModel


class RequiredCoveragePercentageOutput(BaseModel):
    coveragePercentage: float
    totalEndpointsWithEPP: int
