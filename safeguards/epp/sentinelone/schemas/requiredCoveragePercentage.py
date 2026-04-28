from pydantic import BaseModel
from typing import Optional


class RequiredCoveragePercentageOutput(BaseModel):
    coveragePercentage: float
    totalAgentsEnrolled: int
