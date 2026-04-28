from typing import Optional
from pydantic import BaseModel


class RequiredCoveragePercentageOutput(BaseModel):
    coveragePercentage: Optional[float]
    totalAgentsEnrolled: int
    protectedAgents: int
