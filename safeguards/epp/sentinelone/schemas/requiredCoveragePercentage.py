from pydantic import BaseModel, Field
from typing import Optional


class RequiredCoveragePercentageOutput(BaseModel):
    requiredCoveragePercentage: float = Field(
        ...,
        description=(
            "Percentage of managed endpoints that have Endpoint Security installed. "
            "Derived from pagination.totalItems of getAgents. All enrolled agents "
            "have EPP installed by definition, so this is 100.0 when totalItems > 0, "
            "otherwise 0.0."
        ),
    )
    totalEndpointsWithEPP: int = Field(
        ...,
        description="Total number of endpoints with the SentinelOne EPP agent installed.",
    )
    totalEndpointsManaged: int = Field(
        ...,
        description=(
            "Total number of managed endpoints (equals totalEndpointsWithEPP for "
            "SentinelOne since only enrolled endpoints appear in the agent list)."
        ),
    )
