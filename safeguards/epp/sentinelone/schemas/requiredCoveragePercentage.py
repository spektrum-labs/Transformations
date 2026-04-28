from pydantic import BaseModel, Field


class RequiredCoveragePercentageOutput(BaseModel):
    coveragePercentage: float = Field(
        ...,
        description="Percentage of enrolled agents with isActive=true (0.0 to 100.0).",
    )
    totalAgents: int = Field(
        ...,
        description="Total number of enrolled SentinelOne agents across all pages.",
    )
    activeAgents: int = Field(
        ...,
        description="Number of agents with isActive=true.",
    )
