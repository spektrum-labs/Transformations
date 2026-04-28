from pydantic import BaseModel, Field


class IsEPPEnabledOutput(BaseModel):
    isEPPEnabled: bool = Field(
        ...,
        description="True when at least one SentinelOne agent is active and not in an unprotected state.",
    )
    totalAgents: int = Field(..., description="Total number of managed agents returned by the API.")
    activeAgents: int = Field(
        ...,
        description="Number of agents that are active and not flagged as unprotected.",
    )
    inactiveAgents: int = Field(
        ...,
        description="Number of agents that are not active and not explicitly unprotected.",
    )
    unprotectedAgents: int = Field(
        ...,
        description="Number of agents with 'unprotected' in userActionsNeeded.",
    )
